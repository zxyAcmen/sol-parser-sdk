//! Transaction-level envelope subscription.
//!
//! This keeps the normal DexEvent parser path, while exposing the original
//! Yellowstone transaction/meta and a compact raw instruction view for strategy
//! code that needs CU, fee, tip, or outer-instruction structure.

use super::{build_subscribe_request, extract_signature, parse_transaction_core, YellowstoneGrpc};
use super::{AccountFilter, EventTypeFilter, TransactionFilter};
use crate::logs::timestamp_to_microseconds;
use crate::DexEvent;
use crossbeam_queue::ArrayQueue;
use custom_parser::{
    RawInnerInstructionGroup, RawInstructionSource, RawInstructionView, RawTransactionView,
};
use futures::{SinkExt, StreamExt};
use log::error;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio::time::Duration;
use yellowstone_grpc_client::{ClientTlsConfig, GeyserGrpcClient};
use yellowstone_grpc_proto::prelude::*;

#[derive(Clone)]
pub struct TxEnvelope {
    pub signature: solana_sdk::signature::Signature,
    pub slot: u64,
    pub tx_index: u64,
    pub block_time_us: i64,
    pub grpc_recv_us: i64,
    pub meta: Arc<TransactionStatusMeta>,
    pub transaction: Arc<Transaction>,
    pub raw_view: Arc<RawTransactionView>,
    pub events: Vec<DexEvent>,
}

impl YellowstoneGrpc {
    pub async fn subscribe_dex_transactions(
        &self,
        transaction_filters: Vec<TransactionFilter>,
        account_filters: Vec<AccountFilter>,
        event_type_filter: Option<EventTypeFilter>,
    ) -> Result<Arc<ArrayQueue<TxEnvelope>>, Box<dyn std::error::Error>> {
        let queue = Arc::new(ArrayQueue::new(10_000));
        let queue_clone = Arc::clone(&queue);
        let self_clone = self.clone();

        tokio::spawn(async move {
            let mut delay = 1u64;
            loop {
                match self_clone
                    .stream_transaction_envelopes(
                        &transaction_filters,
                        &account_filters,
                        &event_type_filter,
                        &queue_clone,
                    )
                    .await
                {
                    Ok(_) => delay = 1,
                    Err(e) => println!("❌ gRPC tx envelope error: {} - retry in {}s", e, delay),
                }
                tokio::time::sleep(Duration::from_secs(delay)).await;
                delay = (delay * 2).min(60);
            }
        });

        Ok(queue)
    }

    async fn stream_transaction_envelopes(
        &self,
        tx_filters: &[TransactionFilter],
        acc_filters: &[AccountFilter],
        event_filter: &Option<EventTypeFilter>,
        queue: &Arc<ArrayQueue<TxEnvelope>>,
    ) -> Result<(), String> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut builder = GeyserGrpcClient::build_from_shared(self.endpoint.clone())
            .map_err(|e| e.to_string())?
            .x_token(self.token.clone())
            .map_err(|e| e.to_string())?
            .max_decoding_message_size(1024 * 1024 * 1024);

        if self.config.connection_timeout_ms > 0 {
            builder =
                builder.connect_timeout(Duration::from_millis(self.config.connection_timeout_ms));
        }
        if self.config.enable_tls {
            builder = builder
                .tls_config(ClientTlsConfig::new().with_native_roots())
                .map_err(|e| e.to_string())?;
        }

        let mut client = builder.connect().await.map_err(|e| e.to_string())?;
        let request = build_subscribe_request(tx_filters, acc_filters);

        let (subscribe_tx, mut stream) =
            client.subscribe_with_request(Some(request)).await.map_err(|e| e.to_string())?;

        let (control_tx, mut control_rx) = mpsc::channel::<SubscribeRequest>(100);
        *self.control_tx.lock().await = Some(control_tx);
        let subscribe_tx = Arc::new(Mutex::new(subscribe_tx));

        loop {
            tokio::select! {
                msg = stream.next() => {
                    match msg {
                        Some(Ok(update_msg)) => {
                            if matches!(
                                update_msg.update_oneof.as_ref(),
                                Some(subscribe_update::UpdateOneof::Ping(_))
                            ) {
                                if let Err(e) = subscribe_tx
                                    .lock()
                                    .await
                                    .send(SubscribeRequest {
                                        ping: Some(SubscribeRequestPing { id: 1 }),
                                        ..Default::default()
                                    })
                                    .await
                                {
                                    return Err(e.to_string());
                                }
                                continue;
                            }

                            let created_at = update_msg.created_at.unwrap_or_default();
                            let block_time_us =
                                timestamp_to_microseconds(created_at.seconds, created_at.nanos) as i64;
                            let grpc_recv_us = crate::core::now_micros();

                            let Some(update) = update_msg.update_oneof else { continue };
                            if let subscribe_update::UpdateOneof::Transaction(tx) = update {
                                if let Some(env) = build_envelope(&tx, grpc_recv_us, block_time_us, event_filter.as_ref()) {
                                    let _ = queue.push(env);
                                }
                            }
                        }
                        Some(Err(e)) => {
                            error!("Stream error: {:?}", e);
                            return Err(e.to_string());
                        }
                        None => return Ok(()),
                    }
                }
                Some(req) = control_rx.recv() => {
                    if let Err(e) = subscribe_tx.lock().await.send(req).await {
                        return Err(e.to_string());
                    }
                }
            }
        }
    }
}

#[inline]
fn bytes32(bytes: &[u8]) -> Option<[u8; 32]> {
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Some(out)
}

fn build_raw_instruction_view(
    source: RawInstructionSource,
    outer_index: Option<u32>,
    ix: &CompiledInstruction,
) -> RawInstructionView {
    RawInstructionView {
        source,
        outer_index,
        program_id_index: ix.program_id_index,
        account_indices: ix.accounts.clone(),
        data: ix.data.clone(),
    }
}

fn build_raw_inner_instruction_view(outer_index: u32, ix: &InnerInstruction) -> RawInstructionView {
    RawInstructionView {
        source: RawInstructionSource::Inner,
        outer_index: Some(outer_index),
        program_id_index: ix.program_id_index,
        account_indices: ix.accounts.clone(),
        data: ix.data.clone(),
    }
}

fn build_raw_transaction_view(
    info: &SubscribeUpdateTransactionInfo,
    tx: &SubscribeUpdateTransaction,
    transaction: &Transaction,
    meta: &TransactionStatusMeta,
    grpc_recv_us: i64,
    block_time_us: i64,
) -> RawTransactionView {
    let static_account_keys: Vec<[u8; 32]> = transaction
        .message
        .as_ref()
        .map(|msg| msg.account_keys.iter().filter_map(|k| bytes32(k)).collect())
        .unwrap_or_default();

    let loaded_writable_keys: Vec<[u8; 32]> =
        meta.loaded_writable_addresses.iter().filter_map(|k| bytes32(k)).collect();

    let loaded_readonly_keys: Vec<[u8; 32]> =
        meta.loaded_readonly_addresses.iter().filter_map(|k| bytes32(k)).collect();

    let mut all_account_keys = static_account_keys.clone();
    all_account_keys.extend(loaded_writable_keys.iter().copied());
    all_account_keys.extend(loaded_readonly_keys.iter().copied());

    let outer_instructions: Vec<RawInstructionView> = transaction
        .message
        .as_ref()
        .map(|msg| {
            msg.instructions
                .iter()
                .map(|ix| build_raw_instruction_view(RawInstructionSource::Outer, None, ix))
                .collect()
        })
        .unwrap_or_default();

    let inner_instruction_groups: Vec<RawInnerInstructionGroup> = meta
        .inner_instructions
        .iter()
        .map(|group| RawInnerInstructionGroup {
            outer_index: group.index,
            instructions: group
                .instructions
                .iter()
                .map(|ix| build_raw_inner_instruction_view(group.index, ix))
                .collect(),
        })
        .collect();

    RawTransactionView {
        signature: info.signature.clone(),
        slot: tx.slot,
        tx_index: info.index,
        block_time_us,
        grpc_recv_us,
        static_account_keys,
        loaded_writable_keys,
        loaded_readonly_keys,
        all_account_keys,
        outer_instructions,
        inner_instruction_groups,
    }
}

fn build_envelope(
    tx: &SubscribeUpdateTransaction,
    grpc_recv_us: i64,
    block_time_us: i64,
    filter: Option<&EventTypeFilter>,
) -> Option<TxEnvelope> {
    let info = tx.transaction.as_ref()?;
    let meta = info.meta.as_ref()?;
    let transaction = info.transaction.as_ref()?;

    let signature = extract_signature(&info.signature);
    let slot = tx.slot;
    let tx_index = info.index;
    let raw_view =
        build_raw_transaction_view(info, tx, transaction, meta, grpc_recv_us, block_time_us);
    let events = parse_transaction_core(tx, grpc_recv_us, Some(block_time_us), filter);

    if events.is_empty() {
        return None;
    }

    Some(TxEnvelope {
        signature,
        slot,
        tx_index,
        block_time_us,
        grpc_recv_us,
        meta: Arc::new(meta.clone()),
        transaction: Arc::new(transaction.clone()),
        raw_view: Arc::new(raw_view),
        events,
    })
}
