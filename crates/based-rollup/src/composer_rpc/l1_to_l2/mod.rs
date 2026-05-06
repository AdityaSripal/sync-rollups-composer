//! L1 RPC proxy for transparent cross-chain call detection.
//!
//! Sits in front of the L1 RPC and transparently forwards all requests.
//! Intercepts `eth_sendRawTransaction` to detect cross-chain calls:
//!
//! 1. **Detect**: Check if tx targets a CrossChainProxy (via `authorizedProxies`
//!    mapping on Rollups.sol — returns `ProxyInfo(originalAddress, originalRollupId)`)
//! 2. **Queue**: Call `syncrollups_initiateCrossChainCall` on the builder's L2 RPC
//!    with the gas price and raw L1 tx bundled atomically. The driver sorts entries
//!    by gas price descending (matching L1 miner ordering) before computing chained
//!    state deltas, then forwards the L1 txs after `postBatch`.
//!
//! The driver batches all entries into a single `postBatch`, then forwards queued
//! L1 txs — no nonce contention with the proposer's `submitBatch`.
//!
//! Users point MetaMask at this proxy for transparent synchronous composability.

mod process;
mod simulation;

use alloy_primitives::Address;
#[cfg(test)]
use alloy_primitives::U256;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes as HyperBytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::net::TcpListener;

// Shared helpers from the common module.
use super::common::{cors_response, error_response, extract_methods};
use super::model::L1ProxyLookup;

// Re-export process items that trace_and_detect_internal_calls needs.
use process::process_l1_to_l2_calls;
use process::walk_l1_trace_generic;

// Re-export items moved to process.rs so that the test module (which does
// `use super::*`) can still access them.
#[cfg(test)]
use process::parse_address_from_return;
#[cfg(test)]
use process::parse_u256_from_return;

/// Run the L1 RPC proxy server.
#[allow(clippy::too_many_arguments)]
pub async fn run_l1_rpc_proxy(
    l1_proxy_port: u16,
    l1_rpc_url: String,
    l2_rpc_url: String,
    rollups_address: Address,
    builder_address: Address,
    builder_private_key: Option<String>,
    rollup_id: u64,
    cross_chain_manager_address: Address,
) -> eyre::Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], l1_proxy_port));
    let listener = TcpListener::bind(addr).await?;

    tracing::info!(
        target: "based_rollup::l1_proxy",
        %l1_proxy_port,
        %l1_rpc_url,
        %l2_rpc_url,
        %rollups_address,
        %builder_address,
        "L1 RPC proxy listening"
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("failed to build reqwest client");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(target: "based_rollup::l1_proxy", %e, "accept failed");
                // Brief backoff to prevent CPU-saturating spin on persistent errors
                // (e.g., file descriptor exhaustion).
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };

        let client = client.clone();
        let l1_rpc_url = l1_rpc_url.clone();
        let l2_rpc_url = l2_rpc_url.clone();
        let builder_private_key = builder_private_key.clone();

        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let client = client.clone();
                let l1_rpc_url = l1_rpc_url.clone();
                let l2_rpc_url = l2_rpc_url.clone();
                let builder_private_key = builder_private_key.clone();
                handle_request(
                    req,
                    client,
                    l1_rpc_url,
                    l2_rpc_url,
                    rollups_address,
                    builder_address,
                    builder_private_key,
                    rollup_id,
                    cross_chain_manager_address,
                    peer,
                )
            });

            let io = TokioIo::new(stream);
            if let Err(e) = http1::Builder::new()
                .keep_alive(true)
                .serve_connection(io, service)
                .await
            {
                if !e.is_incomplete_message() {
                    tracing::debug!(
                        target: "based_rollup::l1_proxy",
                        %e, %peer,
                        "connection error"
                    );
                }
            }
        });
    }
}

/// Handle a single JSON-RPC request.
#[allow(clippy::too_many_arguments)]
async fn handle_request(
    req: Request<hyper::body::Incoming>,
    client: reqwest::Client,
    l1_rpc_url: String,
    l2_rpc_url: String,
    rollups_address: Address,
    builder_address: Address,
    builder_private_key: Option<String>,
    rollup_id: u64,
    cross_chain_manager_address: Address,
    _peer: SocketAddr,
) -> Result<Response<Full<HyperBytes>>, hyper::Error> {
    // Handle CORS preflight
    if req.method() == hyper::Method::OPTIONS {
        return Ok(cors_response(
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Full::new(HyperBytes::new()))
                .expect("valid response"),
        ));
    }

    // Only handle POST (JSON-RPC)
    if req.method() != hyper::Method::POST {
        return Ok(cors_response(
            Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Full::new(HyperBytes::from("Method Not Allowed")))
                .expect("valid response"),
        ));
    }

    // Read request body (cap at 10 MB to prevent memory exhaustion)
    const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;
    let body_bytes = match req.collect().await {
        Ok(collected) => {
            let bytes = collected.to_bytes();
            if bytes.len() > MAX_BODY_SIZE {
                return Ok(error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request body too large",
                ));
            }
            bytes
        }
        Err(e) => {
            tracing::debug!(target: "based_rollup::l1_proxy", %e, "failed to read request body");
            return Ok(error_response(StatusCode::BAD_REQUEST, "bad request body"));
        }
    };

    // Try to parse as JSON-RPC
    let maybe_json: Option<Value> = serde_json::from_slice(&body_bytes).ok();

    // Intercept specific JSON-RPC methods for cross-chain handling
    if let Some(ref json) = maybe_json {
        let methods = extract_methods(json);
        for (method, params) in &methods {
            if method == "eth_sendRawTransaction" {
                if let Some(raw_tx) = params.and_then(|p| p.first()).and_then(|v| v.as_str()) {
                    tracing::info!(
                        target: "based_rollup::l1_proxy",
                        raw_tx_prefix = %&raw_tx[..raw_tx.len().min(42)],
                        raw_tx_len = raw_tx.len(),
                        "L1 compositor: intercepted eth_sendRawTransaction"
                    );
                    match handle_cross_chain_tx(
                        &client,
                        &l1_rpc_url,
                        &l2_rpc_url,
                        raw_tx,
                        rollups_address,
                        builder_address,
                        builder_private_key.clone(),
                        rollup_id,
                        cross_chain_manager_address,
                    )
                    .await
                    {
                        Ok(Some(tx_hash)) => {
                            // Cross-chain tx queued — entries + user tx sent to builder.
                            // Return the tx hash directly WITHOUT forwarding to L1.
                            // The driver will submit postBatch then forward the raw tx.
                            let json_id = json.get("id").cloned().unwrap_or(Value::Null);
                            let response_body = serde_json::json!({
                                "jsonrpc": "2.0",
                                "result": tx_hash,
                                "id": json_id
                            });
                            return Ok(cors_response(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .header("Content-Type", "application/json")
                                    .body(Full::new(HyperBytes::from(response_body.to_string())))
                                    .expect("valid response"),
                            ));
                        }
                        Ok(None) => {
                            // Not a cross-chain tx, forward normally (fall through)
                        }
                        Err(e) => {
                            tracing::warn!(
                                target: "based_rollup::l1_proxy",
                                %e,
                                "cross-chain handling failed, forwarding tx anyway"
                            );
                        }
                    }
                }
            }

            // Intercept eth_estimateGas for cross-chain proxy addresses.
            // Wallets (MetaMask, Rabby) call this before showing the confirmation
            // dialog. For cross-chain proxy calls, L1 estimation always reverts
            // because the execution table isn't populated yet, causing wallets to
            // fall back to incorrect defaults (e.g. Rabby uses 2M gas).
            // We compute gas from calldata instead.
            if method == "eth_estimateGas" {
                if let Some(result) = process::handle_estimate_gas_for_proxy(
                    &client,
                    &l1_rpc_url,
                    *params,
                    rollups_address,
                    json,
                )
                .await
                {
                    return Ok(result);
                }
            }
        }
    }

    // Forward the original request to L1 as-is
    let resp = match client
        .post(&l1_rpc_url)
        .header("Content-Type", "application/json")
        .body(body_bytes.to_vec())
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(target: "based_rollup::l1_proxy", %e, "L1 request failed");
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                &format!("L1 upstream error: {e}"),
            ));
        }
    };

    let status = resp.status();
    let resp_bytes = resp.bytes().await.unwrap_or_default();

    Ok(cors_response(
        Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .body(Full::new(HyperBytes::from(resp_bytes.to_vec())))
            .expect("valid response"),
    ))
}

/// Handle a potential cross-chain transaction.
///
/// Returns `Ok(Some(tx_hash))` if a cross-chain call was detected and both
/// the execution entries and the user's raw L1 tx were queued for atomic
/// submission by the driver. The caller should return `tx_hash` to the user
/// and NOT forward the tx to L1.
///
/// Returns `Ok(None)` if this is not a cross-chain tx (just forward normally).
/// Returns `Err` if detection/queuing failed.
///
/// Uses a single code path: trace the tx with `debug_traceCall` and walk the
/// call tree with the generic `trace::walk_trace_tree`. No special-case
/// detection for direct proxy calls or bridge contracts — the generic walker
/// detects all patterns (direct proxy, bridgeEther, bridgeTokens, wrapper
/// contracts, multi-call continuations) via the `executeCrossChainCall` child pattern.
#[allow(clippy::too_many_arguments)]
async fn handle_cross_chain_tx(
    client: &reqwest::Client,
    l1_rpc_url: &str,
    l2_rpc_url: &str,
    raw_tx: &str,
    rollups_address: Address,
    _builder_address: Address,
    builder_private_key: Option<String>,
    rollup_id: u64,
    cross_chain_manager_address: Address,
) -> eyre::Result<Option<String>> {
    // Decode the raw transaction to extract fields needed by the trace path.
    let tx_obj = decode_raw_tx_for_trace(raw_tx)?;

    // Contract creation cannot contain cross-chain calls.
    if tx_obj.get("to").and_then(|v| v.as_str()).is_none() {
        return Ok(None);
    }

    // Single code path: trace the tx and detect all cross-chain calls
    // via the generic walk_trace_tree (executeCrossChainCall child pattern).
    trace_and_detect_internal_calls(
        client,
        l1_rpc_url,
        l2_rpc_url,
        raw_tx,
        &tx_obj,
        rollups_address,
        builder_private_key,
        rollup_id,
        cross_chain_manager_address,
    )
    .await
}

/// Trace a transaction using `debug_traceCall` with `callTracer` and detect
/// all cross-chain proxy calls via the generic `trace::walk_trace_tree`.
///
/// Uses protocol-level detection only: a node is a proxy call if any of its
/// direct children call `executeCrossChainCall` on Rollups.sol. No contract-
/// specific selectors (bridgeEther, bridgeTokens, etc.) — works for any
/// contract that uses CrossChainProxy.
///
/// Returns `Ok(Some(tx_hash))` if cross-chain calls were found and queued.
/// Returns `Ok(None)` if no cross-chain calls were detected.
#[allow(clippy::too_many_arguments)]
async fn trace_and_detect_internal_calls(
    client: &reqwest::Client,
    l1_rpc_url: &str,
    l2_rpc_url: &str,
    raw_tx: &str,
    tx_obj: &Value,
    rollups_address: Address,
    builder_private_key: Option<String>,
    rollup_id: u64,
    cross_chain_manager_address: Address,
) -> eyre::Result<Option<String>> {
    // Build the debug_traceCall request from decoded tx fields
    let from = tx_obj
        .get("from")
        .and_then(|v| v.as_str())
        .unwrap_or("0x0000000000000000000000000000000000000000");
    let to = match tx_obj.get("to").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return Ok(None), // Contract creation — cannot contain cross-chain calls
    };
    let data = tx_obj.get("data").and_then(|v| v.as_str()).unwrap_or("0x");
    let value = tx_obj
        .get("value")
        .and_then(|v| v.as_str())
        .unwrap_or("0x0");

    // Wait for any pending precursor that deploys code at `to` to mine.
    //
    // Pipelined-create-and-use pattern (issue #45): a user submits two txs
    // back-to-back — first `createCrossChainProxy(target, rollupId)` to deploy
    // a proxy contract, then a value-transfer or call to the resulting proxy
    // address. If both txs are in-flight when this composer traces the second,
    // the proxy doesn't exist at the L1 RPC's `latest` block and the trace
    // returns no calls — composer falls through to direct mempool forwarding,
    // breaking same-block atomicity.
    //
    // Reth's `debug_traceCall` doesn't apply pending mempool to its pre-state
    // (only to the block header), so tracing at "pending" doesn't help. But
    // reth's `eth_getCode("pending")` DOES return the predicted code from
    // mempool effects. So:
    //   - if `to` already has code at "latest" → proceed normally
    //   - if "latest" empty but "pending" has code → a precursor tx will
    //     deploy code here. Wait briefly for that precursor to mine.
    //   - if both empty → not a deployable cross-chain target; let the
    //     existing trace path return "not cross-chain" naturally.
    //
    // Adds at most ~one L1 slot of latency in the pipelined case. Bounded by
    // a small timeout so a stuck precursor (dropped from mempool, etc.)
    // doesn't hang the user request indefinitely.
    if let Err(e) =
        await_destination_code(client, l1_rpc_url, to).await
    {
        tracing::debug!(
            target: "based_rollup::l1_proxy",
            %e, %to,
            "await_destination_code returned non-fatal error — proceeding with trace anyway"
        );
    }

    tracing::info!(
        target: "based_rollup::l1_proxy",
        %to, %from,
        "slow path: tracing tx with debug_traceCall to detect internal cross-chain calls"
    );

    // First trace: normal (no state overrides).
    // If this finds only 1 cross-chain call but the tx reverts internally,
    // we retry with state overrides (mock Rollups) to discover hidden calls
    // that would execute after entries are posted (multi-call continuation pattern).
    let trace_result = {
        let trace_req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "debug_traceCall",
            "params": [
                {
                    "from": from,
                    "to": to,
                    "data": data,
                    "value": value,
                    "gas": "0x2faf080"
                },
                "latest",
                { "tracer": "callTracer" }
            ],
            "id": 1
        });

        let rpc_resp: super::common::JsonRpcResponse = client
            .post(l1_rpc_url)
            .json(&trace_req)
            .send()
            .await?
            .json()
            .await?;

        match rpc_resp.into_result() {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(
                    target: "based_rollup::l1_proxy",
                    %e,
                    "debug_traceCall failed — forwarding tx without cross-chain detection"
                );
                return Ok(None);
            }
        }
    };

    // Check if the top-level call reverted — indicates the tx needs entries posted first.
    let top_level_error = trace_result.get("error").is_some()
        || trace_result.get("revertReason").is_some()
        || trace_result
            .get("output")
            .and_then(|v| v.as_str())
            .map(|s| {
                s.starts_with(&super::common::selector_hex_prefixed(
                    &super::common::ERROR_STRING_SELECTOR,
                ))
            }) // Error(string) selector
            .unwrap_or(false);

    // Walk the trace tree using the generic trace::walk_trace_tree.
    // This detects ALL cross-chain proxy calls via the executeCrossChainCall
    // child pattern — no contract-specific selectors needed.
    let mut proxy_cache: HashMap<Address, Option<super::trace::ProxyInfo>> = HashMap::new();
    let mut detected_calls = walk_l1_trace_generic(
        client,
        l1_rpc_url,
        rollups_address,
        &trace_result,
        &mut proxy_cache,
    )
    .await;

    // Iterative L1 discovery via the unified discover_until_stable engine.
    // Replaces the inline loop + in_reverted_frame correction block.
    // discover_until_stable handles both the iterative retrace and
    // correct_in_reverted_frame internally.
    if top_level_error && !detected_calls.is_empty() {
        use super::direction::{L1ToL2, UserTxContext};
        use super::sim_client::HttpSimClient;

        let direction = L1ToL2 {
            l2_ccm: cross_chain_manager_address,
            l1_ccm: rollups_address,
            rollup_id,
            builder_key: {
                let key_hex = builder_private_key.as_deref().unwrap_or("");
                let key_clean = key_hex.strip_prefix("0x").unwrap_or(key_hex);
                key_clean
                    .parse::<alloy_signer_local::PrivateKeySigner>()
                    .unwrap_or_else(|_| alloy_signer_local::PrivateKeySigner::random())
            },
            client: client.clone(),
            l1_rpc_url: l1_rpc_url.to_string(),
        };
        let sim = HttpSimClient::new(
            client.clone(),
            l1_rpc_url.to_string(),
            l2_rpc_url.to_string(),
        );
        let lookup = L1ProxyLookup {
            client,
            rpc_url: l1_rpc_url,
            rollups_address,
        };
        let user_tx = UserTxContext {
            from: from.to_string(),
            to: to.to_string(),
            data: data.to_string(),
            value: value.to_string(),
            raw_tx_bytes: vec![], // L1→L2 doesn't need raw tx bytes for enrichment
        };
        match super::discover::discover_until_stable(
            &direction,
            &sim,
            &trace_result,
            &user_tx,
            &lookup,
            &mut proxy_cache,
            Some(detected_calls.clone()),
        )
        .await
        {
            Ok(discovered) => {
                detected_calls = discovered.calls;
                // last_converged_walk stays empty — discover_until_stable handles
                // in_reverted_frame internally via correct_in_reverted_frame
            }
            Err(e) => {
                tracing::warn!(target: "based_rollup::l1_proxy", %e,
                    "discover_until_stable failed — proceeding with initial calls");
            }
        }
    }

    process_l1_to_l2_calls(
        client,
        l1_rpc_url,
        l2_rpc_url,
        raw_tx,
        rollups_address,
        &builder_private_key,
        rollup_id,
        cross_chain_manager_address,
        from,
        to,
        data,
        value,
        top_level_error,
        &mut detected_calls,
        &mut proxy_cache,
    )
    .await
}

/// If the destination address has no code at `latest` but does at `pending`,
/// poll `latest` until the code shows up (i.e. wait for the in-flight precursor
/// tx that deploys it to mine). Returns Ok(()) once `latest` has code, on a
/// fast-path "code already there", or on the "no pending code at all" case.
/// Bounded by a hard timeout so we never block forever.
///
/// See the call site in `trace_and_detect_internal_calls` for full rationale
/// (issue #45 pipelined-create-and-use pattern).
async fn await_destination_code(
    client: &reqwest::Client,
    l1_rpc_url: &str,
    to: &str,
) -> eyre::Result<()> {
    /// Max time we'll hold the user's tx waiting for a precursor to mine.
    /// Three Chiado/Gnosis L1 slots (~5s each) — enough to absorb one missed
    /// slot. Beyond this, give up and let the trace run anyway (it will
    /// return "no cross-chain calls" and the tx will be forwarded normally).
    const AWAIT_CODE_TIMEOUT_MS: u64 = 15_000;
    /// Polling interval for `eth_getCode("latest")`. Must be << one L1 slot
    /// so we catch the precursor as soon as it lands.
    const POLL_INTERVAL_MS: u64 = 500;

    async fn get_code(
        client: &reqwest::Client,
        l1_rpc_url: &str,
        to: &str,
        block: &str,
    ) -> eyre::Result<String> {
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getCode",
            "params": [to, block],
            "id": 1,
        });
        let resp: super::common::JsonRpcResponse =
            client.post(l1_rpc_url).json(&req).send().await?.json().await?;
        match resp.into_result() {
            Ok(Value::String(s)) => Ok(s),
            Ok(other) => Err(eyre::eyre!("eth_getCode returned non-string: {other:?}")),
            Err(e) => Err(eyre::eyre!("eth_getCode failed: {e}")),
        }
    }

    // Fast path: code already exists at latest. Common case (proxy already
    // deployed in some prior block) — no waiting needed.
    let latest_code = get_code(client, l1_rpc_url, to, "latest").await?;
    if latest_code != "0x" {
        return Ok(());
    }

    // Slow path: latest is empty. Check pending — does some mempool tx
    // deploy code here? If not, this destination simply has no code and
    // the trace will correctly find no cross-chain calls.
    let pending_code = get_code(client, l1_rpc_url, to, "pending").await?;
    if pending_code == "0x" {
        return Ok(());
    }

    tracing::info!(
        target: "based_rollup::l1_proxy",
        %to,
        pending_code_len = pending_code.len(),
        "destination has pending code but no latest code — holding user tx until precursor mines"
    );

    // Poll latest until code shows up or timeout.
    let started = std::time::Instant::now();
    while started.elapsed() < std::time::Duration::from_millis(AWAIT_CODE_TIMEOUT_MS) {
        tokio::time::sleep(std::time::Duration::from_millis(POLL_INTERVAL_MS)).await;
        let code = get_code(client, l1_rpc_url, to, "latest").await?;
        if code != "0x" {
            tracing::info!(
                target: "based_rollup::l1_proxy",
                %to,
                waited_ms = started.elapsed().as_millis() as u64,
                "precursor mined — destination now has code at latest"
            );
            return Ok(());
        }
    }

    tracing::warn!(
        target: "based_rollup::l1_proxy",
        %to,
        timeout_ms = AWAIT_CODE_TIMEOUT_MS,
        "timed out waiting for destination code at latest — proceeding with trace (will likely miss cross-chain detection)"
    );
    Ok(())
}

/// Decode a raw signed transaction into a JSON object suitable for tracing.
fn decode_raw_tx_for_trace(raw_tx: &str) -> eyre::Result<Value> {
    let raw_hex = raw_tx.strip_prefix("0x").unwrap_or(raw_tx);
    let raw_bytes =
        hex_decode(raw_hex).ok_or_else(|| eyre::eyre!("invalid hex in raw transaction"))?;

    use alloy_consensus::Transaction;
    use alloy_consensus::transaction::TxEnvelope;
    use alloy_rlp::Decodable;
    use reth_primitives_traits::SignerRecoverable;

    let tx_envelope = TxEnvelope::decode(&mut raw_bytes.as_slice())
        .map_err(|e| eyre::eyre!("failed to decode transaction: {e}"))?;

    let from = tx_envelope
        .recover_signer()
        .map_err(|e| eyre::eyre!("failed to recover signer: {e}"))?;

    let to = tx_envelope.to();
    let value = tx_envelope.value();
    let input = tx_envelope.input();
    let gas = tx_envelope.gas_limit();

    let mut obj = serde_json::json!({
        "from": format!("{from}"),
        "value": format!("{value:#x}"),
        "data": format!("0x{}", hex::encode(input)),
        "gas": format!("{gas:#x}")
    });

    if let Some(to_addr) = to {
        obj["to"] = Value::String(format!("{to_addr}"));
    }

    Ok(obj)
}

// eth_call_view is in super::common (imported above).
// extract_methods, cors_response, error_response are in super::common (imported above).

/// Decode a hex string to bytes.
pub(super) fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16).ok()?;
        bytes.push(byte);
    }
    Some(bytes)
}

/// Extract the effective gas price from a raw signed transaction.
/// For EIP-1559 txs, uses `max_fee_per_gas` (the worst-case ordering price).
/// For legacy/EIP-2930 txs, uses `gas_price`.
pub(super) fn extract_gas_price_from_raw_tx(raw_tx: &str) -> eyre::Result<u128> {
    let raw_hex = raw_tx.strip_prefix("0x").unwrap_or(raw_tx);
    let raw_bytes =
        hex_decode(raw_hex).ok_or_else(|| eyre::eyre!("invalid hex in raw transaction"))?;

    use alloy_consensus::Transaction;
    use alloy_consensus::transaction::TxEnvelope;
    use alloy_rlp::Decodable;

    let tx_envelope = TxEnvelope::decode(&mut raw_bytes.as_slice())
        .map_err(|e| eyre::eyre!("failed to decode transaction: {e}"))?;

    let gas_price = match &tx_envelope {
        TxEnvelope::Legacy(signed) => signed.tx().gas_price,
        TxEnvelope::Eip2930(signed) => signed.tx().gas_price,
        TxEnvelope::Eip1559(signed) => signed.tx().max_fee_per_gas,
        TxEnvelope::Eip4844(signed) => signed.tx().max_fee_per_gas(),
        TxEnvelope::Eip7702(signed) => signed.tx().max_fee_per_gas,
    };

    Ok(gas_price)
}

// get_l1_block_context and get_verification_key are in super::common (imported above).

// Use hex crate for encoding (already in dependency tree via alloy)
mod hex {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(HEX_CHARS[(b >> 4) as usize] as char);
            s.push(HEX_CHARS[(b & 0xf) as usize] as char);
        }
        s
    }

    pub fn decode(hex: &str) -> Result<Vec<u8>, ()> {
        if hex.len() % 2 != 0 {
            return Err(());
        }
        let mut bytes = Vec::with_capacity(hex.len() / 2);
        for i in (0..hex.len()).step_by(2) {
            let byte = u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| ())?;
            bytes.push(byte);
        }
        Ok(bytes)
    }
}

#[cfg(test)]
#[path = "../l1_to_l2_tests.rs"]
mod tests;
