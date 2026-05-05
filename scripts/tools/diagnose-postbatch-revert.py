#!/usr/bin/env python3
"""
Diagnose a reverted postBatch tx by recovering which (parent_hash, timestamp)
the proposer actually signed against, vs what the L1 contract used.

Usage:
    python3 diagnose-postbatch-revert.py <TX_HASH> <RPC_URL> <BUILDER_ADDRESS>

Requires: pip install web3 eth-abi eth-utils eth-keys
"""
import sys
import json
from eth_abi import decode as abi_decode, encode as abi_encode
from eth_utils import keccak, to_checksum_address
from eth_keys import keys
from web3 import Web3

if len(sys.argv) != 4:
    print(__doc__)
    sys.exit(1)

tx_hash, rpc_url, expected_signer = sys.argv[1], sys.argv[2], to_checksum_address(sys.argv[3])

w3 = Web3(Web3.HTTPProvider(rpc_url))
tx = w3.eth.get_transaction(tx_hash)
blk = w3.eth.get_block(tx.blockNumber)
parent_blk = w3.eth.get_block(blk.number - 1)

print(f"=== Failed postBatch tx ===")
print(f"  hash:          {tx_hash}")
print(f"  block:         {blk.number}")
print(f"  block.timestamp: {blk.timestamp}")
print(f"  parent.hash:   {blk.parentHash.hex()}")
print(f"  parent.timestamp: {parent_blk.timestamp}")

# Decode postBatch(entries, blobCount, callData, proof)
selector = tx.input[:4]
input_data = tx.input[4:]

entry_tuple = "(uint256,bytes32,bytes32,int256)[]"
action_tuple = "(uint8,uint256,address,uint256,bytes,bool,address,uint256,uint256[])"
exec_entry_tuple = f"({entry_tuple},bytes32,{action_tuple})"
types = [f"{exec_entry_tuple}[]", "uint256", "bytes", "bytes"]
entries, blob_count, call_data, proof = abi_decode(types, input_data)

print(f"\n=== postBatch inputs ===")
print(f"  entries:    {len(entries)}")
print(f"  blobCount:  {blob_count}")
print(f"  callData:   {call_data.hex() if call_data else '(empty)'}")
print(f"  proof:      0x{proof.hex()} ({len(proof)} bytes)")

# Replicate Rollups.sol::postBatch entry hash computation:
#   entryHash[i] = keccak256(
#       abi.encode(stateDeltas),
#       abi.encode(vks),
#       actionHash,
#       abi.encode(nextAction)
#   )
# vks is per-entry; we don't have it from calldata directly, but the contract
# fetches vks from storage per state delta. We can't reproduce entryHashes
# without on-chain reads, so instead we reconstruct what publicInputsHash
# the proposer signed by trying candidate (parent, ts) pairs and a candidate
# entryHashes/blobHashes fixed to whatever the contract would have computed.

# Step 1: ask the contract what publicInputsHash IT computes.
# Easiest: call postBatch via eth_call against the failed tx to get the trace.
# Even simpler: replay the tx inputs and ask the verifier directly.
# But we don't have an eth_call hook into the internal hash. So we just
# brute force the SIGNED hash and check if it matches anything sensible.

# Recover address from signature for any 32-byte hash candidate
def recover(h: bytes, sig: bytes) -> str:
    if len(sig) != 65:
        return "(bad sig length)"
    # eth_keys expects v in {0,1} or {27,28}
    v = sig[64]
    if v >= 27:
        v -= 27
    s = keys.Signature(sig[:64] + bytes([v]))
    return to_checksum_address(s.recover_public_key_from_msg_hash(h).to_address())

# Brute search: for many (parent_hash, ts) candidates, compute the contract's
# publicInputsHash formula assuming entryHashes/blobHashes are abi.encode of
# whatever the proposer used. Without those we can't reproduce them, but we
# can dump them and let the user verify manually.

# Approach: just print the recovered signer assuming the SIGNED hash equals
# common candidates derived from blk + parent. Whichever recovers
# expected_signer tells us what the proposer signed.

# Since the inner entryHashes/blobHashes are content the proposer chose, we
# can't compute alternatives without access to its predicted state. But the
# AGGREGATE keccak256 of (parent_hash || timestamp || enc(entryHashes) || enc(blobHashes) || keccak(callData))
# is what we recover against. Unknown bits cancel out only if we treat them
# as a single "tail" we replay verbatim.
#
# Concrete approach: assume the proposer signed against the SAME entryHashes
# and blobHashes the contract would compute. Then the only differences are
# parent_hash and timestamp. Use the contract's entryHashes/blobHashes proxy
# by computing them ourselves the same way Rollups.sol does.

# Compute blobHashes — for non-blob txs this is empty
blob_hashes = []
blob_hashes_enc = abi_encode(["bytes32[]"], [blob_hashes])

# Compute callData hash
call_data_hash = keccak(call_data) if len(call_data) else keccak(b'')

# We don't have vks per state delta without on-chain reads, so we test with
# the assumption that the proposer used abi.encode(entryHashes) where
# entryHashes is just an empty array (0 entries case) — only correct for
# protocol-tx-only postBatches where entries=[]. Otherwise this script
# can't determine entryHashes without reading on-chain state.

if len(entries) == 0:
    entry_hashes = []
    entry_hashes_enc = abi_encode(["bytes32[]"], [entry_hashes])

    print(f"\n=== Trying candidate (parent_hash, timestamp) pairs ===")
    candidates = [
        ("blk.parentHash", "blk.timestamp", blk.parentHash, blk.timestamp),
        ("blk.parentHash", "parent.timestamp", blk.parentHash, parent_blk.timestamp),
        ("blk.parentHash", "parent.timestamp+5", blk.parentHash, parent_blk.timestamp + 5),
        ("blk.parentHash", "parent.timestamp+10", blk.parentHash, parent_blk.timestamp + 10),
        ("parent.parentHash", "parent.timestamp", parent_blk.parentHash, parent_blk.timestamp),
        ("parent.parentHash", "parent.timestamp+5", parent_blk.parentHash, parent_blk.timestamp + 5),
        ("parent.parentHash", "parent.timestamp+10", parent_blk.parentHash, parent_blk.timestamp + 10),
    ]

    for name_p, name_t, ph, ts in candidates:
        h = keccak(
            ph
            + ts.to_bytes(32, "big")
            + entry_hashes_enc
            + blob_hashes_enc
            + call_data_hash
        )
        recovered = recover(h, proof)
        match = "  <-- MATCH" if recovered == expected_signer else ""
        print(f"  ({name_p}, {name_t}={ts}): recovered={recovered}{match}")

    print(f"\nExpected signer:  {expected_signer}")
else:
    print(f"\n!!! entries non-empty ({len(entries)}). Cannot recompute entryHashes without on-chain reads.")
    print(f"    Pick a postBatch tx with empty entries (a 'state-only' batch) for this diagnostic.")
