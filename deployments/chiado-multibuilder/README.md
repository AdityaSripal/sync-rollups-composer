# Multi-Builder Experiment on Public Chiado

Spin up **two builders** competing for the same `rollup_id`, each with its own
private key, both signing valid `postBatch` proofs. Approximates the eventual
ZK-prover model where multiple independent provers can submit valid state
transitions and L1 ordering is the only consensus.

**Development experiment only.** Uses `MultiSignerECDSAVerifier` (in
`contracts/test/`) which authorizes a SET of signer addresses. Production
rollups should use a real ZK verifier where any party producing a valid proof
is accepted by construction.

---

## Why this experiment matters

The single-signer `tmpECDSAVerifier` used by `chiado-10200-public/` allows only
one builder per rollup. If you run two instances with the same key they collide
on L1 nonce; if you run two with different keys, only one's signature verifies.
Either way, you can't observe what really happens when **two independently
proven state transitions race on L1**.

`MultiSignerECDSAVerifier` accepts any signature from a configured set, so two
builders with different keys both produce valid proofs. Their `postBatch`
bundles compete on L1 ordering exactly the way independent ZK provers would.

---

## What to watch for

Once both builders are up:

- **Each builder builds its own L2 view.** Different mempool ordering, possibly
  different block contents.
- **Bundles race on L1.** Whichever lands first advances on-chain state. The
  other's bundle either drops at the builder RPC or (if it lands too) reverts
  on state-delta mismatch.
- **The losing builder rebuilds** on top of the winner's state via
  `rebuild_with_fresh_l1_context`, then competes again.
- **Convergence**: do both builders eventually agree? They should — L1 is
  canonical — but the dynamics under contention are the interesting question.

Open questions this setup is designed to answer:

1. How does the bundle endpoint resolve competing bundles for the same target
   block?
2. If both bundles land in the same block, which postBatch wins, and what
   happens to the loser's tx?
3. How fast does the loser detect divergence and rebuild?
4. Does cross-chain atomicity hold under contention? (User submits bridgeEther
   via builder A's composer; builder B's bundle lands instead — does the
   user's tx revert with `ExecutionNotInCurrentBlock`?)

---

## Block-1 caveat

Block 1 of the L2 deploys protocol contracts (L2Context, CCM, Bridge L2) at
addresses computed from the **primary builder**'s address (`CREATE(builder1,
nonce=0..2)`). Only `builder1` produces block 1 — `builder2` syncs from L1
BatchPosted events and joins competition from block 2 onward. The compose file
enforces this via `depends_on: builder1: service_healthy` for `builder2`.

---

## Setup

### 1. Generate two builder keys + faucet xDAI for both

```
B1=$(cast wallet new --json | jq -r '.[0].private_key')
B2=$(cast wallet new --json | jq -r '.[0].private_key')
echo "builder1: $(cast wallet address --private-key $B1)"
echo "builder2: $(cast wallet address --private-key $B2)"
# Faucet both addresses at https://faucet.chiadochain.net/
```

### 2. Deploy

```
deployments/chiado-multibuilder/deploy.sh \
    http://37.27.238.19:18545 \
    "$DEPLOYER_KEY" \
    "$B1" \
    "$B2"
```

Writes `rollup-gnosis.env` and `genesis.json` in this directory. The genesis
contains pre-mints for both builders + CCM, all of which are required for the
L1's committed `initialState` to match what the builders compute locally.

### 3. Configure environment

```
cp deployments/chiado-multibuilder/.env.example deployments/chiado-multibuilder/.env
# Set BUILDER1_PRIVATE_KEY, BUILDER2_PRIVATE_KEY in .env
```

### 4. Start both builders

```
docker compose \
    -f deployments/chiado-multibuilder/docker-compose.yml \
    -f deployments/chiado-multibuilder/docker-compose.dev.yml \
    --env-file deployments/chiado-multibuilder/.env \
    up -d
```

### 5. Watch the race

```
# Tail both builders side-by-side (e.g. in tmux)
docker compose -f deployments/chiado-multibuilder/docker-compose.yml \
    -f deployments/chiado-multibuilder/docker-compose.dev.yml \
    --env-file deployments/chiado-multibuilder/.env logs -f builder1
docker compose -f deployments/chiado-multibuilder/docker-compose.yml \
    -f deployments/chiado-multibuilder/docker-compose.dev.yml \
    --env-file deployments/chiado-multibuilder/.env logs -f builder2

# Compare L2 head between the two
cast block-number --rpc-url http://localhost:9745   # builder1
cast block-number --rpc-url http://localhost:9845   # builder2

# L1 stateRoot — should advance regardless of which builder wins
source deployments/chiado-multibuilder/rollup-gnosis.env
cast call --rpc-url "$L1_RPC_URL" "$ROLLUPS_ADDRESS" \
    "rollups(uint256)(address,bytes32,bytes32,uint256)" 1
```

---

## Ports

Builder1 uses ports 974x; builder2 uses 984x. Both can coexist with the
existing `chiado-10200-public/` deployment (96xx) on the same host.
