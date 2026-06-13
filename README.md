# Compliant Stablecoin

A privacy-preserving, regulation-aware stablecoin built in [Leo](https://leo-lang.org) for the [Aleo](https://aleo.org) network. The system implements a fungible token (USDCx) that supports both **public** and **private** transfers while retaining the compliance controls a regulated issuer needs: role-based administration, a freeze/deny list, an investigator audit trail, a pausable transfer switch, and a Circle-CCTP-style bridge for cross-chain minting and burning. Program upgrades are gated behind a reusable k-of-n multisig.

Privacy and compliance are usually at odds. This design reconciles them with zero-knowledge Merkle proofs: a user can prove their address is *not* on the freeze list without revealing which address they are, and every private transfer simultaneously emits an encrypted `ComplianceRecord` that only a designated investigator can read.

> **Developed together with Sealance Technology by Forte.**

---

## Architecture

The system is composed of five Leo programs. Each is independently deployable, and dependencies are wired through `program.json`. The arrows below show the import/dependency direction.

```
                       merkle_tree.aleo
                              ▲
                              │ (non-inclusion proofs)
                              │
   multisig_core.aleo ◄── freezelist_program.aleo
        ▲   ▲                 ▲
        │   │                 │
        │   └──── stablecoin_program.aleo (USDCx)
        │                 ▲
        │                 │
        └──────── stablecoin_bridge.aleo
```

| Program | Purpose | Dependencies | License |
| --- | --- | --- | --- |
| `merkle_tree.aleo` | Reusable Merkle inclusion / non-inclusion proof verification. | — | MIT |
| `multisig_core.aleo` | k-of-n multisig supporting both Aleo and ECDSA (Ethereum) signers; governs program upgrades. | — | GPL |
| `freezelist_program.aleo` | Compliance freeze/deny list with a public mapping and a Merkle root for private checks. | `merkle_tree`, `multisig_core` | GPL |
| `stablecoin_program.aleo` | The USDCx token: public + private balances, roles, minting/burning, transfers, allowances, pausing. | `freezelist_program`, `multisig_core` | GPL |
| `stablecoin_bridge.aleo` | Mints / burns USDCx against Circle CCTP-style attestations bridged from Ethereum. | `stablecoin_program`, `freezelist_program`, `multisig_core` | GPL |

---

## Programs in detail

### `merkle_tree.aleo`

A small, dependency-free library of Merkle-proof primitives shared across the system.

- `verify_inclusion(addr, proof)` — proves an address is a leaf in the tree and returns the computed root.
- `verify_non_inclusion(addr, [proof; 2])` — proves an address is **absent** from a tree whose leaves are sorted ascending by address-as-`field`. It takes the two adjacent leaves that bracket the missing address and asserts the target falls strictly between them (with dedicated handling for the left-most and right-most edges).
- Hashing uses **Poseidon4**, with a domain-separation prefix (`0field` for internal nodes, `1field` for leaves) to prevent second-preimage attacks across tree levels.
- `MAX_TREE_DEPTH = 15`, so proofs carry up to 16 sibling entries. A `0field` sentinel in the siblings array marks the end of a shorter path.

This program is marked `@noupgrade` — it is immutable once deployed.

### `multisig_core.aleo`

A general-purpose, reusable k-of-n multisig that the other programs rely on to authorize upgrades. Notable properties:

- **Mixed signer types.** A wallet can mix native Aleo signers and ECDSA/Ethereum signers (up to four of each). ECDSA signatures are verified on-chain against an EIP-191 (`"\x19Ethereum Signed Message:\n32"`) digest, with a per-operation nonce to prevent replay.
- **Signing operations.** A signing op is identified by `hash(wallet_id, signing_op_id)`. Signers confirm independently until the wallet threshold is reached, at which point the op is recorded in `completed_signing_ops`. Operations carry an expiry (in blocks) and a round counter so an expired `signing_op_id` can be safely reused without old signatures leaking into the new round.
- **Admin operations.** Change-threshold, add-signer, and remove-signer are themselves multisig-gated operations.
- **Upgrade governance.** `ProgramSettings` holds an `allow_upgrades` kill-switch and an `upgrader_address`. Other programs check `completed_signing_ops` in their `constructor` before permitting an upgrade (see below).
- **Wallet-creation guard.** Optionally (`guard_create_wallet`), creating new wallets itself requires a completed multisig op, so the public cannot squat wallet IDs the deployer cares about.

> This program is adapted from a general-purpose multisig implementation; its own `README.md` referenced in the source header describes the standalone scheme in more depth.

### `freezelist_program.aleo`

The compliance backbone. It maintains the set of frozen/denied accounts in two complementary forms:

- A **public mapping** `freeze_list: address => bool` for transparent, public-transfer checks.
- A **Merkle root** (`freeze_list_root`) over the sorted set of frozen addresses, enabling *private* non-inclusion proofs — a user proves they are not frozen without revealing their address.

Key mechanics:

- **Root rotation window.** When the list changes, the current root becomes the previous root and `root_updated_height` is stamped. A configurable `block_height_window` keeps the previous root valid for a grace period, so in-flight transactions built against the old root don't fail during an update.
- `update_freeze_list(...)` adds or removes an account, maintaining a packed index (`freeze_list_index`) and guarding against double-freezing, double-unfreezing, and accidental root overwrites (it requires the caller to pass the expected `previous_root`).
- `verify_non_inclusion_pub` / `verify_non_inclusion_priv` expose public and private compliance checks for other programs and clients.
- Access is role-gated: a `MANAGER_ROLE` assigns roles, and a `FREEZELIST_MANAGER_ROLE` mutates the list and the block-height window.

### `stablecoin_program.aleo` — USDCx

The token contract. It implements an ERC-20-style public interface plus Aleo-native private records.

**State & metadata**
- `TokenInfo` holds name, symbol, decimals, supply, and a hard `max_supply` cap enforced on every mint.
- Public balances live in `balances: address => u128`; allowances in `allowances` keyed by `hash(account, spender)`.
- Private holdings are `Token` records (`owner`, `amount`), splittable and joinable via `split` / `join`.

**Roles** (bit-masked, so one address can hold several)
- `MINTER_ROLE`, `BURNER_ROLE`, `PAUSE_ROLE`, `MANAGER_ROLE`. The manager assigns roles via `update_role`; a manager cannot strip their own manager bit by accident.

**Lifecycle & transfers**
- `initialize` (deployer-only, once) sets metadata and the initial admin.
- Mint / burn: `mint_public`, `mint_private`, `burn_public`, `burn_private`.
- Public transfers: `transfer_public`, `transfer_public_as_signer`, `transfer_from_public` (+ `approve_public` / `unapprove_public`).
- Cross-visibility transfers: `transfer_public_to_private`, `transfer_from_public_to_private`, `transfer_private`, `transfer_private_to_public`.
- `set_pause_status` (pause-role) halts all transfers in an emergency; every transfer/mint/burn checks the pause flag.

**Compliance integration**
- Every public transfer checks both sender and recipient against the public freeze list.
- Every transfer that touches private records verifies the sender's **non-inclusion** in the freeze-list Merkle tree (accepting the current or recently-rotated previous root).
- Every private movement emits a `ComplianceRecord` owned by the `INVESTIGATOR_ADDRESS`, recording amount, sender, and recipient — an encrypted audit trail readable only by the investigator.
- `get_credentials` issues a reusable `Credentials` record proving freeze-list non-inclusion, so a user can make repeated private transfers (`transfer_private_with_creds`) without re-proving each time.

### `stablecoin_bridge.aleo`

Bridges USDCx to/from an external chain using Circle's CCTP-style attestation format.

- `mint_private` / `mint_public` parse a 240-byte deposit payload, validate a magic value, version, domain, non-zero token & recipient addresses, and amount, then verify a Circle **attester ECDSA signature** over the Keccak-256 digest of the payload before minting. A `nullifier` mapping prevents replaying the same deposit.
- Minting also enforces the freeze list (private Merkle non-inclusion for private mints, the public mapping for public mints) and the bridge pause switch.
- `burn_public` burns USDCx and records the native destination domain + recipient for Circle compliance, subject to a configurable `minimum_burn_amount`. (The legacy `burn` entrypoint is intentionally disabled with an always-failing assertion.)
- Admin keys: `USDCX_PAUSE_KEY` controls pausing; `USDCX_MANAGER_KEY` sets the Circle attester and the minimum burn amount.

---

## Upgrade governance

Every upgradeable program (`stablecoin_program`, `freezelist_program`, `stablecoin_bridge`) uses the same pattern in its `constructor`:

- **Edition 0 (initial deployment):** no checks — the program deploys freely.
- **Edition > 0 (upgrade):** the program derives `signing_op_id = hash(checksum, edition)` and requires a *completed* multisig operation for it in `multisig_core.aleo/completed_signing_ops`. Binding the signing op to both the code checksum **and** the edition number means an upgrade must be explicitly approved and cannot be downgraded or replayed against a different build.

`merkle_tree.aleo` is `@noupgrade` and `multisig_core.aleo` governs its own upgrades through its `ProgramSettings`.

---

## Privacy & compliance model

| Capability | How it's achieved |
| --- | --- |
| Private balances & transfers | Aleo `Token` records; amounts and owners stay off the public ledger. |
| "Prove I'm not sanctioned" without doxxing | Zero-knowledge Merkle **non-inclusion** proof against the freeze-list root. |
| Regulator visibility into private flows | `ComplianceRecord` records encrypted to a fixed `INVESTIGATOR_ADDRESS`. |
| Sanctions enforcement on public flows | Direct `freeze_list` mapping checks on sender and recipient. |
| Emergency stop | `pause` flag honored by every value-moving transition. |
| Safe list updates | Previous-root grace window so in-flight proofs don't break mid-update. |
| Reusable compliance | `Credentials` record lets a vetted user transact privately without re-proving each time. |

---

## Repository layout

```
.
├── merkle_tree/          # Merkle proof verification library (immutable)
├── multisig_core/        # k-of-n multisig (Aleo + ECDSA), upgrade governance
├── freezelist_program/   # Compliance freeze/deny list + Merkle root
├── stablecoin_program/   # USDCx token (public + private)
├── bridge_program/       # stablecoin_bridge.aleo — Circle CCTP-style bridge
├── LICENSE.md            # GNU General Public License
└── README.md
```

Each program directory contains a `program.json` manifest and `src/main.leo`.

---

## Building

These programs target the [Leo](https://docs.leo-lang.org) toolchain version **3.4.0**.

```bash
# Install Leo (see https://docs.leo-lang.org for the latest instructions)

# Build a single program (e.g. the token), with its local dependencies resolved:
cd stablecoin_program
leo build
```

Because of the dependency graph, programs must be deployed bottom-up:

1. `merkle_tree.aleo`
2. `multisig_core.aleo`
3. `freezelist_program.aleo`
4. `stablecoin_program.aleo`
5. `stablecoin_bridge.aleo`

> **Before deploying:** the `DEPLOYER_ADDRESS` / `MULTISIG_DEPLOY_KEY` / `INVESTIGATOR_ADDRESS` and the bridge's `USDCX_*` and `ETH_PUBLIC_KEY` constants are currently set to test values. Replace them with production keys before mainnet deployment. The multisig source notes this explicitly: *"IMPORTANT! Remember to change this before deployment!"*

---

## Security notes

- **Arithmetic safety.** Underflow/overflow on balances and supply is caught by the Aleo VM; the code relies on this (e.g. burning more than a balance reverts).
- **Domain separation.** Merkle hashing prefixes leaves vs. internal nodes; multisig hashes wrap IDs in verbosely-named structs to avoid cross-context collisions.
- **Replay protection.** The bridge uses a per-deposit nullifier; ECDSA multisig signatures use per-operation nonces.
- **Sorted-tree assumption.** Non-inclusion soundness depends on the freeze-list Merkle tree being correctly sorted ascending by address; off-chain tooling that builds the tree must preserve this invariant.

---

## License

Unless noted otherwise in an individual `program.json`, the programs are released under the **GNU General Public License** (see [`LICENSE.md`](./LICENSE.md)). `merkle_tree.aleo` is licensed under MIT.

---

## Acknowledgements

**Developed together with Sealance Technology by Forte.**
