# Kite AI — Staking Contracts Drill (FINDINGS)

**Target:** Kite AI (EVM L1 / Avalanche subnet-evm), Sherlock + Code4rena bug bounty
**Bounty terms:** Critical ≤ $10,000 USDC, High ≤ $2,000. KYC required. Live since 2026-07-20 (5 days old at time of drill).
**Drill date:** 2026-07-25
**Verdict:** **FILE NOTHING — target exhausted.** Two genuine bugs found and confirmed; both are duplicates of already-filed Code4rena known-issues (out of scope). Skeptic re-drill of swarm-uncovered seams yielded zero novel payable findings.

---

## Scope (authoritative)

Source of truth: `gokite-ai/developer-docs` → `kite-chain/3-developing/smart-contracts-list.md` (the page `docs.gokite.ai` renders; pulled from GitHub because `docs.gokite.ai`/`kitescan.ai`/`gokite.ai` are egress-blocked in this environment). Verified source pulled from `kitescan.ai` Blockscout API and committed under `drills/kite/src/` (flattened) and `drills/kite/core/` (Kite-specific bodies extracted).

In-scope, audited here (Kite-native staking stack):

| Contract | Address | Origin |
| --- | --- | --- |
| KiteStakingManager (impl) | `0x065cA4309a5abc9F1cC2d8fA00634BC948C25C6b` | Fork of Ava Labs ACP-77 `StakingManager` (+951 changed lines) |
| RewardVault | `0xd26850d11e8412fC6035750BE6A871dff9091FAe` | Kite-novel (no upstream) |
| FixedAPRRewardCalculator | `0x171eefa30E88f9bca456CEf49c5Df093A516C7c2` | Modified `ExampleRewardCalculator` |
| StakingVault (impl) | `0x69379f875551A505d77876a9363BcDe3dfd00bbe` | Kite-novel LST vault |
| StakingVaultOperations (impl) | `0xE31b845a6898D165e3dFc2AD4C3D61fE74394817` | Kite-novel |
| ValidatorMessages | `0x9C00629cE712B0255b17A4a657171Acd15720B8C` | Byte-identical upstream (deprioritized) |

Fork baseline for diffing: `ava-labs/icm-contracts` `contracts/validator-manager/`.

---

## Findings (both CONFIRMED real, both DUPLICATE → not fileable)

### A — CRITICAL — Reentrancy in `forceInitiateDelegatorRemoval` drains pooled principal
- **Location:** `StakingManager.kite.sol` — `forceInitiateDelegatorRemoval` (~1335, `external`, **no `nonReentrant`**; siblings at 1311/1545 have it) → Completed-validator branch (~1423, never sets `PendingRemoved`) → `_completeDelegatorRemoval` (~1587) → `_withdrawDelegationRewards` → `_reward` → `RewardVault.distributeReward` → `sendValue(attacker)` (external call at ~1731) **before** `delete $._delegatorStakes` (~1627) and `_unlock` (~1643). `delegator` is a per-frame `memory` copy → each reentrant frame re-`_unlock`s the same weight `W`.
- **Mechanism / root cause (verified vs upstream):** upstream `_completeDelegatorRemoval` deletes state **first** (CEI-safe) and `_reward` is a `NATIVE_MINTER` precompile (no callback). Kite (a) moved the `delete` to after the external call and (b) replaced the precompile with an attacker-reachable `call{value:}` — to keep rewards claimable when the vault is dry. Both changes jointly fatal. NB: do **not** frame this as "Kite removed a `nonReentrant`" — upstream also lacks it there; upstream was safe purely via CEI.
- **Impact:** N reentrant frames unlock `N×W` for one `W` staked, draining `KiteStakingManager`'s pooled native balance (all stakers' principal) + `RewardVault`. Profitable at N=2. Permissionless.
- **Verification:** adversarial refutation agent tried all 7 kill-angles → **CONFIRMED-CRITICAL** (reachability, callback, no-guard, same-reward-recompute, memory-copy multiplication, gas 63/64 profit, principal-not-just-vault all hold).
- **DUPLICATE OF (Code4rena known-issues, out of scope):** #19, #20, #21, #22, #23, #24, #25, #26, #27, #28 (≈10 verbatim prior submissions). Also pre-flagged by Halborn "Staking & Rewards" audit ("add `nonReentrant` to prevent reentrancy").

### B — HIGH (originally posited Critical; corrected) — Uptime-baseline / reward has no wall-clock cap
- **Location:** `FixedAPRRewardCalculator.calculateIncrementalReward` (`FixedAPRRewardCalc.sol:99-112`): `periodDuration = currentTime − lastClaimTime` is computed, checked `==0`, then **dead**; reward = `stake × bips × (currentUptime − lastClaimUptime) / (YEAR × 10000)` with no wall-clock bound. Combined with delegator baseline anchored via `_updateUptime` (returns `max(stored, signedProof)`) and no replay protection on uptime Warp messages (no nonce/expiry).
- **Mechanism:** an attacker with their own pristine validator (stored uptime 0) replays a stale low-uptime signed proof at delegator registration (baseline ≈ 0), then claims with a fresh high proof → paid for pre-delegation uptime. Drains `RewardVault`.
- **Verification:** refutation agent → **CONFIRMED-HIGH, not Critical.** The registration baseline is a *mandatory validator-set-signed* proof (`completeDelegatorRegistration` ~1290/1295), so the exploit requires a replayable stale quorum-signed proof surviving validator-set churn + the attacker's own genuinely-run validator — real but non-trivial preconditions. Upstream bounds reward by `(stakingEndTime − stakingStartTime)`; Kite removed that cap.
- **DUPLICATE OF:** #29, #39, #42 ("HAL-7.4 … proof-freshness"), #48.

---

## Vault layer — CLEAN (verified)

`StakingVault` / `StakingVaultOperations` produced **no** Critical/High after two rounds:
- Share math: 1e9 virtual offset applied to both num/denom; both conversions round DOWN (favor pool); round-trip proven non-profitable. `totalAssets` reads internal accounting, never `address(this).balance` → donation/inflation impossible; `receive()` gated, `fallback()` reverts value-bearing calls.
- Withdrawal queue: double-claim blocked (`fulfilled` flag + `requestId < queueHead`); `claimWithdrawalFor` always pays `request.user`; process cursor never skips unprocessed entries.
- Proxy + delegatecall-extension: fallback routing, selector space, ERC-7201 slots (independently recomputed), cross-boundary reentrancy guard, UUPS auth — all sound.

(The swarm did file several vault issues: #46 operator-fee double-count, #51 pre-completion over-withdraw, #53/#54 withdrawal-queue — all already known.)

---

## Skeptic re-drill — swarm-uncovered seams — 0 novel survivors

Hunted the four seams the 30-warden Code4rena swarm barely touched, novelty-gated against all 30 known issues:
1. `ValidatorManager` weight/nonce/churn — byte-identical audited upstream; deltas reduce to known #1/#5/#7/#8.
2. Reward-recipient hijack / fee edges (non-reentrancy) — setters owner-gated, reject `address(0)`; `net+fee==gross`; only residual = self-recoverable reverting-recipient (Low, ~#8).
3. Deep `StakingVaultOperations` — delegated-stake invariant holds; selection loops skip/double/OOB-free; ops role-gated through delegatecall.
4. Cross-contract invariants — balance-delta measurement + `isReceivingManagerFunds` gate + paired state-sync prevent double-count.

**Closest-but-fails:** (a) reverting-recipient reverts removal → self-inflicted, self-curable, no third-party harm → Low/#8; (b) incremental-claim vs removal commission windows → provably disjoint (`lastRewardClaimTime` advanced) → no double-pay.

---

## Why not fileable / lessons

- Both real findings are in the **30-issue Code4rena known-issues set** (every opened issue is out-of-scope per bounty rules) and partly pre-covered by **Halborn "Staking & Rewards" (2026)**.
- The bounty was **5 days old, $10k cap, and C4-swarmed** — dedup surface saturated before this drill.
- **Process fix for next target: run the dedup gate FIRST** (C4/Sherlock known-issues repo + prior audits) before spending audit compute. If the known-issues repo is already fat, walk away.
- **Best next targets:** freshly launched with no concurrent public contest, or private/KYC-gated scope the swarm can't reach.

**Method validated** (fork-diff → adversarial finders → refutation → dedup gate); **nothing banked** — correctly, per FLOOR-FIRST + dedup discipline.
