# NoirWallet Bug Bounty — Security Research Report

**Program:** NoirWallet (HackenProof) — self-custodial Zcash privacy wallet (browser extension)
**Engagement type:** Authorized source-code audit (read-only static review; no live exploitation)
**Date:** 2026-11-16
**Commit audited:** `noir-wallet` @ `6b91c8d` · `zcash-wallet-wasm` @ `9a84e72` · `zcash-wallet-adapter` @ `9f9f166`

---

## A. Program intelligence

- **Product:** Self-custodial browser-extension wallet focused on Zcash (ZEC), shielded transactions, PCZT signing, hardware wallets (Ledger/Keystone), plus a default-enabled EVM provider and a shielded-voting feature.
- **Scope (code only — no live domains/contracts):**
  - `github.com/NoirWallet/noir-wallet` (Chrome extension; background/offscreen/storage/auth) + `packages/sdk` — Critical
  - `github.com/NoirWallet/zcash-wallet-wasm` (Rust→WASM core: keys, tx construction, signing, PCZT, sync) — Critical
  - `github.com/NoirWallet/zcash-wallet-adapter` (connectivity, messaging, permissions, WalletConnect) — Critical
  - `github.com/NoirWallet/noir-wallet-sdk` (archived legacy SDK)
- **Rewards:** Critical $2,000–5,000 · High $500–2,000 · Medium $100–500 · Low $100 (USDC). KYC + PoC required; $10 submission fee; 50 reputation required.
- **Allowed testing:** source review, static analysis, local testing, isolated fuzzing. (This engagement used source review only.)
- **Key exclusions honored:** no DoS; no third-party-infra testing; issues needing a fully compromised device are ineligible unless a NoirWallet-specific flaw is shown; known BlockSec findings #10/#12 excluded.
- **Critical definition (program):** private key exposure, unauthorized transfers, severe wallet-boundary compromise.

## B. Attack-surface map

| Surface | Trust boundary | Status |
|---|---|---|
| Content-script ↔ background bridge | Page (untrusted) → extension; origin derived from Chrome `sender` | **Solid** — top-frame-only, all URL candidates must agree |
| dApp authorization / connection consent | Per-origin authorization + approval UI | **DEFECT — see H-1** (auto-connect allowlist bypass) |
| Transaction signing approval (Zcash + EVM) | "What you see is what you sign" | Solid — approved params == signed; EVM graph/intent + payload-fingerprint binding |
| Approval/HW-sign response listeners | Popup → background | Solid — `isOwnExtensionRouteSender` route+window/tab scoped |
| Keyring / seed at rest / unlock | Password-gated vault; secrets only in trusted contexts | Hardened (one PBKDF2 inconsistency, device-gated) |
| Rust/WASM core (keys/PCZT/Ledger/sign) | Host ↔ device; untrusted CDN/RPC input | Hardened (one voting-metadata gap) |
| WalletConnect adapter | Peer wallet ↔ dApp | Hardened |
| SDK / in-page provider | Page world → content script | Hardened (one inherent co-resident forgery) |

---

## C. Findings (ranked)

### H-1 — Privileged auto-connect allowlist contains a non-official, takeover-prone "develop" origin → zero-click connection-consent bypass and silent disclosure of all shielded addresses
**Severity: High** (path to Critical — see justification) · **Confidence: High** · **CWE-863 Incorrect Authorization / CWE-284 Improper Access Control**
Full write-up in section **E**. This is the recommended submission.

### M-1 — Shielded-voting round metadata (snapshot height, proposal labels) not covered by the signed config
**Severity: Medium · Confidence: Medium · CWE-345 Insufficient Verification of Data Authenticity**
`zcash-wallet-wasm`: `src/voting/config.rs:759-780, 836-924`; `zcash_voting/.../config/mod.rs:238-241`.
The voting trust chain pins/signs the static+dynamic config, but per-round operational metadata fetched from the (by-design untrusted) vote server is only authenticated on `round_id`. `ea_pk` is correctly taken from the signed `AuthenticatedRound`, and forged chain *state* is blocked (`nc_root` re-verified against the chain in `prepare_round`, `session.rs:1292-1368`; nullifier root PIR-verified). But `snapshot_height` and the **proposal/option label text** are read verbatim from the server response and are not bound by any signature. A malicious/compromised vote server can, for a valid `round_id`: (a) pick a different but real `snapshot_height` to shift which historical balance determines voting power/eligibility; (b) swap option labels (tally is by option index, labels are display-only) so a user casts the opposite of their intent. Impact is voting-integrity, not funds/keys. **Fix:** extend signed `AuthenticatedRound` to commit to `snapshot_height` and a hash of the canonical proposal/helper-key set; compare in `trusted_round`.

### M-2 — Co-resident page script can forge in-page provider responses/events
**Severity: Medium · Confidence: High (mechanism), Low (reaches program bar) · CWE-346 Origin Validation Error**
`noir-wallet`: `packages/extension/src/content-script/inject-provider.ts:270-303, 807-823`.
Inbound provider messages are gated only by `event.source === window`, which is true for any co-resident script; the per-request `requestId` is observable in the cleartext outbound frame, so a malicious co-resident script (compromised npm dep / malicious ad / stored XSS on a legit dApp) can win the race and feed the dApp a forged account list, `accountsChanged`/`connect` event, or fake signature/result. **Impact is dApp-side integrity/phishing only** — it cannot expose keys or move funds (real signing stays behind the background approval flow), and the attacker is already same-origin. This is largely inherent to in-page postMessage bridges. **Fix:** deliver responses over a channel page scripts can't read/impersonate (transferred `MessagePort`, or a content-script-injected nonce/secret token). *Likely informational for this program; included for completeness.*

### L-1 — Zcash seed-at-rest protected by PBKDF2-SHA256 100k while the same mnemonic elsewhere uses Argon2id
**Severity: Low–Medium · Confidence: High · CWE-916 Weak Password Hash · *device-compromise-gated → likely program-ineligible***
`noir-wallet`: `packages/extension/src/core/wallet/secure-storage.ts:38-49` (also `credential-capsule.worker.ts:74`, `credential-envelope-authentication.ts:13`).
On wallet creation the BIP-39 mnemonic is persisted to `chrome.storage.local` (`seed_${walletId}`) under PBKDF2-SHA256 **100,000** iterations (≈6× below current OWASP guidance of 600k), whereas the *same* mnemonic in the multichain vault uses memory-hard Argon2id (19 MiB, t=2). Offline brute-force resistance of the seed is set by the weakest copy. Requires at-rest storage exfiltration (device/OS compromise), so it is ineligible under exclusion #4 absent a NoirWallet-specific flaw — the NoirWallet-specific angle is the *inconsistency* (strong Argon2id on one copy, legacy PBKDF2-100k on the duplicate). **Fix:** protect `seed_*` with Argon2id (or PBKDF2 ≥600k), or stop persisting the mnemonic twice.

### L-2 — Unchecked subtraction in journal replay (`range_end - range_start`)
**Severity: Low · Confidence: High · CWE-191 Integer Underflow · *DoS-class, excluded***
`zcash-wallet-wasm`: `src/wallet.rs:1634` (entry `scan_journal_entry`, `:1587`). Ordering of caller-supplied `range_start`/`range_end` is unchecked; `range_end < range_start` underflows (debug panic / release wrap). Trap/DoS only on the wallet's own recovery artifact — no fund impact. **Fix:** `checked_sub` + reject descending ranges.

### L-3 — Minor hardening notes
- **Adapter:** `lending` amount validator (`src/lending/index.ts:248-251`) allows unbounded decimals vs the ≤8-dp ZEC contract; harmless (re-validated downstream, user-approved) but inconsistent.
- **Analytics telemetry crypto** (`noir-wallet`: `lib/analytics/crypto.ts:11-15`): AES-128-CBC with key == IV == static build-time password (fixed IV, key/IV reuse). Protects only telemetry (no key material flows in), so **not** a key-exposure issue — a metadata-privacy weakness, notable only because this is a privacy-focused product. **Fix:** AES-GCM, random per-message IV.

---

## D. Unconfirmed leads (need the program's own confirmation; not mixed with confirmed findings)

- **NOIR_EVENT targeting:** the content script forwards every `NOIR_EVENT` from the service worker to its page (`content-script/index.ts:323-345`) with no local connection check, relying on the background to emit account-bearing events only to connected origins. If the background ever broadcasts `accountsChanged`/`connect` tab-wide, an unconnected origin could learn the active address → potential High (silent address disclosure). I did not find background over-broadcast, but the emit targeting was not exhaustively traced. Worth the program confirming per-connected-origin targeting.
- **Injected-provider TOFU (adapter):** `window.noirwallet` is trust-on-first-write; a hostile extension/earlier script can masquerade. Standard injected-wallet model; precondition is page-level compromise. Informational.
- **`zcash_voting` crate internals (~158k LOC):** only the config-authentication trust anchor and the delegation builder contract were reviewed; internals not exhaustively audited.

---

## E. Submission-ready report (H-1)

**Title:** Non-official, takeover-prone "develop" origin hard-coded in the privileged dApp auto-connect allowlist enables zero-click connection-consent bypass and silent disclosure of every account's shielded address

**Severity:** High (conditions for Critical stated below)
**Affected asset:** `github.com/NoirWallet/noir-wallet` — `packages/extension/src/core/dapp/first-party-policy.ts` (and the auto-connect consumers in `packages/extension/src/background/dapp-handler.ts`)
**Classification:** CWE-863 Incorrect Authorization; CWE-284 Improper Access Control; related CWE-200 (exposure of protected information)

**Summary.** The extension ships a hard-coded allowlist of origins that are auto-connected to the wallet **without any user approval**. Besides the official `https://app.zknoir.com`, the list contains `https://noirdevelop.refburrow.top` — a non-NoirWallet-branded `.top` domain that resolves (CNAME) to a **Cloudflare Pages *develop* deployment** (`noir-dashboard-develop.pages.dev`). Any page served from that origin can, with zero user interaction, cause the wallet to authorize **every account of every wallet** and return their **transparent and shielded addresses**. For a privacy-focused Zcash wallet, silent disclosure of shielded addresses is a core-threat-model breach (deanonymization), and granting production auto-connect to a low-assurance, takeover-prone staging origin is a severe expansion of the wallet's trust boundary.

**Root cause.**
```
// packages/extension/src/core/dapp/first-party-policy.ts
const AUTO_CONNECT_DAPP_ORIGINS: ReadonlySet<string> = new Set([
  'https://app.zknoir.com',
  'https://noirdevelop.refburrow.top'   // <-- non-official, .top, CNAME -> *.pages.dev (develop)
])
export function shouldAutoConnectDApp(origin: string): boolean {
  return AUTO_CONNECT_DAPP_ORIGINS.has(origin)
}
```
Origins in this set are treated as "first-party": the connection-consent UI is skipped and the origin is granted full account authorization automatically.

**Provenance red flag.** `first-party-policy.ts` was **created in the current HEAD commit `6b91c8d`, whose message is "fix(rpc): support Zcash Testnet registry and custom endpoints (#87)"** (author `Harry <jimi@ref.finance>`). A security-critical privileged-origin allowlist — including the non-official develop domain — was introduced inside a commit described as an unrelated RPC change. This is both a code-review/supply-chain hygiene failure and the kind of change that can hide a backdoor.

**Prerequisites.**
- Victim has the wallet **unlocked** (an active unlock session — the normal state while browsing).
- Victim's browser loads a page served from `https://noirdevelop.refburrow.top` (e.g., the attacker controls that origin via one of the scenarios below, or an XSS exists on that develop deployment).
- No clicks, no approval prompt.

**How the bypass executes (code path).**
1. `zcash_requestAccounts` → `requestAccounts()`:
   `dapp-handler.ts:491-492` — `if (shouldAutoConnectDApp(origin) && canAutoConnect(origin)) chosen = await this.authorizeAllWalletAccounts(origin)` — **no `runConnectApproval` / approval window.**
2. `zcash_getAccounts` → `getAccounts()`: `dapp-handler.ts:377-382` — same auto-authorization on a silent read.
3. `ensurePermission()` (gate for sensitive methods): `dapp-handler.ts:1985-1988` — auto-passes for these origins via `authorizeAllWalletAccounts`.
4. `authorizeAllWalletAccounts()` (`dapp-handler.ts:738+`) calls `buildAllWalletAccounts()` — **all wallets, all accounts** — persists the authorization and returns `{ transparent, shielded, accounts[] }` (each account's transparent + shielded addresses).
5. `canAutoConnect()` (`dapp-manager.ts:1279-1283`) returns `true` for a never-before-seen origin (state `undefined` → treated as `unreviewed`), so a first-time visit succeeds.
6. First-party origins also receive an elevated session scope limit of **64** (`first-party-policy.ts:10-13`).

**Proof of concept (safe; to run only against your own test wallet in a local/staging environment you control).**
Host the following at an origin equal to an allowlisted entry (for validation, temporarily add a throwaway origin you control to `AUTO_CONNECT_DAPP_ORIGINS` in a local build, or test against the real entry only with authorization):
```html
<script>
  // Zero user interaction — runs on page load.
  const res = await window.noirwallet.zcash.requestAccounts(); // no approval dialog appears
  // res.shielded / res.transparent / res.accounts[] are returned immediately
  console.log('harvested addresses', res);
  // exfiltrate res to attacker server …
</script>
```
**Expected behavior:** the wallet shows a connection-approval dialog and discloses addresses only after the user approves, and only for the account(s) the user selects.
**Actual behavior:** for an allowlisted origin, no dialog is shown and **all** accounts' transparent + shielded addresses are disclosed automatically.

**Security impact.**
- **Connection-consent boundary fully bypassed** for the allowlisted origin ("severe wallet-boundary compromise" per the program's Critical definition).
- **Silent deanonymization:** every account's shielded address — the wallet's core protected secret — is disclosed to a web origin with no user action. The program's own out-of-scope text carves out "public blockchain data **unless a flaw exposes additional protected information**"; shielded addresses are exactly that protected information, and the "privacy and Zcash security" category is in scope.
- **Blast radius = all users** (the allowlist ships in the default/production build; it is not dev-gated).
- Signing/fund-movement still requires the approval UI, so this is silent *connection + address disclosure*, not silent transfer.

**Attack scenarios (why the domain is the problem).**
1. **Dangling-CNAME / subdomain takeover:** `noirdevelop.refburrow.top` is a custom domain CNAME'd to a Cloudflare Pages project. "develop" projects are routinely renamed/deleted; if the Pages project name is freed, an attacker registers a Pages project with that name and the CNAME points at attacker content → the attacker now controls a *privileged auto-connect origin* and silently harvests addresses from every user who visits.
2. **Domain lapse:** `refburrow.top` is a cheap-TLD domain outside NoirWallet's primary branding; if it expires/changes hands, the new owner inherits auto-connect privilege.
3. **XSS on the develop deployment:** develop/staging environments are typically lower-assurance (debug features, relaxed CSP). A single XSS on `noirdevelop.refburrow.top` yields zero-click wallet connection + shielded-address exfiltration for all production users — no takeover needed.

**Severity justification.** Rated **High** as the defensible baseline: a low-assurance, non-production, structurally takeover-prone origin holds production auto-connect privilege, and exploitation yields zero-click disclosure of every user's protected shielded addresses (deanonymization), a core-threat-model breach for a privacy wallet. It rises to **Critical** ("severe wallet-boundary compromise") upon any of: demonstrated attacker control of the origin (Pages-project takeover or domain lapse), or an XSS on the develop deployment. I do **not** assert the origin is attacker-controlled today — it currently resolves to live infrastructure — which is why the baseline is stated as High; the program is best positioned to confirm ownership and takeover-resistance, which determines the final rating.

**Remediation.**
1. **Remove `https://noirdevelop.refburrow.top` from the production allowlist** immediately; never ship develop/staging origins with production auto-connect. Gate any dev-only auto-connect behind a dev/test build flag (as the project already does for conformance-signing RPC and EVM dev-server behavior).
2. Keep auto-connect to official production origins only, and prefer verifying first-party status by a mechanism not tied to an externally-registerable DNS label.
3. **Audit the dangling-CNAME exposure:** ensure the Cloudflare Pages project backing any custom domain cannot be re-registered by a third party; remove stale custom-domain CNAMEs.
4. Require security review / CODEOWNERS approval for changes to `first-party-policy.ts`; investigate how a privileged-origin allowlist entered the tree inside an unrelated "fix(rpc)" commit.
5. Consider requiring an explicit (even one-time) user consent for first-party origins, so no origin connects fully silently.

**Evidence.**
- Source: `first-party-policy.ts:1-8, 10-13`; `dapp-handler.ts:377-382, 434-435, 491-492, 738+, 1985-1988`; `dapp-manager.ts:1279-1283`.
- Git provenance: file created new in `6b91c8d` — `git log -p -- packages/extension/src/core/dapp/first-party-policy.ts`.
- DNS (passive): `noirdevelop.refburrow.top` → CNAME `noir-dashboard-develop.pages.dev` (A `172.66.47.89`, `172.66.44.167` — Cloudflare); apex `refburrow.top` → `172.104.172.238` (Linode). No active traffic was sent to the host.
- **Executed PoC (see `noirwallet-H1-poc.md` + `noirwallet-H1-poc-tier1.mjs`):** (1) running the *real* shipped `first-party-policy.ts` returns `shouldAutoConnectDApp('https://noirdevelop.refburrow.top') === true` and session scope `64` (vs `16`), while a random attacker origin is `false`; (2) a clean `pnpm install && vite build` yields `dist/assets/runtime-message-security-*.js` containing `Set(["https://app.zknoir.com","https://noirdevelop.refburrow.top"])` — proving it ships in the production bundle (`Noir Wallet` v2.0.0), not dev-stripped.
- **Not reproduced live in the sandbox (honest):** the zero-click address-exfiltration demo additionally needs (a) beta activation via a server-validated invite code (`betaInviteActivation.isActivated()` gates all dApp requests; `infrastructure/wallet/beta-invite-api.ts`) and (b) a created/unlocked wallet — neither available here. This is an environmental blocker, not evidence the bug is absent. It is also a real-world mitigant: current exploitation is limited to beta-activated installs (which is the intended user flow for this promoted beta). Manual full-repro steps are in `noirwallet-H1-poc.md`.

---

## E-bis. Round-2 deep Critical hunt (outcome)

A second pass ran four adversarial agents dedicated to the Critical tier (unauthorized transfer / key exposure), each briefed with round-1's verified facts to go deeper:
- **Zcash send/PCZT fund-redirection** — no Critical. `to`/`amount`/`memo`/fee/account are bound by object identity (software path) or exhaustive field-equality + consume-on-use + JSON binding (hardware path), re-asserted immediately before broadcast; PCZT combine uses the background's own stored full PCZT; sighash binding backstops everything.
- **EVM / blind-sign drains** — no Critical. The raw signed tx is decoded and re-verified byte-for-byte against the reviewed intent; typed-data renders the full AST and decodes Permit/Permit2 (not `primaryType`-only). *Residual lead:* typed-data AST↔digest faithfulness depends on the Rust summarizer (not fully covered). *Low defect:* mislabeled "USDC" token hint (`evm-dapp-handler.ts:1028-1033`) — not UI-consumed, not exploitable.
- **Authorization TOCTOU / cross-origin / session integrity** — no Critical. Uniform capture→approve→recheck(active+authorization+revision); origin derivation unforgeable; the CAIP-25 fail-open is not on the `wallet_invokeMethod` path and the one legacy use is backstopped by per-chain `requireAuthorizedAccount`; first-party status never relaxes per-transaction approval.
- **Key/seed exfiltration** — no Critical. No `externally_connectable`; secret handlers double-gated to the `extension-page` context; every WASM signing export takes a caller-supplied key and never serializes the USK/seed to JS.

**Net:** no new Critical. H-1 remains the strongest eligible finding; its PoC status is recorded in section E and `noirwallet-H1-poc.md`.

## F. Research conclusion

- **Thoroughly investigated:** content-script/background trust boundary and origin derivation; the full dApp authorization + connection model (Zcash + default-enabled EVM); transaction signing/approval WYSIWYS (Zcash send, EVM send/sign, payload-fingerprint binding); approval/HW-sign response listeners; CAIP-25 multichain scope parsing; keyring/seed-at-rest crypto, unlock/session gating, credential envelopes; the Rust/WASM core (key boundary, PCZT prove/combine/extract, Ledger PCZT, one-click & delegation signers, fee/amount handling, compact-block CDN validation); the WalletConnect adapter and SDK/in-page provider.
- **Confirmed:** **H-1** (recommended submission). Supporting lower-severity items M-1, M-2, L-1, L-2, L-3.
- **Not reproduced / cleared:** no forged-approval path, no approve-one-sign-another gap, no key/seed leak across the WASM boundary or into logs/analytics/errors, no WalletConnect scope-widening, no SSRF via rpc-registry, no fixed-nonce/missing-integrity in the wallet-secret path.
- **Most promising next areas:** (1) confirm background `NOIR_EVENT` targeting is strictly per-connected-origin (lead D); (2) exhaustive audit of the `zcash_voting` crate internals around M-1; (3) dynamic/local testing of the H-1 auto-connect flow in a built extension to demonstrate the zero-click disclosure end-to-end; (4) a focused review of the multichain Rust vault (Argon2id/XChaCha nonce handling) which is opaque to TS-level static review.
- **Caveat:** static review only; no instrumented/dynamic testing was performed. Severity of H-1 depends on origin ownership/takeover-resistance, which the program should verify.
