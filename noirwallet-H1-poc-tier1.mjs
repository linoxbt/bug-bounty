// Tier-1 PoC: execute the REAL shipped first-party auto-connect policy module.
import {
  shouldAutoConnectDApp,
  getDAppSessionScopeLimit
} from '/home/user/noirwallet/noir-wallet/packages/extension/src/core/dapp/first-party-policy.ts'

const ROGUE = 'https://noirdevelop.refburrow.top'
const OFFICIAL = 'https://app.zknoir.com'
const ATTACKER_RANDOM = 'https://evil.example.com'

const results = {
  'shouldAutoConnectDApp(rogue)': shouldAutoConnectDApp(ROGUE),
  'shouldAutoConnectDApp(official)': shouldAutoConnectDApp(OFFICIAL),
  'shouldAutoConnectDApp(random attacker)': shouldAutoConnectDApp(ATTACKER_RANDOM),
  'scopeLimit(rogue)': getDAppSessionScopeLimit(ROGUE),
  'scopeLimit(random)': getDAppSessionScopeLimit(ATTACKER_RANDOM)
}
console.log(JSON.stringify(results, null, 2))

const pass =
  results['shouldAutoConnectDApp(rogue)'] === true &&
  results['shouldAutoConnectDApp(random attacker)'] === false &&
  results['scopeLimit(rogue)'] === 64 &&
  results['scopeLimit(random)'] === 16
console.log('\nTIER-1 RESULT:', pass ? 'PROVEN — rogue origin is auto-connect + elevated scope' : 'NOT PROVEN')
process.exit(pass ? 0 : 1)
