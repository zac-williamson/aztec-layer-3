// Prints test vectors for the Bridge's receipt-challenge TXE tests: a receipt key and two receipts
// signed with it. Run once: node src/receipt_vectors.ts
import { newApi } from './pipeline.ts';
import { hex } from './lib.ts';
import { keysFromSeed, scalarToNoir, sign } from './exchange/grumpkin.ts';
import * as M from './exchange/model.ts';

const api = await newApi();
const h = M.hasher(api);
const k = await keysFromSeed(h, 0x7265636569707473n); // "receipts"
const domain = 0x1234abcdn;
console.log(`pk_x ${hex(k.pk.x)}\npk_y ${hex(k.pk.y)}`);
for (const [msg, seq, issued] of [[0x5151n, 7n, 1n], [0x6262n, 8n, 1n]]) {
  const s = await sign(h, k.sk, await h([51n, domain, msg, seq, issued]));
  const sc = scalarToNoir(s.s);
  const ec = scalarToNoir(s.e);
  console.log(`msg ${hex(msg)} seq ${seq} issued ${issued}: s { lo: ${sc.lo}, hi: ${sc.hi} } e { lo: ${ec.lo}, hi: ${ec.hi} }`);
}
await api.destroy();
