// The operator node's gateway and sequencer (P2.24, SPEC.md §5, §11): a TCP server speaking
// newline-delimited JSON (wire.ts). Each signed action is checked, sequenced, journaled and
// answered with its receipt and execution report, or refused.
//
// For tests and load runs it starts from genesis with `--accounts N` demo accounts, registered and
// funded through priority requests, whose keys come from seeds DEMO_SEED + i (load.ts derives the
// same keys), and opens a block every second with signed index updates from the test oracles.
// A deployment instead restores its state from the journal and the Bridge.
//
// The gateways (gateway.ts) are worker threads sharing the port: they parse, check signatures and
// sign receipts, so this thread only sequences and journals. With `--gateways 0` this thread does
// everything itself.
//
// Usage: node src/operator/server.ts [--port 7300] [--accounts 1000] [--journal path] [--fsync]
//                                     [--threads 16] [--gateways 4] [--block-ms 1000] [--batch-ms 72000]
import { createServer, type Socket } from 'node:net';
import { parseArgs } from 'node:util';
import { Worker } from 'node:worker_threads';
import { randomField } from '../lib.ts';
import { Engine, signUpdate } from '../exchange/engine.ts';
import { keysFromSeed } from '../exchange/grumpkin.ts';
import * as M from '../exchange/model.ts';
import { protocolAccounts, testParams } from '../exchange/params.ts';
import { native } from '../native.ts';
import type { GatewayConfig, ToGateway, ToSequencer } from './gateway.ts';
import { Sequencer } from './sequencer.ts';
import { type Request, type Response, fromWire, lineReader } from './wire.ts';

export const DEMO_SEED = 0x6c33782e64656d6fn; // "l3x.demo"
/** The test markets' index prices for demo runs (markets 0, 1, 2). */
export const DEMO_PRICES = [2000n, 30_000n, 100n];
export const RECEIPT_SEED = 0x6c33782e72637074n; // "l3x.rcpt"

const { values: args } = parseArgs({
  options: {
    port: { type: 'string', default: '7300' },
    accounts: { type: 'string', default: '1000' },
    journal: { type: 'string' },
    fsync: { type: 'boolean', default: false },
    threads: { type: 'string', default: '16' },
    gateways: { type: 'string', default: '4' },
    'block-ms': { type: 'string', default: '1000' },
    'batch-ms': { type: 'string', default: '72000' },
  },
});
const log = (m: string) => console.log(`[operator] ${m}`);
native.cryptoThreads(Number(args.threads));

const h = M.hasher(null as any);
const { params, oracleSks } = await testParams(h);
const engine = await Engine.create(null as any, params, 0n, await protocolAccounts(h), {}, { lite: true });
const receiptKey = await keysFromSeed(h, RECEIPT_SEED);
const seq = new Sequencer(engine, { receiptSk: receiptKey.sk, journal: args.journal, durability: args.fsync ? 'fsync' : 'write' });

// Genesis, journaled like everything after it: batch 1, a block with the index prices, the demo
// accounts' encryption keys (as Bridge.register delivers them), then their registrations and deposits.
const N = Number(args.accounts);
const t0 = performance.now();
let now = BigInt(Math.floor(Date.now() / 1000));
const updates = (time: bigint) => Promise.all(DEMO_PRICES.map((p, m) => signUpdate(h, engine.domain, oracleSks, [0, 2], BigInt(m), p, p, time)));
let batch = 1n;
await seq.newBatch(batch);
await seq.block(now, await updates(now));
const reqs: M.Request[] = [];
for (let i = 0; i < N; i++) {
  const k = await keysFromSeed(h, DEMO_SEED + BigInt(i));
  const encC = await M.encCommitment(h, k.kEnc);
  void seq.deliverKey(encC, k.kEnc);
  reqs.push({ kind: M.KIND.REGISTER, a: await M.masterAuthOf(h, k.pk!.x, k.pk!.y), b: encC, sender: randomField(), time: now });
}
for (let i = 0; i < N; i++) reqs.push(await M.depositRequest(h, BigInt(2 + i), 1n << 40n, randomField(), now));
await seq.priority(reqs);
log(`genesis: ${N} demo accounts registered and funded in ${(performance.now() - t0).toFixed(0)} ms`);

// A new batch every slot (SPEC.md §9.1, [D10]).
setInterval(() => void seq.newBatch(++batch).catch((e) => log(`batch ${batch} refused: ${e.message}`)), Number(args['batch-ms']));

// A block every second; its index updates come from the test oracles.
setInterval(async () => {
  const t = BigInt(Math.floor(Date.now() / 1000));
  if (t <= now) return;
  now = t;
  try {
    await seq.block(t, await updates(t));
  } catch (e: any) {
    log(`block ${t} refused: ${e.message}`);
  }
}, Number(args['block-ms']));

function serve(sock: Socket) {
  sock.setNoDelay(true);
  let out: string[] = [];
  let queued = false;
  const send = (r: Response) => {
    out.push(JSON.stringify(r));
    if (!queued) {
      queued = true;
      setImmediate(() => {
        queued = false;
        sock.write(out.join('\n') + '\n');
        out = [];
      });
    }
  };
  sock.on(
    'data',
    lineReader((line) => {
      let req: Request;
      try {
        req = JSON.parse(line);
      } catch {
        return send({ id: -1, ok: false, reason: 'malformed request' });
      }
      if (req.op === 'status') return send({ id: req.id, ok: true, status: seq.status() });
      if (req.op !== 'act') return send({ id: (req as any).id ?? -1, ok: false, reason: 'unknown op' });
      let a;
      try {
        a = fromWire(req.a);
      } catch {
        return send({ id: req.id, ok: false, reason: 'malformed action' });
      }
      seq.submit(a).then((o) =>
        send(
          o.ok
            ? {
                id: req.id,
                ok: true,
                seq: o.seq.toString(),
                at: o.at.toString(),
                receipt: [o.receipt.s.toString(), o.receipt.e.toString()],
                fills: o.fills.map((f) => [f.price.toString(), f.lots.toString()]),
                ...(o.rested ? { rested: [o.rested.market, o.rested.side.toString(), o.rested.price.toString(), o.rested.seq.toString(), o.rested.lots.toString()] } : {}),
              }
            : { id: req.id, ok: false, reason: o.reason },
        ),
      );
    }),
  );
  sock.on('error', () => {});
}

const G = Number(args.gateways);
const gateways: Worker[] = [];
let server: ReturnType<typeof createServer> | undefined;
const ready = `listening on port ${args.port}: ${G ? `${G} gateway threads` : 'one thread'}, ${native.cryptoThreads()} crypto threads, journal ${args.journal ?? 'off'}${args.fsync ? ' (fsync)' : ''}`;
if (G === 0) {
  server = createServer(serve).listen(Number(args.port), () => log(ready));
} else {
  let up = 0;
  for (let i = 0; i < G; i++) {
    const cfg: GatewayConfig = { port: Number(args.port), domain: engine.domain, receiptSk: receiptKey.sk, gateway: i };
    const w = new Worker(new URL('./gateway.ts', import.meta.url), { workerData: cfg });
    const to = (m: ToGateway) => w.postMessage(m);
    w.on('message', (m: ToSequencer) => {
      if (m.k === 'batch') seq.sequenceChecked(m.items).then((items) => to({ k: 'done', items }));
      else if (m.k === 'status') to({ k: 'status', id: m.id, status: seq.status() });
      else if (m.k === 'listening' && ++up === G) log(ready);
    });
    w.on('error', (e: Error) => log(`gateway ${i} failed: ${e.stack ?? e}`));
    gateways.push(w);
  }
}
const stop = () => {
  log(`stopping: ${JSON.stringify(seq.status())}`);
  seq.close();
  server?.close();
  for (const w of gateways) void w.terminate();
  process.exit(0);
};
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
