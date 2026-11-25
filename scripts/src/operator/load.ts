// Load generator for the operator (P2.24, SPEC.md §14). Worker threads, each with its own TCP
// connection and share of the demo accounts, send signed actions on a fixed schedule: market makers
// quote around the index and cancel their oldest quotes, takers send small crossing IOC orders.
// Each account has at most one action in flight, so its nonces never run ahead of a refusal.
// Latency is measured from each action's scheduled send time, so a slow operator is not hidden by
// a sender that slows down with it, and separately from the moment the signed action was written.
//
// Usage: node src/operator/load.ts [--port 7300] [--accounts 1000] [--rate 5000] [--seconds 20]
//                                   [--workers 8] [--burst-rate 0 --burst-seconds 5]
import { connect } from 'node:net';
import { parseArgs } from 'node:util';
import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads';
import { signAction } from '../exchange/engine.ts';
import { keysFromSeed } from '../exchange/grumpkin.ts';
import * as M from '../exchange/model.ts';
import { testParams } from '../exchange/params.ts';
import * as X from '../exchange/rules.ts';
import { Histogram, type Response, lineReader, toWire } from './wire.ts';

const DEMO_SEED = 0x6c33782e64656d6fn; // server.ts DEMO_SEED
const MIDS = [2000n, 30_000n];

type Job = { port: number; host: string; first: number; count: number; phases: { rate: number; seconds: number }[]; worker: number };
type Report = { worker: number; sent: number; accepted: number; refused: Record<string, number>; skipped: number; sched: number[][]; wire: number[][]; perSecond: { t: number; accepted: number }[] };

if (isMainThread) {
  const { values: a } = parseArgs({
    options: {
      host: { type: 'string', default: '127.0.0.1' },
      port: { type: 'string', default: '7300' },
      accounts: { type: 'string', default: '1000' },
      rate: { type: 'string', default: '5000' },
      seconds: { type: 'string', default: '20' },
      workers: { type: 'string', default: '8' },
      'burst-rate': { type: 'string', default: '0' },
      'burst-seconds': { type: 'string', default: '5' },
    },
  });
  const W = Number(a.workers);
  const N = Number(a.accounts);
  const phases = [{ rate: Number(a.rate), seconds: Number(a.seconds) }];
  if (Number(a['burst-rate']) > 0) phases.push({ rate: Number(a['burst-rate']), seconds: Number(a['burst-seconds']) });
  console.log(`[load] ${W} workers, ${N} accounts, phases ${phases.map((p) => `${p.rate}/s for ${p.seconds} s`).join(', then ')}`);
  const reports: Report[] = await Promise.all(
    [...Array(W).keys()].map(
      (w) =>
        new Promise<Report>((ok, fail) => {
          const per = Math.floor(N / W);
          const job: Job = { host: a.host!, port: Number(a.port), first: w * per, count: per, worker: w, phases: phases.map((p) => ({ rate: p.rate / W, seconds: p.seconds })) };
          const worker = new Worker(new URL(import.meta.url), { workerData: job });
          worker.on('message', ok);
          worker.on('error', fail);
        }),
    ),
  );
  const sched = phases.map(() => new Histogram());
  const wire = phases.map(() => new Histogram());
  const refused: Record<string, number> = {};
  let [sent, accepted, skipped] = [0, 0, 0];
  const perSecond = new Map<number, number>();
  for (const r of reports) {
    r.sched.forEach((xs, i) => xs.forEach((x) => sched[i].add(x)));
    r.wire.forEach((xs, i) => xs.forEach((x) => wire[i].add(x)));
    sent += r.sent;
    accepted += r.accepted;
    skipped += r.skipped;
    for (const [k, v] of Object.entries(r.refused)) refused[k] = (refused[k] ?? 0) + v;
    for (const s of r.perSecond) perSecond.set(s.t, (perSecond.get(s.t) ?? 0) + s.accepted);
  }
  const fmt = (h: Histogram) => {
    const p = h.percentiles();
    return `p50 ${(p.p50 / 1000).toFixed(2)} ms, p90 ${(p.p90 / 1000).toFixed(2)} ms, p99 ${(p.p99 / 1000).toFixed(2)} ms, p99.9 ${(p['p99.9'] / 1000).toFixed(2)} ms, max ${(h.max() / 1000).toFixed(1)} ms`;
  };
  const secs = [...perSecond.entries()].sort(([x], [y]) => x - y).map(([, v]) => v);
  console.log(`[load] sent ${sent}, accepted ${accepted}, refused ${Object.values(refused).reduce((x, y) => x + y, 0)}, not sent (every account busy) ${skipped}`);
  console.log(`[load] accepted per second: ${secs.join(' ')}`);
  phases.forEach((p, i) => {
    console.log(`[load] ${p.rate}/s phase: latency from schedule ${fmt(sched[i])}`);
    console.log(`[load] ${p.rate}/s phase: latency on the wire   ${fmt(wire[i])}`);
  });
  if (Object.keys(refused).length) console.log(`[load] refusals: ${Object.entries(refused).map(([k, v]) => `${k} ×${v}`).join('; ')}`);
  // The operator's own view.
  const status = await new Promise<any>((ok) => {
    const s = connect(Number(a.port), a.host!, () => s.write(JSON.stringify({ id: 1, op: 'status' }) + '\n'));
    s.on('data', lineReader((l) => (ok(JSON.parse(l).status), s.end())));
  });
  console.log(`[load] operator: ${JSON.stringify(status)}`);
  process.exit(0);
} else {
  const job = workerData as Job;
  const h = M.hasher(null as any);
  const { params } = await testParams(h);
  const domain = await M.domainOf(h, params);
  type User = { index: bigint; keys: Awaited<ReturnType<typeof keysFromSeed>>; nonce: bigint; busy: boolean; maker: boolean; quotes: { m: number; side: bigint; price: bigint; seq: bigint }[]; flip: number };
  const users: User[] = [];
  for (let i = job.first; i < job.first + job.count; i++) {
    users.push({ index: BigInt(2 + i), keys: await keysFromSeed(h, DEMO_SEED + BigInt(i)), nonce: 0n, busy: false, maker: i % 4 !== 3, quotes: [], flip: i });
  }
  const sock = connect(job.port, job.host);
  await new Promise((ok) => sock.on('connect', ok));
  sock.setNoDelay(true);
  const pending = new Map<number, { u: User; sched: number; sent: number; kind: bigint; phase: number }>();
  const report: Report = { worker: job.worker, sent: 0, accepted: 0, refused: {}, skipped: 0, sched: job.phases.map(() => []), wire: job.phases.map(() => []), perSecond: [] };
  const t0 = performance.now();
  const second = new Map<number, number>();
  sock.on(
    'data',
    lineReader((line) => {
      const r: Response = JSON.parse(line);
      const p = pending.get(r.id);
      if (!p) return;
      pending.delete(r.id);
      const now = performance.now();
      p.u.busy = false;
      report.sched[p.phase].push((now - p.sched) * 1000);
      report.wire[p.phase].push((now - p.sent) * 1000);
      if (r.ok && 'seq' in r) {
        report.accepted++;
        const s = Math.floor((now - t0) / 1000);
        second.set(s, (second.get(s) ?? 0) + 1);
        if (r.rested) p.u.quotes.push({ m: r.rested[0], side: BigInt(r.rested[1]), price: BigInt(r.rested[2]), seq: BigInt(r.rested[3]) });
      } else if (!r.ok) {
        report.refused[r.reason] = (report.refused[r.reason] ?? 0) + 1;
        // The action did not use its nonce.
        p.u.nonce -= 1n;
      }
    }),
  );
  let id = 0;
  let next = 0;
  let phase = 0;
  async function sendOne(sched: number) {
    // The next idle account, round robin.
    let u: User | undefined;
    for (let k = 0; k < users.length; k++) {
      const c = users[(next + k) % users.length];
      if (!c.busy) {
        u = c;
        next = (next + k + 1) % users.length;
        break;
      }
    }
    if (!u) {
      report.skipped++;
      return;
    }
    u.busy = true;
    u.nonce += 1n;
    const m = u.flip % 2;
    let kind: bigint = X.KIND_ACT.PLACE;
    let p: bigint[];
    if (u.maker && u.quotes.length >= 4) {
      const q = u.quotes.shift()!;
      kind = X.KIND_ACT.CANCEL;
      p = [BigInt(q.m), q.side, q.price, q.seq];
    } else if (u.maker) {
      const side = u.flip++ % 4 < 2 ? M.SIDE.BID : M.SIDE.ASK;
      const off = BigInt(1 + (u.flip % 5)) * (m === 0 ? 1n : 10n);
      p = [BigInt(m), side, side === M.SIDE.BID ? MIDS[m] - off : MIDS[m] + off, 5n, X.TIF.GTC, 0n, 0n, 0n];
    } else {
      const side = u.flip++ % 2 ? M.SIDE.BID : M.SIDE.ASK;
      p = [BigInt(m), side, side === M.SIDE.BID ? (MIDS[m] * 101n) / 100n : (MIDS[m] * 99n) / 100n, 1n, X.TIF.IOC, 0n, 0n, 0n];
    }
    const a = await signAction(h, domain, u.keys, kind, u.index, u.nonce, p);
    const rid = ++id;
    pending.set(rid, { u, sched, sent: performance.now(), kind, phase });
    report.sent++;
    sock.write(JSON.stringify({ id: rid, op: 'act', a: toWire(a) }) + '\n');
  }
  // The schedule: actions due at a steady rate per phase, checked every millisecond.
  let phaseStart = performance.now();
  let sentInPhase = 0;
  for (const [i, ph] of job.phases.entries()) {
    phase = i;
    phaseStart = performance.now();
    sentInPhase = 0;
    const end = phaseStart + ph.seconds * 1000;
    while (performance.now() < end) {
      const now = performance.now();
      const due = Math.floor(((now - phaseStart) / 1000) * ph.rate);
      while (sentInPhase < due) {
        // Action k is due once k + 1 actions' worth of time has passed (`due` above).
        const sched = phaseStart + ((sentInPhase + 1) / ph.rate) * 1000;
        sentInPhase++;
        await sendOne(sched);
      }
      // Sleep until the next action is due. Timers fire up to a millisecond late, which the latency
      // from schedule includes; the generator does not spin, so it leaves the operator its CPUs.
      const wait = phaseStart + ((sentInPhase + 1) / ph.rate) * 1000 - performance.now();
      await new Promise((ok) => setTimeout(ok, Math.max(0, wait)));
    }
  }
  // Drain.
  const drainEnd = performance.now() + 10_000;
  while (pending.size && performance.now() < drainEnd) await new Promise((ok) => setTimeout(ok, 5));
  report.perSecond = [...second.entries()].map(([t, accepted]) => ({ t, accepted }));
  parentPort!.postMessage(report);
  sock.end();
}
