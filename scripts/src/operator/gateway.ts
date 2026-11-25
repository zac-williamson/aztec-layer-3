// A gateway thread (P2.24, SPEC.md §5): it owns its share of the client connections (gateways
// share the port, and the kernel spreads connections across them), parses requests, runs the
// gateway's checks of each signed action on the crypto pool, hands checked actions to the
// sequencer thread in arrival order, then signs the receipts of the ones it applied and answers.
// The sequencer thread only sequences and journals.
import { createServer, type Socket } from 'node:net';
import { parentPort, workerData } from 'node:worker_threads';
import { randomField } from '../lib.ts';
import * as M from '../exchange/model.ts';
import { native } from '../native.ts';
import { type Request, type Response, type WireAction, lineReader } from './wire.ts';

/** What a gateway passes the sequencer for one checked action. */
export type Checked = {
  rid: number;
  kind: bigint;
  account: bigint;
  keyId: bigint;
  nonce: bigint;
  p: bigint[];
  pk: [bigint, bigint];
  msg: bigint;
  masterAuth: bigint;
  ok: boolean;
  /** The action as it arrived, for the journal. */
  raw: string;
};
/** The sequencer's answer: applied, with its number, time and execution, or refused. */
export type Sequenced =
  | { rid: number; ok: true; seq: bigint; at: bigint; fills: [string, string][]; rested?: [number, string, string, string, string] }
  | { rid: number; ok: false; reason: string };
export type GatewayConfig = { port: number; domain: bigint; receiptSk: bigint; gateway: number };
/** Messages between a gateway and the sequencer thread. */
export type ToSequencer = { k: 'listening' } | { k: 'batch'; items: Checked[] } | { k: 'status'; id: number };
export type ToGateway = { k: 'done'; items: Sequenced[] } | { k: 'status'; id: number; status: Record<string, unknown> };

type Arrival = { c: Checked; s: bigint; e: bigint; sock: Socket; id: number };

if (parentPort && workerData?.gateway !== undefined) {
  const cfg = workerData as GatewayConfig;
  const port = parentPort;
  const post = (m: ToSequencer) => port.postMessage(m);
  /** Requests the sequencer has not answered yet, by request id. */
  const waiting = new Map<number, { sock: Socket; id: number; msg: bigint }>();
  const statusWaiters = new Map<number, Socket>();
  let rid = 0;
  let arrivals: Arrival[] = [];
  let flushQueued = false;
  /** Checked batches go to the sequencer in arrival order, even when their checks finish out of order. */
  let tail: Promise<void> = Promise.resolve();

  const outboxes = new Map<Socket, string[]>();
  const send = (sock: Socket, r: Response) => {
    let out = outboxes.get(sock);
    if (!out) {
      outboxes.set(sock, (out = []));
      setImmediate(() => {
        outboxes.delete(sock);
        if (!sock.destroyed) sock.write(out!.join('\n') + '\n');
      });
    }
    out.push(JSON.stringify(r));
  };

  const flush = () => {
    flushQueued = false;
    const batch = arrivals;
    arrivals = [];
    const flat: bigint[] = [];
    for (const { c, s, e } of batch) flat.push(c.kind, c.account, c.keyId, c.nonce, ...c.p, c.pk[0], c.pk[1], s, e);
    const checked = native.prepareActions(M.DS.ACTION, M.DS.MAUTH, cfg.domain, flat);
    tail = tail.then(async () => {
      const out = await checked;
      const items = batch.map(({ c, sock, id }, i) => {
        c.msg = out[3 * i];
        c.masterAuth = out[3 * i + 1];
        c.ok = out[3 * i + 2] === 1n;
        waiting.set(c.rid, { sock, id, msg: c.msg });
        return c;
      });
      post({ k: 'batch', items });
    });
  };

  const done = async (items: Sequenced[]) => {
    // Refusals are answered now; receipts for the applied actions are signed on the crypto pool.
    const applied: { r: Extract<Sequenced, { ok: true }>; w: { sock: Socket; id: number; msg: bigint } }[] = [];
    const flat: bigint[] = [];
    for (const r of items) {
      const w = waiting.get(r.rid)!;
      waiting.delete(r.rid);
      if (!r.ok) {
        send(w.sock, { id: w.id, ok: false, reason: r.reason });
        continue;
      }
      applied.push({ r, w });
      flat.push(w.msg, r.seq, r.at);
    }
    if (!applied.length) return;
    const sigs = await native.signReceipts(M.DS.RECEIPT_SIG, cfg.domain, cfg.receiptSk, randomField(), flat);
    applied.forEach(({ r, w }, i) =>
      send(w.sock, { id: w.id, ok: true, seq: r.seq.toString(), at: r.at.toString(), receipt: [sigs[2 * i].toString(), sigs[2 * i + 1].toString()], fills: r.fills, ...(r.rested ? { rested: r.rested } : {}) }),
    );
  };

  port.on('message', (m: ToGateway) => {
    if (m.k === 'done') void done(m.items);
    else if (m.k === 'status') {
      const sock = statusWaiters.get(m.id);
      statusWaiters.delete(m.id);
      if (sock) send(sock, { id: m.id, ok: true, status: m.status });
    }
  });

  const serve = (sock: Socket) => {
    sock.setNoDelay(true);
    sock.on('error', () => {});
    sock.on(
      'data',
      lineReader((line) => {
        let req: Request;
        try {
          req = JSON.parse(line);
        } catch {
          return send(sock, { id: -1, ok: false, reason: 'malformed request' });
        }
        if (req.op === 'status') {
          statusWaiters.set(req.id, sock);
          return post({ k: 'status', id: req.id });
        }
        if (req.op !== 'act') return send(sock, { id: (req as any).id ?? -1, ok: false, reason: 'unknown op' });
        let arrival: Arrival;
        try {
          const a: WireAction = req.a;
          const p = a.p.map(BigInt);
          if (p.length !== 8) throw new Error('payload');
          const c: Checked = { rid: ++rid, kind: BigInt(a.kind), account: BigInt(a.account), keyId: BigInt(a.keyId), nonce: BigInt(a.nonce), p, pk: [BigInt(a.pk[0]), BigInt(a.pk[1])], msg: 0n, masterAuth: 0n, ok: false, raw: JSON.stringify(a) };
          arrival = { c, s: BigInt(a.sig[0]), e: BigInt(a.sig[1]), sock, id: req.id };
        } catch {
          return send(sock, { id: req.id, ok: false, reason: 'malformed action' });
        }
        arrivals.push(arrival);
        if (!flushQueued) {
          flushQueued = true;
          setImmediate(flush);
        }
      }),
    );
  };
  createServer(serve).listen({ port: cfg.port, reusePort: true }, () => post({ k: 'listening' }));
}
