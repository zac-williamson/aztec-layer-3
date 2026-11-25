// The sequencer (P2.24, SPEC.md §5, §11): signed actions in, receipts and execution reports out.
//
//   arrivals ──▶ gateway batch ──▶ sequencing, in arrival order ──▶ journal ──▶ receipt batch ──▶ replies
//                (crypto pool:       (one thread: the engine in       (one write   (crypto pool:
//                 message, signer,    sequencer mode, each action      a batch)     Schnorr over
//                 signature)          atomic)                                       Grumpkin)
//
// Arrivals of one event-loop turn form a gateway batch. Batches are checked in parallel and
// sequenced strictly in arrival order, so an earlier arrival always gets the lower sequence number.
// Blocks and other operator steps go through the same sequencing queue. The journal records every
// sequenced step in order: replayed into an engine that builds witnesses, it yields the batches to
// prove (SPEC.md §5, "Its journal is the witness source").
import { closeSync, fdatasync, openSync, writeSync } from 'node:fs';
import { monitorEventLoopDelay } from 'node:perf_hooks';
import { randomField } from '../lib.ts';
import type { Engine, Execution, OracleUpdate, SignedAction } from '../exchange/engine.ts';
import * as M from '../exchange/model.ts';
import { native } from '../native.ts';
import type { Checked, Sequenced } from './gateway.ts';
import { Histogram, toWire } from './wire.ts';

export type Outcome =
  | ({ ok: true; seq: bigint; at: bigint; receipt: { s: bigint; e: bigint } } & Execution)
  | { ok: false; reason: string };

export type SequencerOptions = {
  /** The receipt key; its public key is the one the Bridge's configuration names (§11). */
  receiptSk: bigint;
  /** Append-only journal of every sequenced step, one JSON line each. */
  journal?: string;
  /** 'fsync': a batch's receipts are released only once its journal lines are on disk. */
  durability?: 'write' | 'fsync';
  /** Most actions in one gateway batch. */
  maxBatch?: number;
};

type Pending = { a: SignedAction; done: (o: Outcome) => void; t0: number; t1?: number; t2?: number };

const ser = (x: unknown) => JSON.stringify(x, (_k, v) => (typeof v === 'bigint' ? v.toString() : v));
/** Accounts checked for liquidation at each block. */
const LIQ_SCAN = 1000;
/** Checked actions carry the gateway's verdict, so their signature is never read again. */
const NO_SIG = { s: 0n, e: 0n };

export class Sequencer {
  readonly engine: Engine;
  private readonly opts: Required<Omit<SequencerOptions, 'journal'>> & Pick<SequencerOptions, 'journal'>;
  private arrivals: Pending[] = [];
  private flushQueued = false;
  /** The sequencing queue: every step runs after the one before it. */
  private tail: Promise<void> = Promise.resolve();
  private fd?: number;
  private lines: string[] = [];
  /** Checked batches from gateways, waiting to be sequenced. */
  private inbox: { items: Checked[]; reply: (r: Sequenced[]) => void }[] = [];
  private draining = false;
  private scanCursor = 0n;
  /** Counters and latency (µs, from arrival to reply) for status reports. */
  readonly stats = {
    accepted: 0,
    refused: 0,
    batches: 0,
    blocks: 0,
    sequencingUs: 0,
    /** Arrival to reply, and its stages: the gateway's checks, waiting to be sequenced, the receipt. */
    latency: new Histogram(),
    checks: new Histogram(),
    queued: new Histogram(),
    receipt: new Histogram(),
    batchSize: new Histogram(),
  };
  /** How late the sequencer's thread runs its callbacks: how busy, or how starved of CPU, it is. */
  private readonly loopDelay = monitorEventLoopDelay({ resolution: 1 });

  constructor(engine: Engine, opts: SequencerOptions) {
    if (!engine.lite) throw new Error('the sequencer runs its engine in sequencer mode');
    this.engine = engine;
    this.opts = { durability: 'write', maxBatch: 256, ...opts };
    if (opts.journal) this.fd = openSync(opts.journal, 'a');
    this.loopDelay.enable();
  }

  /** Queues a signed action; resolves with its receipt and execution report, or its refusal. */
  submit(a: SignedAction): Promise<Outcome> {
    return new Promise((done) => {
      this.arrivals.push({ a, done, t0: performance.now() });
      if (!this.flushQueued) {
        this.flushQueued = true;
        setImmediate(() => this.flush());
      }
    });
  }

  /** Runs an operator step (a block, priority requests, maintenance...) in sequence. */
  step<T>(label: string, f: (e: Engine) => Promise<T>, record?: object): Promise<T> {
    const run = this.tail.then(() => f(this.engine));
    // A step that throws changed nothing (the engine's steps are atomic) and is not journaled.
    this.tail = run.then(
      () => void (record && this.journalLine({ t: label, ...record })),
      () => {},
    );
    return run;
  }

  /**
   * Sequences actions a gateway thread has checked (gateway.ts), in order, through the sequencing
   * queue, and journals the applied ones. Resolves with each one's outcome once its journal lines
   * are written (on disk, with 'fsync'); the next batch sequences meanwhile.
   */
  sequenceChecked(items: Checked[]): Promise<Sequenced[]> {
    return new Promise((reply) => {
      this.inbox.push({ items, reply });
      if (this.draining) return;
      this.draining = true;
      // Every batch waiting when the sequencing queue reaches this step is sequenced in one run,
      // in arrival order, with one journal write: under load, the per-batch costs are shared.
      this.tail = this.tail.then(async () => {
        while (this.inbox.length) {
          const jobs = this.inbox;
          this.inbox = [];
          const { out, durable } = await this.runChecked(jobs.length === 1 ? jobs[0].items : jobs.flatMap((j) => j.items));
          let i = 0;
          const parts = jobs.map((j) => out.slice(i, (i += j.items.length)));
          void durable.then(() => jobs.forEach((j, k) => j.reply(parts[k])));
        }
        this.draining = false;
      });
    });
  }

  private async runChecked(items: Checked[]) {
    this.stats.batches++;
    this.stats.batchSize.add(items.length);
    const t0 = performance.now();
    const at = BigInt(Math.floor(Date.now() / 1000));
    const out: Sequenced[] = [];
    for (const c of items) {
      if (!c.ok) {
        this.stats.refused++;
        out.push({ rid: c.rid, ok: false, reason: 'bad signature' });
        continue;
      }
      const a: SignedAction = { kind: c.kind, account: c.account, keyId: c.keyId, nonce: c.nonce, p: c.p, pk: { x: c.pk[0], y: c.pk[1] }, sig: NO_SIG, prepared: { msg: c.msg, masterAuth: c.masterAuth, ok: true } };
      try {
        const x = await this.engine.sequence(a);
        this.stats.accepted++;
        if (this.fd !== undefined) this.lines.push(`{"t":"act","seq":"${a.seq}","at":"${at}","a":${c.raw}}`);
        const r = x.rested;
        out.push({ rid: c.rid, ok: true, seq: a.seq!, at, fills: x.fills.map((f) => [f.price.toString(), f.lots.toString()]), ...(r ? { rested: [r.market, r.side.toString(), r.price.toString(), r.seq.toString(), r.lots.toString()] } : {}) });
      } catch (e: any) {
        this.stats.refused++;
        out.push({ rid: c.rid, ok: false, reason: String(e.message ?? e) });
      }
    }
    this.stats.sequencingUs += (performance.now() - t0) * 1000;
    return { out, durable: this.writeJournal() };
  }

  /**
   * A block at `time` with the given index updates (§8.4), then the operator's duties at the new
   * marks: it fires every due trigger and liquidates the due accounts it finds in its next slice of
   * accounts (`LIQ_SCAN` a block, round robin). The whole step is atomic and journaled as one entry.
   */
  block(time: bigint, updates: OracleUpdate[] = []) {
    this.stats.blocks++;
    const fired: number[] = [];
    const liquidated: bigint[] = [];
    return this.step(
      'block',
      (e) =>
        e.atomic(async () => {
          await e.block(time, updates);
          for (let m = 0; m < M.MARKETS; m++) {
            if (!e.markets[m].triggerPending) continue;
            await e.fireTriggers([m]);
            fired.push(m);
          }
          for (const i of this.dueSlice(e)) {
            await e.liquidateAccount(i);
            liquidated.push(i);
          }
        }),
      { time, updates, fired, liquidated },
    );
  }

  /** The next slice of accounts to check for liquidation; those due. */
  private dueSlice(e: Engine): bigint[] {
    const n = e.numAccounts;
    const due: bigint[] = [];
    for (let k = 0; k < LIQ_SCAN && BigInt(k) < n; k++) {
      this.scanCursor = this.scanCursor + 1n >= n ? 0n : this.scanCursor + 1n;
      if (e.dueForLiquidation(this.scanCursor)) due.push(this.scanCursor);
    }
    return due;
  }

  /** Opens batch `n` where the last one ended: a batch boundary in the journal (§9.1). */
  newBatch(n: bigint) {
    return this.step(
      'batch',
      async (e) => {
        const r = e.running;
        await e.beginBatch(n, r?.priorityHead ?? 0n, r?.priorityCursor ?? 0n, r?.time ?? 0n);
      },
      { n, ms: Date.now() },
    );
  }

  /** An encryption key the Bridge delivered with a registration or rekey (§10.1). */
  deliverKey(commitment: bigint, kEnc: bigint) {
    return this.step(
      'key',
      async (e) => {
        e.keyring.set(commitment, kEnc);
      },
      { c: commitment, k: kEnc },
    );
  }

  /** Priority requests from the Bridge's queue, in queue order (§10.1). */
  priority(reqs: M.Request[]) {
    return this.step('priority', (e) => e.priority(reqs), { reqs });
  }

  private flush() {
    this.flushQueued = false;
    while (this.arrivals.length) {
      const batch = this.arrivals.splice(0, this.opts.maxBatch);
      const flat: bigint[] = [];
      for (const { a } of batch) flat.push(a.kind, a.account, a.keyId, a.nonce, ...a.p, a.pk.x, a.pk.y, a.sig.s, a.sig.e);
      // The gateway's checks run now, in parallel with earlier batches' sequencing.
      const checked = native.prepareActions(M.DS.ACTION, M.DS.MAUTH, this.engine.domain, flat).then((out) => {
        const t = performance.now();
        for (const p of batch) p.t1 = t;
        return out;
      });
      this.tail = this.tail.then(async () => {
        const out = await checked;
        batch.forEach(({ a }, i) => (a.prepared = { msg: out[3 * i], masterAuth: out[3 * i + 1], ok: out[3 * i + 2] === 1n }));
        await this.sequenceBatch(batch);
      });
    }
  }

  private async sequenceBatch(batch: Pending[]) {
    this.stats.batches++;
    this.stats.batchSize.add(batch.length);
    const t0 = performance.now();
    for (const p of batch) {
      this.stats.checks.add((p.t1! - p.t0) * 1000);
      this.stats.queued.add((t0 - p.t1!) * 1000);
    }
    const at = BigInt(Math.floor(Date.now() / 1000));
    const signed: { p: Pending; x: Execution }[] = [];
    for (const p of batch) {
      if (!p.a.prepared!.ok) {
        this.refuse(p, 'bad signature');
        continue;
      }
      try {
        const x = await this.engine.sequence(p.a);
        signed.push({ p, x });
        // The wire encoding is all strings: no replacer to call for every value.
        if (this.fd !== undefined) this.lines.push(JSON.stringify({ t: 'act', seq: p.a.seq!.toString(), at: at.toString(), a: toWire(p.a) }));
      } catch (e: any) {
        this.refuse(p, String(e.message ?? e));
      }
    }
    const t1 = performance.now();
    this.stats.sequencingUs += (t1 - t0) * 1000;
    if (!signed.length) return;
    const durable = this.writeJournal();
    const flat: bigint[] = [];
    for (const { p } of signed) flat.push(p.a.prepared!.msg, p.a.seq!, at);
    // Receipts are signed off the sequencing thread; the next batch sequences meanwhile.
    void Promise.all([native.signReceipts(M.DS.RECEIPT_SIG, this.engine.domain, this.opts.receiptSk, randomField(), flat), durable]).then(
      ([sigs]) => {
        const now = performance.now();
        this.stats.receipt.add((now - t1) * 1000);
        signed.forEach(({ p, x }, i) => {
          this.stats.accepted++;
          this.stats.latency.add((now - p.t0) * 1000);
          p.done({ ok: true, seq: p.a.seq!, at, receipt: { s: sigs[2 * i], e: sigs[2 * i + 1] }, ...x });
        });
      },
      (err) => {
        // The actions are sequenced and journaled; only their receipts failed. Never expected.
        console.error(`[sequencer] receipts for sequence numbers ${signed[0].p.a.seq}-${signed.at(-1)!.p.a.seq} failed: ${err}`);
        signed.forEach(({ p }) => p.done({ ok: false, reason: `sequenced as ${p.a.seq}, but its receipt failed` }));
      },
    );
  }

  private refuse(p: Pending, reason: string) {
    this.stats.refused++;
    this.stats.latency.add((performance.now() - p.t0) * 1000);
    p.done({ ok: false, reason });
  }

  private journalLine(x: unknown) {
    if (this.fd !== undefined) this.lines.push(ser(x));
  }

  /** Writes the buffered journal lines; with 'fsync', resolves once they are on disk. */
  private writeJournal(): Promise<void> {
    if (this.fd === undefined || !this.lines.length) return Promise.resolve();
    writeSync(this.fd, this.lines.join('\n') + '\n');
    this.lines = [];
    if (this.opts.durability !== 'fsync') return Promise.resolve();
    const fd = this.fd;
    return new Promise((ok, fail) => fdatasync(fd, (err) => (err ? fail(err) : ok())));
  }

  close() {
    this.writeJournal();
    if (this.fd !== undefined) closeSync(this.fd);
  }

  status() {
    const l = this.stats.latency;
    const ms = (h: Histogram) => Object.fromEntries(Object.entries(h.percentiles([50, 99])).map(([k, v]) => [k, +(v / 1000).toFixed(2)]));
    return {
      accepted: this.stats.accepted,
      refused: this.stats.refused,
      batches: this.stats.batches,
      blocks: this.stats.blocks,
      lastSeq: this.engine.lastSeq.toString(),
      sequencingUsPerAction: Math.round(this.stats.sequencingUs / Math.max(1, this.stats.accepted + this.stats.refused)),
      latencyUs: { ...l.percentiles(), max: Math.round(l.max()), n: l.count },
      stagesMs: { checks: ms(this.stats.checks), queued: ms(this.stats.queued), receipt: ms(this.stats.receipt) },
      batchSize: this.stats.batchSize.percentiles([50, 99]),
      loopDelayMs: { p50: +(this.loopDelay.percentile(50) / 1e6).toFixed(2), p99: +(this.loopDelay.percentile(99) / 1e6).toFixed(2), max: +(this.loopDelay.max / 1e6).toFixed(1) },
    };
  }
}
