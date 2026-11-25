// Witness execution on worker threads (P2.28, SPEC.md §14). noir_js executes ACIR in WASM on the
// calling thread: on the proving service's main thread every circuit of a batch ran one after
// another (54 s for a 23-segment Chonk run). This pool runs them on `n` workers at once; each
// worker keeps a Noir instance per circuit.
import { cpus } from 'node:os';
import { isMainThread, parentPort, Worker } from 'node:worker_threads';
import { Noir } from '@aztec-foundation/noir-noir_js';
import { readCircuit } from './lib.ts';

type Job = { id: number; pkg: string; inputs: Record<string, unknown> };
type Done = { id: number; witness?: Uint8Array; returnValue?: unknown; error?: string };

if (!isMainThread && parentPort) {
  const noirs = new Map<string, Noir>();
  const port = parentPort;
  port.on('message', async (j: Job) => {
    try {
      let n = noirs.get(j.pkg);
      if (!n) noirs.set(j.pkg, (n = new Noir(readCircuit(j.pkg) as any)));
      const { witness, returnValue } = await n.execute(j.inputs as any);
      port.postMessage({ id: j.id, witness, returnValue } satisfies Done, [witness.buffer as ArrayBuffer]);
    } catch (e: any) {
      port.postMessage({ id: j.id, error: String(e?.stack ?? e) } satisfies Done);
    }
  });
}

export class ExecPool {
  private workers: Worker[] = [];
  private idle: Worker[] = [];
  private queue: { job: Job; ok: (d: Done) => void }[] = [];
  private pending = new Map<number, (d: Done) => void>();
  private nextId = 0;

  constructor(n = Math.min(16, cpus().length)) {
    for (let i = 0; i < n; i++) {
      const w = new Worker(new URL(import.meta.url));
      w.on('message', (d: Done) => {
        const ok = this.pending.get(d.id)!;
        this.pending.delete(d.id);
        // An idle worker must not keep the process alive; a busy one must, or a process whose
        // only pending work is a witness would exit (with status 0) while awaiting it.
        w.unref();
        this.idle.push(w);
        this.pump();
        ok(d);
      });
      w.unref();
      this.workers.push(w);
      this.idle.push(w);
    }
  }

  private pump() {
    while (this.idle.length && this.queue.length) {
      const w = this.idle.pop()!;
      const { job, ok } = this.queue.shift()!;
      this.pending.set(job.id, ok);
      w.ref();
      w.postMessage(job);
    }
  }

  /** noir_js's execute, on a worker. */
  async execute(pkg: string, inputs: Record<string, unknown>): Promise<{ witness: Uint8Array; returnValue: any }> {
    const d = await new Promise<Done>((ok) => {
      this.queue.push({ job: { id: this.nextId++, pkg, inputs }, ok });
      this.pump();
    });
    if (d.error) throw new Error(`${pkg}: ${d.error}`);
    return { witness: d.witness!, returnValue: d.returnValue };
  }

  async destroy() {
    await Promise.all(this.workers.map((w) => w.terminate()));
  }
}

let shared: ExecPool | undefined;
/** One pool per process, made on first use. */
export const execPool = () => (shared ??= new ExecPool());
