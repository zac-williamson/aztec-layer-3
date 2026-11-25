// The operator's wire format (P2.24, SPEC.md §11): newline-delimited JSON over TCP, one request or
// response a line. Integers and field elements travel as decimal strings.
import type { SignedAction } from '../exchange/engine.ts';

export type WireAction = { kind: string; account: string; keyId: string; nonce: string; p: string[]; pk: [string, string]; sig: [string, string] };

export type Request =
  /** A signed action (§7.1), answered with its receipt and execution report, or a refusal. */
  | { id: number; op: 'act'; a: WireAction }
  /** The operator's counters and latency percentiles. */
  | { id: number; op: 'status' };

export type Fill = [price: string, lots: string];
export type Response =
  | {
      id: number;
      ok: true;
      seq: string;
      /** The receipt (§11): the operator's signature (s, e) over H(DS_RECEIPT_SIG, domain, msg, seq, at). */
      at: string;
      receipt: [string, string];
      fills: Fill[];
      /** Where the remainder rests: market, side, price, seq, lots. */
      rested?: [number, string, string, string, string];
    }
  | { id: number; ok: false; reason: string }
  | { id: number; ok: true; status: Record<string, unknown> };

export const toWire = (a: SignedAction): WireAction => ({
  kind: a.kind.toString(),
  account: a.account.toString(),
  keyId: a.keyId.toString(),
  nonce: a.nonce.toString(),
  p: a.p.map((x) => x.toString()),
  pk: [a.pk.x.toString(), a.pk.y.toString()],
  sig: [a.sig.s.toString(), a.sig.e.toString()],
});

export const fromWire = (w: WireAction): SignedAction => ({
  kind: BigInt(w.kind),
  account: BigInt(w.account),
  keyId: BigInt(w.keyId),
  nonce: BigInt(w.nonce),
  p: w.p.map(BigInt),
  pk: { x: BigInt(w.pk[0]), y: BigInt(w.pk[1]) },
  sig: { s: BigInt(w.sig[0]), e: BigInt(w.sig[1]) },
});

/** Splits a byte stream into lines and hands each to `line`. */
export function lineReader(line: (s: string) => void) {
  let buf = '';
  return (chunk: Buffer | string) => {
    buf += chunk.toString();
    let i: number;
    while ((i = buf.indexOf('\n')) >= 0) {
      const s = buf.slice(0, i);
      buf = buf.slice(i + 1);
      if (s) line(s);
    }
  };
}

/** Latency samples in µs, with percentiles. */
export class Histogram {
  private xs: number[] = [];
  add(us: number) {
    this.xs.push(us);
  }
  get count() {
    return this.xs.length;
  }
  percentiles(ps = [50, 90, 99, 99.9]) {
    const s = Float64Array.from(this.xs).sort();
    return Object.fromEntries(ps.map((p) => [`p${p}`, s.length ? Math.round(s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))]) : 0]));
  }
  max() {
    return this.xs.reduce((a, b) => (b > a ? b : a), 0);
  }
  reset() {
    this.xs = [];
  }
}
