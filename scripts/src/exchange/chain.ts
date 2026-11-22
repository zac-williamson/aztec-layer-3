// Reading the Bridge's public record from an Aztec node: event metadata from the compiled
// artifact, decoded public events, and the Mode R DA logs.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { loadContractArtifact } from '@aztec-labs/aztec.js/abi';
import { EventSelector, decodeFunctionSignature } from '@aztec-labs/stdlib/abi';
import { getPublicEvents } from '@aztec-labs/aztec.js/events';
import { Fr } from '@aztec-labs/aztec.js/fields';
import { Tag } from '@aztec-labs/stdlib/logs';
import { ROOT } from '../lib.ts';
import { MARKET_DATA_LEN } from './model.ts';

export const DA_LOG_TAG = 0x6c33782e64612e7631n;

export type ArtifactName = 'l3x_bridge-L3XBridge' | 'ctoken-ConfidentialToken' | 'ctbridge-ConfidentialTokenBridge';

export function rawArtifact(name: ArtifactName): any {
  return JSON.parse(readFileSync(join(ROOT, 'contracts', 'target', `${name}.json`), 'utf8'));
}

export const artifact = (name: ArtifactName) => loadContractArtifact(rawArtifact(name));

/** Event metadata, built from the artifact the same way `aztec codegen` builds it. */
export async function eventMeta(raw: any, name: string) {
  const ev = raw.outputs.structs.events.find((e: any) => e.path.split('::').at(-1) === name);
  if (!ev) throw new Error(`no event ${name}`);
  return {
    abiType: ev,
    eventSelector: await EventSelector.fromSignature(decodeFunctionSignature(name, ev.fields)),
    fieldNames: ev.fields.map((f: any) => f.name),
  };
}

/** Every public event of one kind the contract has emitted, oldest first. */
export async function allPublicEvents<T = any>(node: any, meta: any, contractAddress: any): Promise<T[]> {
  const out: T[] = [];
  let afterEvent: any;
  for (;;) {
    const page = await getPublicEvents<T>(node, meta, { contractAddress, ...(afterEvent ? { afterEvent } : {}) } as any);
    out.push(...page.events.map((e) => e.event));
    if (!page.nextCursor) return out;
    afterEvent = page.nextCursor;
  }
}

export const big = (x: any): bigint => (typeof x === 'bigint' ? x : BigInt(x?.toBigInt?.() ?? x?.toString?.() ?? x));

/**
 * Every DA log of the Bridge, as (batch, market data, payload), in batch order (SPEC.md §8.4,
 * §9.5): the log is [DA_LOG_TAG, batch, market data, payload].
 */
export async function daLogs(node: any, contractAddress: any): Promise<{ batch: bigint; marketData: bigint[]; payload: bigint[]; blockNumber: number }[]> {
  const out: { batch: bigint; marketData: bigint[]; payload: bigint[]; blockNumber: number }[] = [];
  let afterLog: any;
  for (;;) {
    const [logs] = await node.getPublicLogsByTags({
      contractAddress,
      tags: [{ tag: new Tag(new Fr(DA_LOG_TAG)), ...(afterLog ? { afterLog } : {}) }],
    });
    if (!logs?.length) break;
    for (const l of logs) {
      const f = l.logData.map(big);
      if (f[0] !== DA_LOG_TAG) continue;
      out.push({ batch: f[1], marketData: f.slice(2, 2 + MARKET_DATA_LEN), payload: f.slice(2 + MARKET_DATA_LEN), blockNumber: Number(l.blockNumber) });
    }
    const last = logs[logs.length - 1];
    if (!last.cursor && !last.logCursor) break;
    afterLog = last.cursor ?? last.logCursor;
  }
  out.sort((a, b) => (a.batch < b.batch ? -1 : 1));
  for (let i = 0; i < out.length; i++) {
    if (out[i].batch !== BigInt(i + 1)) throw new Error(`DA logs are missing batch ${i + 1}`);
  }
  return out;
}
