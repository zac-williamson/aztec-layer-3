// Operator check (P2.24, SPEC.md §5, §11): the operator end to end on one machine. It starts the
// operator (gateway threads, sequencer, journal) with demo accounts, drives it with the load
// generator, stops it, then replays its journal into an engine that builds witnesses and executes
// a trading batch's segments in their circuits. It requires that every action was answered, that
// refusals were only the expected race (a cancel of an order a taker had just filled), and that the
// replay applied every action the operator applied, under the same sequence numbers.
// Usage: node src/operator/check.ts
import { spawn } from 'node:child_process';
import { mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { OUT } from '../lib.ts';
import { assert } from '../pipeline.ts';
import { replay } from './replay.ts';

const log = (m: string) => console.log(`[operator-check] ${m}`);
const PORT = 7400 + Math.floor(Math.random() * 500);
const ACCOUNTS = 120;
mkdirSync(OUT, { recursive: true });
const journal = join(OUT, 'operator-check.jsonl');
rmSync(journal, { force: true });

const node = (args: string[]) => spawn(process.execPath, args, { cwd: join(import.meta.dirname, '../..'), stdio: ['ignore', 'pipe', 'pipe'] });
const server = node(['src/operator/server.ts', '--port', String(PORT), '--accounts', String(ACCOUNTS), '--journal', journal, '--gateways', '2', '--threads', '8', '--block-ms', '1000', '--batch-ms', '3000']);
let serverOut = '';
await new Promise<void>((ok, fail) => {
  server.stdout.on('data', (d) => {
    serverOut += d;
    if (serverOut.includes('listening')) ok();
  });
  server.stderr.on('data', (d) => (serverOut += d));
  server.on('exit', (c) => fail(new Error(`operator exited (${c}): ${serverOut}`)));
});
log(serverOut.trim().split('\n').at(-1)!);

const load = node(['src/operator/load.ts', '--port', String(PORT), '--accounts', String(ACCOUNTS), '--rate', '50', '--seconds', '8', '--workers', '2']);
let loadOut = '';
load.stdout.on('data', (d) => (loadOut += d));
load.stderr.on('data', (d) => (loadOut += d));
const loadCode = await new Promise<number | null>((ok) => load.on('exit', ok));
for (const l of loadOut.trim().split('\n')) if (/sent|phase|refusals/.test(l)) log(l.replace('[load] ', 'load: '));
assert(loadCode === 0, `load generator failed: ${loadOut}`);
const m = loadOut.match(/sent (\d+), accepted (\d+), refused (\d+), not sent \(every account busy\) (\d+)/);
assert(!!m, 'no load summary');
const [sent, accepted, refused] = [Number(m[1]), Number(m[2]), Number(m[3])];
assert(sent > 300 && accepted + refused === sent, `every action is answered (sent ${sent}, accepted ${accepted}, refused ${refused})`);
const reasons = [...loadOut.matchAll(/([a-z][a-z ]+) ×\d+/g)].map((r) => r[1]);
assert(reasons.every((r) => r === 'no such order'), `unexpected refusals: ${reasons.join(', ')}`);

// Stop the operator; it closes the journal.
server.kill('SIGINT');
await new Promise((ok) => server.on('exit', ok));

const { report } = await replay(journal, { execute: [1], log: (s) => log(`replay: ${s}`) });
assert(report.actions === accepted, `the journal replays every applied action (${report.actions} of ${accepted})`);
assert(report.batches >= 3 && report.executed > 0, 'batches were cut and a trading batch was executed');
log(`the operator answered ${sent} actions (${accepted} applied); the journal replays them and its batches execute in the circuits`);
process.exit(0);
