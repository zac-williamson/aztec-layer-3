// TypeScript mirror of contracts/ctoken (SPEC.md §10.5): a credit's identifier and nullifiers.
// Its Poseidon2 with a separator is the same sponge as l3xHash with the separator first.
import { big } from './chain.ts';
import type { H } from './model.ts';

export const DS_CREDIT = 0x63742e637265646974n; // "ct.credit"
export const DS_CREATED = 0x63742e63726561746564n; // "ct.created"
export const DS_SPENT = 0x63742e7370656e74n; // "ct.spent"
/** Tag of the plaintext log of a confidential payment's parties; the kernel siloes it by the token. */
export const PARTIES_LOG_TAG = 0x63742e70617274696573n; // "ct.parties"

/** A credit's opening as its owner holds it; a zero amount marks an unused input. */
export type Credit = { amount: bigint; blind: bigint };

export const creditId = (h: H, owner: unknown, amount: bigint, blind: bigint) => h([DS_CREDIT, big(owner), amount, blind]);
export const createdNullifier = (h: H, credit: bigint) => h([DS_CREATED, credit]);
export const spentNullifier = (h: H, credit: bigint) => h([DS_SPENT, credit]);
