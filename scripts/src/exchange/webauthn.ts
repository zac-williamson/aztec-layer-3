// A WebAuthn authenticator, simulated for the passkey client circuit (SPEC.md §7.4): an assertion's
// signature is ECDSA P-256 over SHA-256(authenticatorData ‖ SHA-256(clientDataJSON)), with the
// action message, base64url-encoded, as the challenge. Browsers serialize clientDataJSON with
// "type" then "challenge" first, which is what the circuit relies on; what follows is hashed but
// not parsed.
import { createHash } from 'node:crypto';
import { type P256Key, bytes32, p256Sign } from './p256.ts';

export const sha256 = (b: Uint8Array) => new Uint8Array(createHash('sha256').update(b).digest());
export const base64url = (b: Uint8Array) => Buffer.from(b).toString('base64url');

/** Flags: user present (0x01) and user verified (0x04). */
const UP_UV = 0x05;
export const AUTH_DATA_LEN = 37;
export const CLIENT_DATA_MAX = 311;

export type Assertion = { authenticatorData: Uint8Array; clientDataJSON: Uint8Array; signature: Uint8Array };

/**
 * An assertion for `msg` by the passkey `key` registered with relying party `rpId`. `extra` is
 * appended to clientDataJSON after the origin, as browsers sometimes append fields.
 */
export function makeAssertion(key: P256Key, rpId: string, origin: string, msg: bigint, signCount = 1, extra = ''): Assertion {
  const authenticatorData = new Uint8Array(AUTH_DATA_LEN);
  authenticatorData.set(sha256(new TextEncoder().encode(rpId)), 0);
  authenticatorData[32] = UP_UV;
  new DataView(authenticatorData.buffer).setUint32(33, signCount);
  const challenge = base64url(new Uint8Array(bytes32(msg)));
  const json = `{"type":"webauthn.get","challenge":"${challenge}","origin":"${origin}","crossOrigin":false${extra}}`;
  const clientDataJSON = new TextEncoder().encode(json);
  if (clientDataJSON.length > CLIENT_DATA_MAX) throw new Error('clientDataJSON too long for the circuit');
  const signed = new Uint8Array([...authenticatorData, ...sha256(clientDataJSON)]);
  return { authenticatorData, clientDataJSON, signature: p256Sign(key, sha256(signed)) };
}

/** The relying party ID hash in 16-byte halves, as the auth binding takes it. */
export function rpHalves(rpId: string): [bigint, bigint] {
  const h = BigInt(`0x${Buffer.from(sha256(new TextEncoder().encode(rpId))).toString('hex')}`);
  return [h >> 128n, h & ((1n << 128n) - 1n)];
}
