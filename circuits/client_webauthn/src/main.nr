use l3x_types::{DS_WEBAUTHN, hash::hash};

global AUTH_DATA_LEN: u32 = 37;
/// clientDataJSON up to 311 bytes: five SHA-256 blocks with padding.
global CLIENT_DATA_MAX: u32 = 311;
global CLIENT_DATA_BLOCKS: u32 = 5;
/// `{"type":"webauthn.get","challenge":"`, which browsers serialize first (WebAuthn §5.8.1.1).
global PREFIX: [u8; 36] = [
    123, 34, 116, 121, 112, 101, 34, 58, 34, 119, 101, 98, 97, 117, 116, 104, 110, 46, 103, 101, 116, 34, 44, 34,
    99, 104, 97, 108, 108, 101, 110, 103, 101, 34, 58, 34,
];
global CHALLENGE_LEN: u32 = 43;
global IV: [u32; 8] =
    [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

/// Passkey client circuit (SPEC.md §7.4): a WebAuthn assertion authorizes the action digest `msg`
/// for `account_index`. The assertion's challenge is `msg`, base64url-encoded, so the passkey signs
/// exactly this action. `auth_binding` commits to the key, to the relying party (authenticator data
/// begins with the SHA-256 of its ID) and to a salt the client keeps. The rest of clientDataJSON,
/// including the origin, is hashed as signed but not parsed: the relying party binds the site.
/// Public inputs, in order: (msg, account_index, auth_binding).
fn main(
    pk_x: [u8; 32],
    pk_y: [u8; 32],
    salt: Field,
    signature: [u8; 64],
    authenticator_data: [u8; AUTH_DATA_LEN],
    client_data: [u8; CLIENT_DATA_MAX],
    client_data_len: u32,
    msg: pub Field,
    account_index: pub Field,
    auth_binding: pub Field,
) {
    assert(binding(pk_x, pk_y, authenticator_data, salt) == auth_binding, "key does not match the auth binding");
    assert((authenticator_data[32] & 1) == 1, "user not present");
    assert((client_data_len > 36 + CHALLENGE_LEN) & (client_data_len <= CLIENT_DATA_MAX), "client data length");
    for i in 0..36 {
        assert(client_data[i] == PREFIX[i], "not a WebAuthn assertion");
    }
    let digest: [u8; 32] = msg.to_be_bytes();
    let challenge = base64url32(digest);
    for i in 0..CHALLENGE_LEN {
        assert(client_data[36 + i] as Field == challenge[i], "assertion for another challenge");
    }
    assert(client_data[36 + CHALLENGE_LEN] == 34, "assertion for another challenge");
    let client_data_hash = sha256_var(client_data, client_data_len);
    let mut signed: [u8; 69] = [0; 69];
    for i in 0..AUTH_DATA_LEN {
        signed[i] = authenticator_data[i];
    }
    for i in 0..32 {
        signed[AUTH_DATA_LEN + i] = client_data_hash[i];
    }
    assert(
        std::ecdsa_secp256r1::verify_signature(pk_x, pk_y, signature, sha256_69(signed)),
        "bad passkey signature",
    );
    // account_index is bound only as a public input: the proof authorizes exactly it.
    let _ = account_index;
}

/// hash(DS_WEBAUTHN, x_hi, x_lo, y_hi, y_lo, rp_hi, rp_lo, salt): the key's coordinates and the
/// relying party ID hash, each in 16-byte halves.
fn binding(pk_x: [u8; 32], pk_y: [u8; 32], authenticator_data: [u8; AUTH_DATA_LEN], salt: Field) -> Field {
    let mut h: [Field; 6] = [0; 6];
    for i in 0..16 {
        h[0] = h[0] * 256 + pk_x[i] as Field;
        h[1] = h[1] * 256 + pk_x[16 + i] as Field;
        h[2] = h[2] * 256 + pk_y[i] as Field;
        h[3] = h[3] * 256 + pk_y[16 + i] as Field;
        h[4] = h[4] * 256 + authenticator_data[i] as Field;
        h[5] = h[5] * 256 + authenticator_data[16 + i] as Field;
    }
    hash([DS_WEBAUTHN, h[0], h[1], h[2], h[3], h[4], h[5], salt])
}

/// The base64url character for a 6-bit value, as a field element, without branches.
fn b64(v: u32) -> Field {
    let f = v as Field;
    f + 65 + 6 * ((v >= 26) as Field) - 75 * ((v >= 52) as Field) - 13 * ((v == 62) as Field)
        + 36 * ((v == 63) as Field)
}

/// base64url of 32 bytes, unpadded: 43 characters.
fn base64url32(b: [u8; 32]) -> [Field; CHALLENGE_LEN] {
    let mut out: [Field; CHALLENGE_LEN] = [0; CHALLENGE_LEN];
    for g in 0..10 {
        let x = ((b[3 * g] as u32) << 16) | ((b[3 * g + 1] as u32) << 8) | (b[3 * g + 2] as u32);
        out[4 * g] = b64((x >> 18) & 63);
        out[4 * g + 1] = b64((x >> 12) & 63);
        out[4 * g + 2] = b64((x >> 6) & 63);
        out[4 * g + 3] = b64(x & 63);
    }
    let x = ((b[30] as u32) << 16) | ((b[31] as u32) << 8);
    out[40] = b64((x >> 18) & 63);
    out[41] = b64((x >> 12) & 63);
    out[42] = b64((x >> 6) & 63);
    out
}

fn words<let N: u32>(bytes: [u8; N], offset: u32) -> [u32; 16] {
    let mut w: [u32; 16] = [0; 16];
    for j in 0..16 {
        let k = offset + 4 * j;
        w[j] = ((bytes[k] as u32) << 24) | ((bytes[k + 1] as u32) << 16) | ((bytes[k + 2] as u32) << 8)
            | (bytes[k + 3] as u32);
    }
    w
}

fn digest_bytes(state: [u32; 8]) -> [u8; 32] {
    let mut out: [u8; 32] = [0; 32];
    for j in 0..8 {
        out[4 * j] = (state[j] >> 24) as u8;
        out[4 * j + 1] = (state[j] >> 16) as u8;
        out[4 * j + 2] = (state[j] >> 8) as u8;
        out[4 * j + 3] = state[j] as u8;
    }
    out
}

/// SHA-256 of data[0..len], len ≤ CLIENT_DATA_MAX: every block is compressed, and the state after
/// the message's last padded block is kept.
fn sha256_var(data: [u8; CLIENT_DATA_MAX], len: u32) -> [u8; 32] {
    let blocks = (len + 9 + 63) / 64;
    let total = blocks * 64;
    // len < 2^9, so its bit length fits in the last two bytes of the length field.
    let bits = len * 8;
    let mut padded: [u8; 320] = [0; 320];
    for i in 0..CLIENT_DATA_MAX {
        padded[i] = if i < len {
            data[i]
        } else if i == len {
            0x80
        } else if i == total - 2 {
            (bits >> 8) as u8
        } else if i == total - 1 {
            bits as u8
        } else {
            0
        };
    }
    for i in CLIENT_DATA_MAX..320 {
        padded[i] = if i == len {
            0x80
        } else if i == total - 2 {
            (bits >> 8) as u8
        } else if i == total - 1 {
            bits as u8
        } else {
            0
        };
    }
    let mut state = IV;
    for b in 0..CLIENT_DATA_BLOCKS {
        let next = std::hash::sha256_compression(words(padded, 64 * b), state);
        if b < blocks {
            state = next;
        }
    }
    digest_bytes(state)
}

/// SHA-256 of the 69 signed bytes (authenticator data and the client data hash): two blocks.
fn sha256_69(m: [u8; 69]) -> [u8; 32] {
    let mut padded: [u8; 128] = [0; 128];
    for i in 0..69 {
        padded[i] = m[i];
    }
    padded[69] = 0x80;
    // 69 · 8 = 552 = 0x0228 bits.
    padded[126] = 0x02;
    padded[127] = 0x28;
    let s = std::hash::sha256_compression(words(padded, 0), IV);
    digest_bytes(std::hash::sha256_compression(words(padded, 64), s))
}
