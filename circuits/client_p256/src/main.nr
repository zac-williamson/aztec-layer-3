use l3x_types::{DS_P256, hash::hash};

/// P-256 client circuit (SPEC.md §7.4): a hardware key authorizes the action digest `msg` for
/// `account_index`, for example a Secure Enclave or passkey key through a digest-signing API. The
/// key signs the message's 32 bytes as its digest; the message is already a domain-separated hash
/// (SPEC.md §7.1). `auth_binding` commits to the key and to a salt the client keeps, so the
/// account's master authorization names the key without making the key a public identifier.
/// Public inputs, in order: (msg, account_index, auth_binding).
fn main(
    pk_x: [u8; 32],
    pk_y: [u8; 32],
    salt: Field,
    signature: [u8; 64],
    msg: pub Field,
    account_index: pub Field,
    auth_binding: pub Field,
) {
    assert(p256_binding(pk_x, pk_y, salt) == auth_binding, "key does not match the auth binding");
    let digest: [u8; 32] = msg.to_be_bytes();
    assert(std::ecdsa_secp256r1::verify_signature(pk_x, pk_y, signature, digest), "bad P-256 signature");
    // account_index is bound only as a public input: the proof authorizes exactly it.
    let _ = account_index;
}

/// hash(DS_P256, x_hi, x_lo, y_hi, y_lo, salt), each coordinate split into 16-byte halves.
fn p256_binding(pk_x: [u8; 32], pk_y: [u8; 32], salt: Field) -> Field {
    let mut h: [Field; 4] = [0; 4];
    for i in 0..16 {
        h[0] = h[0] * 256 + pk_x[i] as Field;
        h[1] = h[1] * 256 + pk_x[16 + i] as Field;
        h[2] = h[2] * 256 + pk_y[i] as Field;
        h[3] = h[3] * 256 + pk_y[16 + i] as Field;
    }
    hash([DS_P256, h[0], h[1], h[2], h[3], salt])
}
