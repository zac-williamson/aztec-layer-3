use l3x_types::{DS_AUTH, hash::hash};

/// P0 client-proof-lane circuit (SPEC.md §7.4). The prover knows the secret behind the
/// account's `auth_binding` and authorizes the action digest `msg` for `account_index`.
/// Public inputs, in order: (msg, account_index, auth_binding).
fn main(secret: Field, msg: pub Field, account_index: pub Field, auth_binding: pub Field) {
    assert(hash([DS_AUTH, secret]) == auth_binding, "bad auth secret");
    // msg and account_index are bound only as public inputs: the proof authorizes exactly them.
    let _ = (msg, account_index);
}

#[test]
fn test_accepts_matching_secret() {
    main(5, 1, 2, hash([DS_AUTH, 5]));
}

#[test(should_fail_with = "bad auth secret")]
fn test_rejects_wrong_secret() {
    main(6, 1, 2, hash([DS_AUTH, 5]));
}
