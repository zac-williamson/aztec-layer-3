/// Poseidon2 sponge over the BN254 scalar field: rate 3, capacity 1, with the input length
/// in the capacity element so inputs of different lengths never collide. Every L3X hash
/// (circuits, Bridge contract, scripts/src/hash.ts) uses this one construction with an
/// explicit domain separator as its first input.
pub fn hash<let N: u32>(inputs: [Field; N]) -> Field {
    let mut state: [Field; 4] = [0, 0, 0, (N as Field) * 18446744073709551616];
    let mut pos: u32 = 0;
    for i in 0..N {
        state[pos] += inputs[i];
        pos += 1;
        if pos == 3 {
            state = std::hash::poseidon2_permutation(state);
            pos = 0;
        }
    }
    if pos != 0 {
        state = std::hash::poseidon2_permutation(state);
    }
    state[0]
}

#[test]
fn test_hash_distinguishes_lengths() {
    assert(hash([1, 2, 3]) != hash([1, 2, 3, 0]));
    assert(hash([7]) != hash([7, 0]));
}
