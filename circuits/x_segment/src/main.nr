use l3x_types::{
    da_absorb, DS_ACCOUNTS, DS_ACTION_LOG, hash::hash, MAX_PRIORITY, NodeOutput, priority_next_head,
    Running, trees, X_DA_MAX,
};

/// X-segment (SPEC.md §9.2), P0 stub. An UltraHonk circuit proved directly with the
/// noir-rollup-no-zk target: it has no recursive verification, so bb attaches its default IPA
/// claim and the proof enters the merge tree like a tube's (M7). It carries one L3 block: it
/// advances time, consumes priority entries in queue order, and absorbs DA fields.
///
/// P0 stub effect: each consumed entry is absorbed into the accounts root and the action log.
fn main(
    config_hash: Field,
    start: Running,
    accounts_root: Field,
    other_root: Field,
    block_time: u64,
    priority_n: u32,
    priority_entries: [Field; MAX_PRIORITY],
    da_n: u32,
    da_fields: [Field; X_DA_MAX],
) -> pub NodeOutput {
    assert(start.state == trees(accounts_root, other_root), "state opening");
    assert(block_time >= start.time, "time regressed");
    assert(priority_n <= MAX_PRIORITY, "too many priority entries");
    assert(da_n <= X_DA_MAX, "too many DA fields");
    let mut end = start;
    let mut accounts = accounts_root;
    for i in 0..MAX_PRIORITY {
        if i < priority_n {
            let entry = priority_entries[i];
            end.priority_head = priority_next_head(end.priority_head, entry);
            accounts = hash([DS_ACCOUNTS, accounts, entry]);
            end.action_log = hash([DS_ACTION_LOG, end.action_log, entry, 0]);
        }
    }
    end.priority_cursor = start.priority_cursor + priority_n as u64;
    for i in 0..X_DA_MAX {
        if i < da_n {
            let (da, len) = da_absorb(end.da, end.da_len, da_fields[i]);
            end.da = da;
            end.da_len = len;
        }
    }
    end.state = trees(accounts, other_root);
    end.time = block_time;
    NodeOutput { config_hash, start, end }
}
