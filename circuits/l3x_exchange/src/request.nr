use crate::consts::DS_REQ;
use l3x_types::{hash::hash, priority_entry};

/// A priority request as the Bridge queued it (SPEC.md §7.3, §10.1). The Bridge stores only the
/// entry; the segment receives this preimage and the hash chain binds it.
///   Register:        a = master_auth, b = enc_commitment
///   Deposit:         a = account index, b = H(DS_DEPAMT, amount, salt), c = refund_to (custody
///                    queues a deposit once its funds are in the vault)
///   ForcedWithdraw:  a = account index, b = recipient
///   ForcedClose:     a = account index, b = market, c = worst price
///   ForcedCancelAll: a = account index
pub struct Request {
    pub kind: Field,
    pub a: Field,
    pub b: Field,
    pub c: Field,
    pub sender: Field,
    pub time: u64,
}

impl Request {
    pub fn payload_hash(self) -> Field {
        payload_hash(self.kind, self.a, self.b, self.c)
    }

    pub fn entry(self) -> Field {
        priority_entry(self.payload_hash(), self.sender, self.time)
    }
}

pub fn payload_hash(kind: Field, a: Field, b: Field, c: Field) -> Field {
    hash([DS_REQ, kind, a, b, c])
}
