use crate::crypto::sha256;

/// Merkle leaf hash for a PRR: H(bytes).
pub fn leaf_hash(leaf_bytes: &[u8]) -> [u8; 32] {
    sha256(leaf_bytes)
}

/// Hash two nodes: H(left || right).
fn hash_node(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    sha256(&buf)
}

/// Compute Merkle root from leaves.
/// - If no leaves: root = H("").
/// - If odd number at a level: duplicate last.
pub fn merkle_root(mut leaves: Vec<[u8; 32]>) -> [u8; 32] {
    if leaves.is_empty() {
        return sha256(&[]);
    }
    while leaves.len() > 1 {
        if leaves.len() % 2 == 1 {
            leaves.push(*leaves.last().unwrap());
        }
        let mut next = Vec::with_capacity(leaves.len() / 2);
        for pair in leaves.chunks(2) {
            next.push(hash_node(&pair[0], &pair[1]));
        }
        leaves = next;
    }
    leaves[0]
}
