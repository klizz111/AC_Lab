use sha2::{Sha256,Digest};


/// label, length=16, 小端序
pub type Block = [u8; 16];

/// Get least significant bit of a block
pub fn get_lsb(block: &Block) -> bool {
    block[0] & 1 == 1
}

/// xor blocks
pub fn xor_block(a : &Block, b: &Block) -> Block {
    let mut res = [0u8; 16];
    for i in 0..16 {
        res[i] = a[i] ^ b[i];
    }
    res
}

pub fn rand_block() -> Block {
    use rand::RngCore;
    let mut block = [0u8; 16];
    rand::rng().fill_bytes(&mut block);
    block
}

// Half-Gate 哈希函数: H(label, gid, tweak)
// tweak: 0 for left input, 1 for right input
pub fn hash_label(label: &Block, gid: u64, tweak: u64) -> Block {
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update(gid.to_be_bytes());
    hasher.update(tweak.to_be_bytes());
    let result = hasher.finalize();
    
    let mut out = [0u8; 16];
    out.copy_from_slice(&result[0..16]); // 截断前16字节
    out
}