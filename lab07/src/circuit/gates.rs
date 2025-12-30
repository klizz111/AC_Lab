use serde::{Deserialize, Serialize};

use crate::circuit::utils::{Block, get_lsb, hash_label, rand_block, xor_block};

// !Garbler

/// return (GarbledTable, OutputLabel0)
pub fn garble_and_gate(a0: &Block, b0: &Block, delta: &Block, gid: u64) -> ((Block, Block), Block) {
    let pa = get_lsb(a0);
    let pb = get_lsb(b0);

    // 1. 计算哈希值
    let ha0 = hash_label(a0, gid, 0);
    let ha1 = hash_label(&xor_block(a0, delta), gid, 0); // H(a1)
    let hb0 = hash_label(b0, gid, 1);
    let hb1 = hash_label(&xor_block(b0, delta), gid, 1); // H(b1)

    // 2. Garbler half-gate
    // tg = ha0 ^ ha1 ^ (delta if pb else 0)
    let mut tg = xor_block(&ha0, &ha1);
    if pb {
        tg = xor_block(&tg, delta);
    }

    // wg0 = ha0 ^ (pa? tg : 0)
    let mut wg0 = ha0;
    if pa {
        wg0 = xor_block(&wg0, &tg);
    }

    // 3. Evaluator half-gate
    // te = hb0 ^ hb1 ^ a0
    let te = xor_block(&xor_block(&hb0, &hb1), a0);

    // we0 = hb0 ^ ( pb ? te ^ a0 : 0 )
    let mut we0 = hb0;
    if pb {
        let tmp = xor_block(&te, a0);
        we0 = xor_block(&we0, &tmp);
    }

    // 4. 输出标签
    // output0 = wg0 ^ we0
    let output0 = xor_block(&wg0, &we0);

    ((tg, te), output0)
}

// !Evaluator

/// Evaluate AND gate
pub fn eval_and_gate(
    label_a: &Block,
    label_b: &Block,
    garbled_table: &(Block, Block),
    gid: u64,
) -> Block {
    let (tg, te) = garbled_table;
    let sa = get_lsb(label_a);
    let sb = get_lsb(label_b);

    // wga = H(a) ^ ( sa ? tg : 0 )
    let ha = hash_label(label_a, gid, 0);
    let mut wga = ha;
    if sa {
        wga = xor_block(&wga, tg);
    }

    // web = H(b) ^ ( sb ? te ^ a : 0 )
    let hb = hash_label(label_b, gid, 1);
    let mut web = hb;
    if sb {
        let tmp = xor_block(te, label_a);
        web = xor_block(&web, &tmp);
    }

    xor_block(&wga, &web)
}

/// Evaluate XOR gate
pub fn eval_xor_gate(label_a: &Block, label_b: &Block) -> Block {
    xor_block(label_a, label_b)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Cipher {
    pub tg: Block,
    pub te: Block,
}

pub struct GarblerGate {
    pub delta: Block,
}

impl GarblerGate {
    pub fn new() -> Self {
        let mut delta = rand_block();
        delta[0] |= 1;
        GarblerGate { delta }
    }

    pub fn gen_labels(&self) -> (Block, Block) {
        let label0 = rand_block();
        let label1 = xor_block(&label0, &self.delta);
        (label0, label1)
    }

    pub fn garble_and(
        &self,
        a0: &Block,
        a1: &Block,
        b0: &Block,
        b1: &Block,
        gid: u64,
    ) -> (Block, Block, Cipher) {
        let pa = get_lsb(a0);
        let pb = get_lsb(b0);

        let ha0 = hash_label(a0, gid, 0);
        let ha1 = hash_label(a1, gid, 0);
        let hb0 = hash_label(b0, gid, 1);
        let hb1 = hash_label(b1, gid, 1);

        let mut tg = xor_block(&ha0, &ha1);
        if pb {
            tg = xor_block(&tg, &self.delta);
        }

        let mut te = xor_block(&hb0, &hb1);
        te = xor_block(&te, a0);

        let mut wg0 = ha0;
        if pa {
            wg0 = xor_block(&wg0, &tg);
        }

        let mut wg0 = xor_block(&wg0, &hb0);
        if pb {
            let tmp = xor_block(&te, a0);
            wg0 = xor_block(&wg0, &tmp);
        }

        let wg1 = xor_block(&wg0, &self.delta);

        (wg0, wg1, Cipher { tg, te })
    }

    pub fn eval_and(la: &Block, lb: &Block, ct: &Cipher, gid: u64) -> Block {
        let sa = get_lsb(la);
        let sb = get_lsb(lb);

        let hla = hash_label(la, gid, 0);
        let hlb = hash_label(lb, gid, 1);

        // w = H(La) ^ (sa ? Tg : 0) ^ H(Lb) ^ (sb ? (Te ^ La) : 0)
        let mut w = hla;
        if sa {
            w = xor_block(&w, &ct.tg);
        }
        w = xor_block(&w, &hlb);
        if sb {
            let term = xor_block(&ct.te, la);
            w = xor_block(&w, &term);
        }
        w
    }
}
