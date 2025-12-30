#[cfg(test)]
mod tests {
    use lab07::{circuit::{gates::{eval_and_gate, garble_and_gate}, utils::{Block, rand_block, xor_block}}, circuit_debug_log};

    fn gen_delta() -> Block {
        let mut delta = rand_block();
        delta[0] |= 1; 
        delta
    }

    #[test]
    fn test_and_gate() {
        let delta = gen_delta();
        let gid: u64 = 100;

        let a0 = rand_block();
        let a1 = xor_block(&a0, &delta);

        let b0 = rand_block();
        let b1 = xor_block(&b0, &delta);

        let (table, out0) = garble_and_gate(&a0, &b0, &delta, gid);
        let out1 = xor_block(&out0, &delta);

        let scenarios = vec![
            (false, false, false), // 00=0
            (false, true, false), // 01=0
            (true, false, false), // 10=0
            (true, true, true), // 11=1
        ];

        for (val_a, val_b, expected) in scenarios {
            circuit_debug_log!("Testing AND gate with inputs: {} & {}", val_a, val_b);
            let label_a = if val_a { &a1 } else { &a0 };
            let label_b = if val_b { &b1 } else { &b0 };

            let eval_out = eval_and_gate(label_a, label_b, &table, gid);

            circuit_debug_log!("Evaluated output label: {:?}", eval_out);

            let expected_label = if expected { &out1 } else { &out0 };

            circuit_debug_log!("Expected output label: {:?}", expected_label);

            assert_eq!(eval_out, *expected_label, "AND gate failed for inputs: {} AND {}", val_a, val_b);
        }
    }

    #[test]
    fn test_xor() {
        let delta = gen_delta();

        let a0 = rand_block();
        let a1 = xor_block(&a0, &delta);

        let b0 = rand_block();
        let b1 = xor_block(&b0, &delta);

        let c0 = xor_block(&a0, &b0);
        let c1 = xor_block(&c0, &delta);

        let scenarios = vec![
            (false, false, false), // 00=0
            (false, true, true), // 01=1
            (true, false, true), // 10=1
            (true, true, false), // 11=0
        ];

        for (val_a, val_b, expected) in scenarios {
            circuit_debug_log!("Testing XOR gate with inputs: {} ^ {}", val_a, val_b);
            let label_a = if val_a { &a1 } else { &a0 };
            let label_b = if val_b { &b1 } else { &b0 };

            let eval_out = xor_block(label_a, label_b);

            circuit_debug_log!("Evaluated output label: {:?}", eval_out);

            let expected_label = if expected { &c1 } else { &c0 };

            circuit_debug_log!("Expected output label: {:?}", expected_label);

            assert_eq!(eval_out, *expected_label, "XOR gate failed for inputs: {} XOR {}", val_a, val_b);
        }
    }
}