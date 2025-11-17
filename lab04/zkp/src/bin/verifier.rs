#![allow(dead_code,unused_imports,unused_variables)]
use std::env;
use zkp::challenge::*;
use zkp::soduku::commit::{v_a_line, v_a_cell};
use zkp::soduku::*;
use zkp::networks::*;
use std::hash::{DefaultHasher, Hash, Hasher};

macro_rules! printusage {
    () => {
        eprintln!("Usage: verifier <port> <rounds>");
    };
}

macro_rules! verifier_print {
    ($exp:expr) => {
        println!("[Verifier] {}", $exp);
    };
}

struct Verifier {
    port: String,
    rounds: usize,
    puzzle: Matrix,
    num_clues: i8, 
}

impl Verifier {
    pub fn new(port: String, rounds: usize) -> Self {
        Verifier {
            port,
            rounds,
            puzzle: Matrix::new(),
            num_clues: 0,
        }
    }

    pub fn check_line(&self, mat_commit: &Vec<u64>, random_: &Vec<u64>, line: &Vec<u8>) -> bool {
        // 先查是否符合规则
        let mut cclloonnee = line.clone();
        cclloonnee.sort();
        for i in 0..9 {
            if cclloonnee[i] != (i + 1) as u8 {
                return false;
            }
        }
        // 再查是否通过承诺
        let bbooll = v_a_line(mat_commit, random_, line);
        true
    }

    pub fn check_cell(&self, mat_commit: &Vec<Vec<u64>>, random_: &Vec<Vec<u64>>, cell_no: u8, cell: &Matrix) -> bool {
        // 先查是否符合规则
        let mut cclloonnee: Vec<u8> = Vec::new();
        for i in 0..3 {
            for j in 0..3 {
                cclloonnee.push(cell[i][j]);
            }
        }
        cclloonnee.sort();
        for i in 0..9 {
            if cclloonnee[i] != (i + 1) as u8 {
                return false;
            }
        }
        // 再查是否通过承诺
        let bbooll = v_a_cell(mat_commit, random_, cell);
        true
    }
    
}

fn main() {
    let args: Vec<String>= env::args().collect();
    if args.len() != 3  {
        printusage!();
        return;
    }
    let port = &args[1];
    let round = &args[2].parse::<usize>().unwrap();

    // Start up listener
    verifier_print!(format!("Starting verifier ......"));

}