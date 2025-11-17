#![allow(dead_code,unused_imports,unused_variables)]
use std::env;
use zkp::soduku::sudoku_gen::Sudoku;

struct Prover {
    sudo: Sudoku,
    port: String,
    host: String,
    rounds: usize,
    clues: i8,
}

macro_rules! prover_print {
    ($exp:expr) => {
        println!("[Prover] {}", $exp);
    };
}


impl Prover {
    pub fn new(port: String, host_:Option<String>, rounds: usize, clues_: Option<i8>) -> Self {
        Prover {
            sudo: Sudoku::new(),
            port,
            rounds,
            clues: match clues_ {
                Some(c) => c,
                None => 30,
            },
            host: match host_ {
                Some(h) => h,
                None => "127.0.0.1".to_string(),
            },
        }
    }

    pub fn init(&mut self) {
        self.sudo.init();
        let puzzle = self.sudo.get_puzzle();
        let solution = self.sudo.get_solution();
        prover_print!(format!("Initialized Sudoku puzzle with {} clues.", self.clues));
        prover_print!(format!("Puzzle:"));
        self.sudo.print_it(1);
        prover_print!(format!("Solution:"));
        self.sudo.print_it(0);
    }
}

macro_rules! printusage {
    () => {
        eprint!("Usage: prover <host> <port> <rounds> <clues>\n");
        eprint!("Use - to use default values for host and clues.\n");
    };
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 5 {
        printusage!();
        return;
    }
    let host = if args[1] == "-" {
        None
    } else {
        Some(args[1].clone())
    };
    let port = args[2].clone();
    let rounds: usize = match args[3].parse() {
        Ok(n) => n,
        Err(_) => {
            printusage!();
            return;
        }
    };
    let clues: Option<i8> = if args[4] == "-" {
        None
    } else {
        match args[4].parse() {
            Ok(n) => Some(n),
            Err(_) => {
                printusage!();
                return;
            }
        }
    };
}

#[test]
fn test_prover_init() {
    let mut prover = Prover::new("9000".to_string(),None, 5,None);
    prover.init();
}