#![allow(dead_code, unused_imports, unused_variables)]

use std::collections::{HashMap, HashSet};
use std::env;
use std::io::{self, ErrorKind, Error};
use std::net::TcpStream;
use std::thread::sleep;
use std::time::Duration;

use zkp::challenge::ChallengeType;
use zkp::networks::{
    BoxReveal, ClueResponse, ClueReveal, CommitmentMessage, LineReveal, ProverMessage,
    PuzzleMessage, ResponseMessage, RevealPayload, VerifierMessage, receive_message, send_message,
};
use zkp::soduku::commit::{CastCommit, CommitMat_, MatCommit};
use zkp::soduku::sudoku_gen::Sudoku;
use zkp::soduku::{CommitMat, Matrix};

struct RoundArtifacts {
    mapping: Vec<u8>,
    mapping_randomness: Vec<u64>,
    mapped_solution: Matrix,
    board_randomness: CommitMat,
}

/// - `host`: "127.0.0.1"
/// - `port`: "8899"
/// - `rounds`: 10
/// - `clues`: 30
struct Prover {
    sudo: Sudoku,
    port: String,
    host: String,
    rounds: usize,
    clues: usize,
}

macro_rules! prover_print {
    ($exp:expr) => {
        println!("[Prover] {}", $exp);
    };
}

impl Prover {
    pub fn new(port_: Option<String>, host_: Option<String>, rounds_: Option<usize>, clues_: Option<i8>) -> Self {
        Prover {
            sudo: Sudoku::new(),
            port: port_.unwrap_or("8899".to_string()),
            rounds: rounds_.unwrap_or(10),
            clues: clues_.map(|c| c.max(30) as usize).unwrap_or(30),
            host: host_.unwrap_or_else(|| "127.0.0.1".to_string()),
        }
    }

    fn init_puzzle(&mut self) {
        self.sudo.init(Some(self.clues));
        prover_print!(format!("Generated puzzle with {} clues", self.clues));
        prover_print!("Puzzle preview:");
        self.sudo.print_it(1);
    }

    fn connect(&self) -> io::Result<TcpStream> {
        let addr = format!("{}:{}", self.host, self.port);
        let mut attempts = 0;
        loop {
            attempts += 1;
            match TcpStream::connect(&addr) {
                Ok(stream) => {
                    prover_print!(format!(
                        "Connected to verifier at {} after {} attempt(s)",
                        addr, attempts
                    ));
                    stream.set_nodelay(true).ok();
                    prover_print!(format!("Running at {}", stream.local_addr().unwrap()));
                    return Ok(stream);
                }
                Err(err) => {
                    if attempts >= 5 {
                        return Err(err);
                    }
                    prover_print!(format!(
                        "Connection failed (attempt {}): {}. Retrying...",
                        attempts, err
                    ));
                    sleep(Duration::from_secs(1));
                }
            }
        }
    }

    fn clue_cells(&self) -> Vec<(usize, usize, u8)> {
        let puzzle = self.sudo.get_puzzle();
        let mut cells = Vec::new();
        for (row, line) in puzzle.iter().enumerate() {
            for (col, &val) in line.iter().enumerate() {
                if val != 0 {
                    cells.push((row, col, val));
                }
            }
        }
        cells
    }

    fn prepare_round(&mut self) -> (CommitmentMessage, RoundArtifacts) {
        let mapping = self.sudo.gen_cast();
        let mapped_solution = Self::apply_mapping(&self.sudo.get_solution(), &mapping);
        let (board_commit, board_randomness) = mapped_solution.commit();
        let (mapping_commit, mapping_randomness) = mapping.clone().commit();

        let commitment = CommitmentMessage {
            round: 0,
            board_commit: board_commit.clone(),
            mapping_commit,
        };

        let artifacts = RoundArtifacts {
            mapping,
            mapping_randomness,
            mapped_solution,
            board_randomness,
        };

        (commitment, artifacts)
    }

    fn respond_to_challenge(
        &self,
        round_idx: usize,
        challenge: ChallengeType,
        artifacts: &RoundArtifacts,
        clues: &[(usize, usize, u8)],
    ) -> ResponseMessage {
        let payload = match challenge {
            ChallengeType::Row(row) => {
                let values = artifacts.mapped_solution[row].clone();
                let randomness = artifacts.board_randomness[row].clone();
                self.log_row_reveal(row, &values);
                RevealPayload::Row(LineReveal {
                    index: row,
                    values,
                    randomness,
                })
            }
            ChallengeType::Col(col) => {
                let mut values = Vec::with_capacity(9);
                let mut randomness = Vec::with_capacity(9);
                for r in 0..9 {
                    values.push(artifacts.mapped_solution[r][col]);
                    randomness.push(artifacts.board_randomness[r][col]);
                }
                self.log_column_reveal(col, &values);
                RevealPayload::Col(LineReveal {
                    index: col,
                    values,
                    randomness,
                })
            }
            ChallengeType::Box(cell) => {
                let values = artifacts.mapped_solution.get_a_cell(cell as u8);
                let randomness = artifacts.board_randomness.get_a_cell(cell as u8);
                self.log_box_reveal(cell, &values);
                RevealPayload::Box(BoxReveal {
                    index: cell,
                    values,
                    randomness,
                })
            }
            ChallengeType::Clue => {
                let mut clue_payloads = Vec::with_capacity(clues.len());
                for &(row, col, _) in clues {
                    clue_payloads.push(ClueReveal {
                        row,
                        col,
                        mapped_value: artifacts.mapped_solution[row][col],
                        randomness: artifacts.board_randomness[row][col],
                    });
                }
                let response = ClueResponse {
                    mapping: artifacts.mapping.clone(),
                    mapping_randomness: artifacts.mapping_randomness.clone(),
                    clues: clue_payloads,
                };
                self.log_clue_reveal(&response);
                RevealPayload::Clue(response)
            }
        };

        ResponseMessage {
            round: round_idx,
            payload,
        }
    }

    fn apply_mapping(solution: &Matrix, mapping: &Vec<u8>) -> Matrix {
        let mut mapped = vec![vec![0u8; 9]; 9];
        for row in 0..9 {
            for col in 0..9 {
                let val = solution[row][col] as usize;
                mapped[row][col] = mapping[val];
            }
        }
        mapped
    }

    fn log_round_overview(
        &self,
        artifacts: &RoundArtifacts,
        clue_positions: &HashSet<(usize, usize)>,
    ) {
        let mapping_pairs = (1..=9)
            .map(|d| format!("{}->{}", d, artifacts.mapping[d as usize]))
            .collect::<Vec<_>>()
            .join(" ");
        prover_print!(format!("Digit mapping (orig->mapped): {}", mapping_pairs));
        prover_print!("  Mapping result board (orig->mapped, [] = clue)");
        let solution = self.sudo.get_solution();
        for row in 0..9 {
            if row % 3 == 0 {
                prover_print!("    ----------+-----------+----------");
            }
            let mut line = String::from("    ");
            for col in 0..9 {
                if col % 3 == 0 && col != 0 {
                    line.push_str("| ");
                }
                let orig_val = solution[row][col];
                let mapped = artifacts.mapping[orig_val as usize];
                let cell_repr = format!("{:>2}->{:<1}", orig_val, mapped);
                if clue_positions.contains(&(row, col)) {
                    line.push_str(&format!("[{}] ", cell_repr));
                } else {
                    line.push_str(&format!(" {}  ", cell_repr));
                }
            }
            prover_print!(line.trim_end().to_string());
        }
        prover_print!("    ----------+-----------+----------");
    }

    fn log_challenge_intro(&self, challenge: ChallengeType) {
        match challenge {
            ChallengeType::Row(idx) => {
                prover_print!(format!("Received ROW challenge for row {}", idx));
            }
            ChallengeType::Col(idx) => {
                prover_print!(format!("Received COL challenge for column {}", idx));
            }
            ChallengeType::Box(idx) => {
                prover_print!(format!("Received BOX challenge for box {}", idx));
            }
            ChallengeType::Clue => {
                prover_print!("Received CLUE challenge (all clue cells)");
            }
        }
    }

    fn log_row_reveal(&self, idx: usize, values: &[u8]) {
        let mut line = format!("  [ROW {}] |", idx);
        for (i, val) in values.iter().enumerate() {
            line.push_str(&format!(" {}", val));
            if (i + 1) % 3 == 0 {
                line.push_str(" |");
            }
        }
        prover_print!(line);
    }

    fn log_column_reveal(&self, idx: usize, values: &[u8]) {
        prover_print!(format!("  [COLUMN {}] top → bottom", idx));
        for (row, val) in values.iter().enumerate() {
            prover_print!(format!("    r {:>1} : {}", row, val));
            if row == 2 || row == 5 {
                prover_print!("    ------");
            }
        }
    }

    fn log_box_reveal(&self, idx: usize, values: &Vec<Vec<u8>>) {
        prover_print!(format!("  [BOX {}]", idx));
        prover_print!("    +-----+-----+-----+");
        for row in 0..3 {
            let mut line = String::from("    |");
            for col in 0..3 {
                line.push_str(&format!(" {} |", values[row][col]));
            }
            prover_print!(line);
            prover_print!("    +-----+-----+-----+");
        }
    }

    fn log_clue_reveal(&self, response: &ClueResponse) {
        prover_print!("  CLUE reveal details:");
        let mapping_pairs = (1..=9)
            .map(|d| format!("{}->{}", d, response.mapping[d as usize]))
            .collect::<Vec<_>>()
            .join(" ");
        prover_print!(format!("  Digit mapping: {}", mapping_pairs));
        prover_print!("  当前承诺棋盘（方括号表示已揭示格子）");

        let puzzle = self.sudo.get_puzzle();
        let mut clue_map: HashMap<(usize, usize), u8> = HashMap::new();
        for clue in &response.clues {
            clue_map.insert((clue.row, clue.col), clue.mapped_value);
        }

        for row in 0..9 {
            if row % 3 == 0 {
                prover_print!("    ----------+-----------+----------");
            }
            let mut line = String::from("    ");
            for col in 0..9 {
                if col % 3 == 0 && col != 0 {
                    line.push_str("| ");
                }
                if let Some(mapped) = clue_map.get(&(row, col)) {
                    let orig = puzzle[row][col];
                    line.push_str(&format!("[{:>1}->{:>1}] ", orig, mapped));
                } else {
                    line.push_str("   .   ");
                }
            }
            prover_print!(line.trim_end().to_string());
        }
        prover_print!("    ----------+-----------+----------");
    }

    pub fn run(&mut self) -> io::Result<()> {
        prover_print!(format!(
            "port: {}, host: {}, rounds: {}, clues: {}",
            &self.port, &self.host, &self.rounds, &self.clues)
        );

        self.init_puzzle();
        let mut stream = self.connect()?;

        let puzzle = self.sudo.get_puzzle();
        let clue_cells = self.clue_cells();
        let clue_count = clue_cells.len();
        let clue_positions: HashSet<(usize, usize)> =
            clue_cells.iter().map(|&(r, c, _)| (r, c)).collect();

        send_message(
            &mut stream,
            &ProverMessage::Puzzle(PuzzleMessage {
                puzzle: puzzle.clone(),
                clues: clue_count,
            }),
        )?;

        let ack = receive_message::<VerifierMessage>(&mut stream)?;
        let mut current_round = 0usize;
        match ack {
            VerifierMessage::PuzzleAck { rounds } => {
                if rounds != self.rounds {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "Verifier rounds mismatch",
                    ));
                }
            }
            VerifierMessage::Abort(reason) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("Verifier aborted: {}", reason),
                ));
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "Unexpected message after puzzle",
                ));
            }
        }

        // round loop
        while current_round < self.rounds {
            let (mut commitment, artifacts) = self.prepare_round();
            commitment.round = current_round;
            prover_print!(format!("=== Round {} ===", current_round + 1));
            self.log_round_overview(&artifacts, &clue_positions);
            send_message(&mut stream, &ProverMessage::Commitment(commitment.clone()))?;

            let challenge = loop {
                match receive_message::<VerifierMessage>(&mut stream)? {
                    VerifierMessage::Challenge { round, challenge } => {
                        if round != current_round {
                            return Err(Error::new(
                                ErrorKind::InvalidData,
                                "Challenge round mismatch",
                            ));
                        }
                        break challenge;
                    }
                    VerifierMessage::Abort(reason) => {
                        return Err(Error::new(
                            ErrorKind::Other,
                            format!("Verifier aborted: {}", reason),
                        ));
                    }
                    other => {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            format!("Unexpected message: {:?}", other),
                        ));
                    }
                }
            };
            self.log_challenge_intro(challenge);

            let response =
                self.respond_to_challenge(current_round, challenge, &artifacts, &clue_cells);
            send_message(&mut stream, &ProverMessage::Response(response))?;

            match receive_message::<VerifierMessage>(&mut stream)? {
                VerifierMessage::RoundResult {
                    round,
                    accepted,
                    reason,
                } => {
                    if round != current_round {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "Round result mismatch",
                        ));
                    }
                    if !accepted {
                        return Err(Error::new(
                            ErrorKind::Other,
                            reason.unwrap_or_else(|| "Round rejected".to_string()),
                        ));
                    }
                    prover_print!(format!("Round {} verified", current_round + 1));
                }
                VerifierMessage::Abort(reason) => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("Verifier aborted: {}", reason),
                    ));
                }
                other => {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        format!("Unexpected message: {:?}", other),
                    ));
                }
            }

            current_round += 1;

            println!();
        }

        match receive_message::<VerifierMessage>(&mut stream)? {
            VerifierMessage::FinalResult { accepted } => {
                if accepted {
                    prover_print!("Protocol completed successfully");
                } else {
                    return Err(Error::new(ErrorKind::Other, "Proof rejected"));
                }
            }
            VerifierMessage::Abort(reason) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("Verifier aborted: {}", reason),
                ));
            }
            other => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("Unexpected message at final stage: {:?}", other),
                ));
            }
        }
        
        Ok(())
    }
}

macro_rules! printusage {
    () => {
        eprintln!("Usage: prover <host> <port> <rounds> <clues>");
        eprintln!("Use - to use default values for host and clues.");
    };
}

fn parser(args: Vec<String>) -> Result<(), String> {
    if args.len() < 5 {
        printusage!();
    }

    let host = if args[1] == "-" {
        None
    } else {
        Some(args[1].clone())
    };

    let port = if args[2] == "-" {
        None
    } else {
        Some(args[2].clone())
    };

    let rounds = if args[3] == "-" {
        None
    } else {
        match args[3].parse::<usize>() {
            Ok(n) => Some(n),
            Err(_) => return Err("Invalid rounds value".to_string()),
        }
    };

    let clues: Option<i8> = if args[4] == "-" {
        None
    } else {
        match args[4].parse::<i8>() {
            Ok(n) => Some(n),
            Err(_) => return Err("Invalid clues value".to_string()),
        }
    };

    let mut prover = Prover::new(port, host, rounds, clues);
    prover.run().map_err(|e| e.to_string())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if let Err(err) = parser(args) {
        eprintln!("[Prover] {}", err);
    }
}

#[test]
fn test_parser() {
    let args = vec![
        "prover".to_string(),
        "-".to_string(),
        "9000".to_string(),
        "10".to_string(),
        "30".to_string(),
    ];
    parser(args).unwrap();
}
