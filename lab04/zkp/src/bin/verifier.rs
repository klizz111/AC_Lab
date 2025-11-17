#![allow(dead_code, unused_imports, unused_variables)]

use std::collections::HashMap;
use std::env;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::{self, ErrorKind};
use std::net::{TcpListener, TcpStream};

use zkp::challenge::{ChallengeType, random_challenge};
use zkp::networks::{
    BoxReveal, ClueResponse, CommitmentMessage, LineReveal, ProverMessage, ResponseMessage,
    RevealPayload, VerifierMessage, receive_message, send_message,
};
use zkp::soduku::commit::v_a_value;
use zkp::soduku::{CommitMat, Matrix, MatrixP};

macro_rules! printusage {
    () => {
        eprint!("Usage: verifier <port> <rounds>\n");
        eprint!("Pass <-> to use default opt");
    };
}

macro_rules! verifier_print {
    ($exp:expr) => {
        println!("[Verifier] {}", $exp);
    };
}

/// - `port`: 8899
/// - `rounds`: 10
struct Verifier {
    port: String,
    rounds: usize,
    puzzle: Matrix,
    clues: Vec<(usize, usize, u8)>,
}

impl Verifier {
    pub fn new(port_: Option<String>, rounds_: Option<usize>) -> Self {
        Verifier {
            port: port_.unwrap_or("8899".to_string()),
            rounds: rounds_.unwrap_or(10),
            puzzle: vec![vec![0u8; 9]; 9],
            clues: Vec::new(),
        }
    }

    pub fn run(&mut self) -> io::Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.port))?;
        verifier_print!(format!(
            "Listening on port {} (rounds = {})",
            self.port, self.rounds
        ));
        let (mut stream, addr) = listener.accept()?;
        verifier_print!(format!("Prover connected from {}", addr));
        stream.set_nodelay(true).ok();

        self.handle_session(&mut stream)
    }

    fn handle_session(&mut self, stream: &mut TcpStream) -> io::Result<()> {
        let puzzle_msg = match receive_message::<ProverMessage>(stream)? {
            ProverMessage::Puzzle(msg) => msg,
            ProverMessage::Abort(reason) => {
                return Err(io::Error::new(
                    ErrorKind::Other,
                    format!("Prover aborted early: {}", reason),
                ));
            }
            other => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    format!("Expected puzzle, got {:?}", other),
                ));
            }
        };

        self.puzzle = puzzle_msg.puzzle.clone();
        self.clues = self.collect_clues();
        verifier_print!(format!("Puzzle received ({} clues).", self.clues.len()));
        self.puzzle.print();
        send_message(
            stream,
            &VerifierMessage::PuzzleAck {
                rounds: self.rounds,
            },
        )?;

        for round in 0..self.rounds {
            verifier_print!(format!("=== Round {} ===", round + 1));

            let commitment = match receive_message::<ProverMessage>(stream)? {
                ProverMessage::Commitment(msg) => {
                    if msg.round != round {
                        return Err(io::Error::new(
                            ErrorKind::InvalidData,
                            "Commitment round mismatch",
                        ));
                    }
                    verifier_print!("Received commitment");
                    msg
                }
                ProverMessage::Abort(reason) => {
                    return Err(io::Error::new(
                        ErrorKind::Other,
                        format!("Prover aborted: {}", reason),
                    ));
                }
                other => {
                    return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        format!("Expected commitment, got {:?}", other),
                    ));
                }
            };

            let challenge = random_challenge(9);
            self.log_challenge_request(challenge);
            send_message(stream, &VerifierMessage::Challenge { round, challenge })?;

            let response = match receive_message::<ProverMessage>(stream)? {
                ProverMessage::Response(resp) => resp,
                ProverMessage::Abort(reason) => {
                    return Err(io::Error::new(
                        ErrorKind::Other,
                        format!("Prover aborted: {}", reason),
                    ));
                }
                other => {
                    return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        format!("Expected response, got {:?}", other),
                    ));
                }
            };
            self.log_payload_details(challenge, &response.payload);

            let (accepted, reason) = self.verify_round(&commitment, &response, challenge);
            send_message(
                stream,
                &VerifierMessage::RoundResult {
                    round,
                    accepted,
                    reason: reason.clone(),
                },
            )?;
            if !accepted {
                send_message(stream, &VerifierMessage::FinalResult { accepted: false })?;
                return Err(io::Error::new(
                    ErrorKind::Other,
                    reason.unwrap_or_else(|| "Verification failed".to_string()),
                ));
            }
            verifier_print!(format!("Round {} verified", round + 1));
            println!("");
        }

        send_message(stream, &VerifierMessage::FinalResult { accepted: true })?;
        verifier_print!("Proof accepted.");
        Ok(())
    }

    fn log_challenge_request(&self, challenge: ChallengeType) {
        match challenge {
            ChallengeType::Row(idx) => {
                verifier_print!(format!("Issuing ROW challenge for row {}", idx));
            }
            ChallengeType::Col(idx) => {
                verifier_print!(format!("Issuing COL challenge for column {}", idx));
            }
            ChallengeType::Box(idx) => {
                verifier_print!(format!("Issuing BOX challenge for box {}", idx));
            }
            ChallengeType::Clue => {
                verifier_print!("Issuing CLUE challenge (all clue cells)");
            }
        }
    }

    fn log_payload_details(&self, challenge: ChallengeType, payload: &RevealPayload) {
        match (challenge, payload) {
            (ChallengeType::Row(idx), RevealPayload::Row(line)) => {
                self.log_row_values(idx, &line.values);
            }
            (ChallengeType::Col(idx), RevealPayload::Col(line)) => {
                self.log_column_values(idx, &line.values);
            }
            (ChallengeType::Box(idx), RevealPayload::Box(cell)) => {
                self.log_box_values(idx, &cell.values);
            }
            (ChallengeType::Clue, RevealPayload::Clue(data)) => {
                self.log_clue_payload(data);
            }
            _ => {
                verifier_print!("  (Response payload mismatched challenge)");
            }
        }
    }

    fn log_row_values(&self, idx: usize, values: &[u8]) {
        let mut line = format!("  [ROW {}] |", idx);
        for (i, val) in values.iter().enumerate() {
            line.push_str(&format!(" {}", val));
            if (i + 1) % 3 == 0 {
                line.push_str(" |");
            }
        }
        verifier_print!(line);
    }

    fn log_column_values(&self, idx: usize, values: &[u8]) {
        verifier_print!(format!("  [COLUMN {}] top → bottom", idx));
        for (row, val) in values.iter().enumerate() {
            verifier_print!(format!("    r {:>1} : {}", row, val));
            if row == 2 || row == 5 {
                verifier_print!("    ------");
            }
        }
    }

    fn log_box_values(&self, idx: usize, values: &Vec<Vec<u8>>) {
        verifier_print!(format!("  [BOX {}]", idx));
        verifier_print!("    +-----+-----+-----+");
        for row in 0..3 {
            let mut line = String::from("    |");
            for col in 0..3 {
                line.push_str(&format!(" {} |", values[row][col]));
            }
            verifier_print!(line);
            verifier_print!("    +-----+-----+-----+");
        }
    }

    fn log_clue_payload(&self, data: &ClueResponse) {
        let mapping_pairs = (1..=9)
            .map(|d| format!("{}->{}", d, data.mapping[d as usize]))
            .collect::<Vec<_>>()
            .join(" ");
        verifier_print!(format!("  Digit mapping (orig->mapped): {}", mapping_pairs));
        verifier_print!("  Mapping result board (orig->mapped, [] = clue, '.'=unknown)");

        let mut clue_map: HashMap<(usize, usize), u8> = HashMap::new();
        for clue in &data.clues {
            clue_map.insert((clue.row, clue.col), clue.mapped_value);
        }

        for row in 0..9 {
            if row % 3 == 0 {
                verifier_print!("    ----------+-----------+----------");
            }
            let mut line = String::from("    ");
            for col in 0..9 {
                if col % 3 == 0 && col != 0 {
                    line.push_str("| ");
                }
                if let Some(mapped) = clue_map.get(&(row, col)) {
                    let orig = self.puzzle[row][col];
                    line.push_str(&format!("[{:>1}->{:>1}] ", orig, mapped));
                } else {
                    line.push_str("   .   ");
                }
            }
            verifier_print!(line.trim_end().to_string());
        }
        verifier_print!("    ----------+-----------+----------");
    }

    fn collect_clues(&self) -> Vec<(usize, usize, u8)> {
        let mut res = Vec::new();
        for (row, line) in self.puzzle.iter().enumerate() {
            for (col, &val) in line.iter().enumerate() {
                if val != 0 {
                    res.push((row, col, val));
                }
            }
        }
        res
    }

    fn verify_round(
        &self,
        commitment: &CommitmentMessage,
        response: &ResponseMessage,
        challenge: ChallengeType,
    ) -> (bool, Option<String>) {
        if response.round != commitment.round {
            return (false, Some("Response round mismatch".to_string()));
        }

        match (&challenge, &response.payload) {
            (ChallengeType::Row(idx), RevealPayload::Row(line)) => {
                self.verify_row(*idx, line, &commitment.board_commit)
            }
            (ChallengeType::Col(idx), RevealPayload::Col(line)) => {
                self.verify_column(*idx, line, &commitment.board_commit)
            }
            (ChallengeType::Box(idx), RevealPayload::Box(cell)) => {
                self.verify_box(*idx, cell, &commitment.board_commit)
            }
            (ChallengeType::Clue, RevealPayload::Clue(data)) => {
                self.verify_clues(data, &commitment.board_commit, &commitment.mapping_commit)
            }
            _ => (false, Some("Challenge/response type mismatch".to_string())),
        }
    }

    fn verify_row(
        &self,
        idx: usize,
        reveal: &LineReveal,
        board_commit: &CommitMat,
    ) -> (bool, Option<String>) {
        if reveal.index != idx || reveal.values.len() != 9 || reveal.randomness.len() != 9 {
            return (false, Some("Row reveal malformed".to_string()));
        }
        if !Self::is_1_9(&reveal.values) {
            return (false, Some("Row violates Sudoku constraint".to_string()));
        }
        for col in 0..9 {
            if !v_a_value(
                reveal.values[col],
                reveal.randomness[col],
                board_commit[idx][col],
            ) {
                return (
                    false,
                    Some(format!("Row commitment mismatch at col {}", col)),
                );
            }
        }
        (true, None)
    }

    fn verify_column(
        &self,
        idx: usize,
        reveal: &LineReveal,
        board_commit: &CommitMat,
    ) -> (bool, Option<String>) {
        if reveal.index != idx || reveal.values.len() != 9 || reveal.randomness.len() != 9 {
            return (false, Some("Column reveal malformed".to_string()));
        }
        if !Self::is_1_9(&reveal.values) {
            return (false, Some("Column violates Sudoku constraint".to_string()));
        }
        for row in 0..9 {
            if !v_a_value(
                reveal.values[row],
                reveal.randomness[row],
                board_commit[row][idx],
            ) {
                return (
                    false,
                    Some(format!("Column commitment mismatch at row {}", row)),
                );
            }
        }
        (true, None)
    }

    fn verify_box(
        &self,
        idx: usize,
        reveal: &BoxReveal,
        board_commit: &CommitMat,
    ) -> (bool, Option<String>) {
        if reveal.index != idx {
            return (false, Some("Box index mismatch".to_string()));
        }
        let mut values = Vec::with_capacity(9);
        for row in 0..3 {
            if reveal.values[row].len() != 3 || reveal.randomness[row].len() != 3 {
                return (false, Some("Box shape invalid".to_string()));
            }
            for col in 0..3 {
                values.push(reveal.values[row][col]);
            }
        }
        if !Self::is_1_9(&values) {
            return (false, Some("Box violates Sudoku constraint".to_string()));
        }

        let start_row = (idx / 3) * 3;
        let start_col = (idx % 3) * 3;
        for i in 0..3 {
            for j in 0..3 {
                if !v_a_value(
                    reveal.values[i][j],
                    reveal.randomness[i][j],
                    board_commit[start_row + i][start_col + j],
                ) {
                    return (false, Some("Box commitment mismatch".to_string()));
                }
            }
        }
        (true, None)
    }

    fn verify_clues(
        &self,
        reveal: &ClueResponse,
        board_commit: &CommitMat,
        mapping_commit: &Vec<u64>,
    ) -> (bool, Option<String>) {
        if reveal.mapping.len() != mapping_commit.len()
            || reveal.mapping_randomness.len() != mapping_commit.len()
        {
            return (false, Some("Mapping reveal malformed".to_string()));
        }
        for i in 0..mapping_commit.len() {
            if !v_a_value(
                reveal.mapping[i],
                reveal.mapping_randomness[i],
                mapping_commit[i],
            ) {
                return (
                    false,
                    Some(format!("Mapping commitment mismatch at digit {}", i)),
                );
            }
        }

        for &(row, col, orig_val) in &self.clues {
            match reveal.clues.iter().find(|c| c.row == row && c.col == col) {
                Some(clue) => {
                    let mapped = reveal.mapping[orig_val as usize];
                    if mapped != clue.mapped_value {
                        return (false, Some("Clue mapping inconsistent".to_string()));
                    }
                    if !v_a_value(clue.mapped_value, clue.randomness, board_commit[row][col]) {
                        return (false, Some("Clue commitment mismatch".to_string()));
                    }
                }
                None => {
                    return (false, Some("Missing clue reveal".to_string()));
                }
            }
        }

        (true, None)
    }

    fn is_1_9(values: &Vec<u8>) -> bool {
        let mut sorted = values.clone();
        sorted.sort();
        sorted == (1u8..=9).collect::<Vec<u8>>()
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        printusage!();
        return;
    }

    let port = if args[1] == "-" {
        None
    } else {
        Some(args[1].clone())
    };

    let rounds = if args[2] == "-" {
        None
    } else {
        match args[2].parse::<usize>() {
            Ok(r) => Some(r),
            Err(_) => {
                printusage!();
                return;
            }
        }
    };

    let mut verifier = Verifier::new(port, rounds);
    if let Err(err) = verifier.run() {
        verifier_print!(format!("Protocol failed: {}", err));
    }
}
