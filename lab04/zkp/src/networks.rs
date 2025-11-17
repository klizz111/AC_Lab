use std::io::{self, Read, Write};
use std::net::TcpStream;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::challenge::ChallengeType;
use crate::soduku::{CommitMat, Matrix};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PuzzleMessage {
    pub puzzle: Matrix,
    pub clues: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CommitmentMessage {
    pub round: usize,
    pub board_commit: CommitMat,
    pub mapping_commit: Vec<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LineReveal {
    pub index: usize,
    pub values: Vec<u8>,
    pub randomness: Vec<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BoxReveal {
    pub index: usize,
    pub values: Matrix,
    pub randomness: CommitMat,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ClueReveal {
    pub row: usize,
    pub col: usize,
    pub mapped_value: u8,
    pub randomness: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ClueResponse {
    pub mapping: Vec<u8>,
    pub mapping_randomness: Vec<u64>,
    pub clues: Vec<ClueReveal>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum RevealPayload {
    Row(LineReveal),
    Col(LineReveal),
    Box(BoxReveal),
    Clue(ClueResponse),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ResponseMessage {
    pub round: usize,
    pub payload: RevealPayload,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ProverMessage {
    Puzzle(PuzzleMessage),
    Commitment(CommitmentMessage),
    Response(ResponseMessage),
    Abort(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum VerifierMessage {
    PuzzleAck {
        rounds: usize,
    },
    Challenge {
        round: usize,
        challenge: ChallengeType,
    },
    RoundResult {
        round: usize,
        accepted: bool,
        reason: Option<String>,
    },
    FinalResult {
        accepted: bool,
    },
    Abort(String),
}

pub fn send_message<T: Serialize>(stream: &mut TcpStream, message: &T) -> io::Result<()> {
    let payload = bincode::serde::encode_to_vec(message, bincode::config::standard())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("encode error: {e}")))?;
    let len = payload.len() as u32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&payload)?;
    Ok(())
}

pub fn receive_message<T: DeserializeOwned>(stream: &mut TcpStream) -> io::Result<T> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    let (message, _): (T, _) =
        bincode::serde::decode_from_slice(&payload, bincode::config::standard())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("decode error: {e}")))?;
    Ok(message)
}

#[derive(Debug)]
pub enum NetworkSide {
    Prover,
    Verifier,
}

pub fn send_abort(stream: &mut TcpStream, side: NetworkSide, reason: impl Into<String>) {
    let msg = reason.into();
    let _ = match side {
        NetworkSide::Prover => send_message(stream, &ProverMessage::Abort(msg)),
        NetworkSide::Verifier => send_message(stream, &VerifierMessage::Abort(msg)),
    };
}
