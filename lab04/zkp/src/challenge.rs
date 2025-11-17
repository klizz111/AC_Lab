#[derive(Debug, Clone, Copy)]
pub enum ChallengeType { Row(usize), Col(usize), Box(usize), Clue } 

pub fn random_challenge(n: usize) -> ChallengeType {
    use rand::Rng;
    let mut rng = rand::rng();
    match rng.random_range(0..4) {
        0 => ChallengeType::Row(rng.random_range(0..n)),
        1 => ChallengeType::Col(rng.random_range(0..n)),
        2 => ChallengeType::Box(rng.random_range(0..n)),
        _ => ChallengeType::Clue,
    }
}

#[test]
fn test_random_challenge() {
    for _ in 1..10 {
        let c = random_challenge(9);
        println!("{:?}", c);
    }
}