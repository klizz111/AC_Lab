use crate::soduku::{CommitMat, Matrix};
use rand::Rng;
use std::hash::{DefaultHasher, Hash, Hasher};

// 全矩阵承诺
pub trait MatCommit {
    fn commit(&self) -> (CommitMat, CommitMat)
    where
        Self: Sized;
    fn verify(&self, commited: &CommitMat, random: &CommitMat) -> bool;
    fn get_a_cell(&self, cell_no: u8) -> Vec<Vec<u8>>;
}

impl MatCommit for Matrix {
    fn commit(&self) -> (CommitMat, CommitMat) {
        let mut commited_mat: CommitMat = vec![vec![0u64; 9]; 9];
        let mut random_mat: CommitMat = vec![vec![0u64; 9]; 9];
        let mut rng = rand::rng();

        for row in 0..9 {
            for col in 0..9 {
                let mut hasher = DefaultHasher::new();
                let rand_val: u64 = rng.random_range(1..=u64::MAX);
                random_mat[row][col] = rand_val;
                let hash_input = (self[row][col], rand_val);
                hash_input.hash(&mut hasher);
                commited_mat[row][col] = hasher.finish() as u64;
            }
        }

        (commited_mat.clone(), random_mat.clone())
    }

    fn verify(&self, commited: &CommitMat, random: &CommitMat) -> bool {
        for row in 0..9 {
            for col in 0..9 {
                let mut hasher = DefaultHasher::new();
                let hash_input = (self[row][col], random[row][col]);
                hash_input.hash(&mut hasher);
                let computed_hash = hasher.finish() as u64;
                if computed_hash != commited[row][col] {
                    return false;
                }
            }
        }

        true
    }

    fn get_a_cell(&self, cell_no: u8) -> Vec<Vec<u8>> {
        let mut cell: Vec<Vec<u8>> = vec![vec![0u8; 3]; 3];
        let start_row = (cell_no / 3) * 3;
        let start_col = (cell_no % 3) * 3;

        for i in 0..3 {
            for j in 0..3 {
                cell[i as usize][j as usize] =
                    self[(start_row + i) as usize][(start_col + j) as usize];
            }
        }

        cell
    }
}

// 投影承诺
pub trait CastCommit {
    fn commit(&self) -> (Vec<u64>, Vec<u64>);
    fn verify(&self, commited: &Vec<u64>, random: &Vec<u64>) -> bool;
}

impl CastCommit for Vec<u8> {
    fn commit(&self) -> (Vec<u64>, Vec<u64>) {
        let mut commited_vec: Vec<u64> = vec![0u64; self.len()];
        let mut random_vec: Vec<u64> = vec![0u64; self.len()];

        let mut rng = rand::rng();

        for i in 0..self.len() {
            let mut hasher = DefaultHasher::new();
            let rand_val: u64 = rng.random_range(1..=u64::MAX);
            random_vec[i] = rand_val;
            let hash_input = (self[i], rand_val);
            hash_input.hash(&mut hasher);
            commited_vec[i] = hasher.finish() as u64;
        }

        (commited_vec.clone(), random_vec.clone())
    }

    fn verify(&self, commited: &Vec<u64>, random: &Vec<u64>) -> bool {
        for i in 0..self.len() {
            let mut hasher = DefaultHasher::new();
            let hash_input = (self[i], random[i]);
            hash_input.hash(&mut hasher);
            let computed_hash = hasher.finish() as u64;
            if computed_hash != commited[i] {
                return false;
            }
        }

        true
    }
}

pub trait CommitMat_ {
    fn get_a_cell(&self, cell_no: u8) -> Vec<Vec<u64>>;
}
impl CommitMat_ for CommitMat {
    fn get_a_cell(&self, cell_no: u8) -> Vec<Vec<u64>> {
        let mut cell: Vec<Vec<u64>> = vec![vec![0u64; 3]; 3];
        let start_row = (cell_no / 3) * 3;
        let start_col = (cell_no % 3) * 3;

        for i in 0..3 {
            for j in 0..3 {
                cell[i as usize][j as usize] =
                    self[(start_row + i) as usize][(start_col + j) as usize];
            }
        }

        cell
    }
}

pub fn v_a_line(cmmt: &Vec<u64>, rand: &Vec<u64>, line: &Vec<u8>) -> bool {
    // 验证 1 line 的承诺是否正确
    for i in 0..9 {
        let mut hasher = DefaultHasher::new();
        let hash_in = (line[i], rand[i]);
        hash_in.hash(&mut hasher);
        let computed_hash = hasher.finish() as u64;
        if computed_hash != cmmt[i] {
            return false;
        }
    }

    true
}

pub fn v_a_cell(cmmt: &Vec<Vec<u64>>, rand: &Vec<Vec<u64>>, mat: &Matrix) -> bool {
    // 验证 1 cell 的承诺是否正确
    for i in 0..3 {
        for j in 0..3 {
            let mut hasher = DefaultHasher::new();
            let hash_in = (mat[i][j], rand[i][j]);
            hash_in.hash(&mut hasher);
            let computed_hash = hasher.finish() as u64;
            if computed_hash != cmmt[i][j] {
                return false;
            }
        }
    }

    true
}

pub fn v_a_value(value: u8, random: u64, commt: u64) -> bool {
    // 验证 1 个值的承诺是否正确
    let mut hasher = DefaultHasher::new();
    let hash_in = (value, random);
    hash_in.hash(&mut hasher);
    let computed_hash = hasher.finish() as u64;
    if computed_hash != commt {
        return false;
    }

    true
}
#[test]
fn test_commit() {
    use crate::soduku::sudoku_gen::Sudoku;
    let mut sudoku = Sudoku::new();
    sudoku.init(Some(30));
    let original_mat = sudoku.get_solution();
    let (commited_mat, random_mat) = original_mat.commit();
    print!("Original Matrix: {:?}\n", original_mat);
    print!("Commited Matrix: {:?}\n", commited_mat);
    print!("Random Matrix: {:?}\n", random_mat);

    assert!(original_mat.verify(&commited_mat, &random_mat));

    let original_cast = sudoku.get_cast();
    let (commited_cast, random_cast) = original_cast.commit();
    print!("Original Cast: {:?}\n", original_cast);
    print!("Commited Cast: {:?}\n", commited_cast);
    print!("Random Cast: {:?}\n", random_cast);

    assert!(original_cast.verify(&commited_cast, &random_cast));

    assert!(v_a_line(
        &commited_cast[0..9].to_vec(),
        &random_cast[0..9].to_vec(),
        &original_cast[0..9].to_vec()
    ));

    let cell_no = 4;
    let cell_mat = original_mat.get_a_cell(cell_no);
    let cell_cmmt = commited_mat.get_a_cell(cell_no);
    let cell_rand = random_mat.get_a_cell(cell_no);
    assert!(v_a_cell(&cell_cmmt, &cell_rand, &cell_mat));
}
