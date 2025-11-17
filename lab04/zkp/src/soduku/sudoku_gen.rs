// Sudoku 生成
#![allow(dead_code, unused_imports, unused_variables)]

pub struct Sudoku {
    pub solution: Vec<Vec<u8>>,
    pub puzzle: Vec<Vec<u8>>,
    pub cast: Vec<u8>, // 映射
}

impl Sudoku {
    pub fn new() -> Sudoku {
        Sudoku {
            solution: vec![vec![0u8; 9]; 9],
            puzzle: vec![vec![0u8; 9]; 9],
            cast: (0..=9).collect(), // 下标0不使用
        }
    }

    pub fn print_it(&self, which: i8) {
        let mat = match which {
            0 => &self.solution,
            1 => &self.puzzle,
            _ => {
                println!("Invalid option");
                return;
            }
        };

        let mut _num: u8 = 0;
        for row in 0..9 {
            for val in 0..9 {
                if val % 3 == 0 && val != 0 {
                    print!("| ");
                }
                if row % 3 == 0 && val == 0 {
                    println!("---------------------");
                }
                _num = mat[row][val];
                if _num == 0 {
                    print!("- ");
                } else {
                    print!("{} ", mat[row][val]);
                }
                if row == 8 && val == 8 {
                    println!();
                    println!("---------------------");
                    println!();
                }
            }
            println!();
        }
    }

    fn base_mod(&mut self) {
        self.solution = vec![vec![0u8; 9]; 9];

        for row in 0..9 {
            for col in 0..9 {
                self.solution[row][col] = ((row * 3 + row / 3 + col) % 9 + 1) as u8;
            }
        }
    }

    fn full_mod(&mut self) {
        use rand::rng;
        use rand::seq::SliceRandom;

        let mut rng = rng();

        // 步骤1 + 3：行带打乱
        let mut row_indices: Vec<usize> = Vec::with_capacity(9);
        let mut row_bands = vec![0usize, 1, 2];
        row_bands.shuffle(&mut rng);
        for &band in &row_bands {
            let mut inner = vec![0usize, 1, 2];
            inner.shuffle(&mut rng);
            for &i in &inner {
                row_indices.push(band * 3 + i);
            }
        }

        // 步骤2 + 4：列带打乱
        let mut col_indices: Vec<usize> = Vec::with_capacity(9);
        let mut col_bands = vec![0usize, 1, 2];
        col_bands.shuffle(&mut rng);
        for &band in &col_bands {
            let mut inner = vec![0usize, 1, 2];
            inner.shuffle(&mut rng);
            for &i in &inner {
                col_indices.push(band * 3 + i);
            }
        }

        // 步骤5：随机数字映射 1..9
        let mut digits: Vec<u8> = (1u8..=9).collect();
        digits.shuffle(&mut rng);

        let mut map = vec![0u8; 10];
        for (i, &d) in digits.iter().enumerate() {
            map[i + 1] = d;
        }

        // 根据 row_indices, col_indices 和 map 构造新的 solution
        let mut new_solution = vec![vec![0u8; 9]; 9];
        for (r_new, &r_old) in row_indices.iter().enumerate() {
            for (c_new, &c_old) in col_indices.iter().enumerate() {
                let v = self.solution[r_old][c_old] as usize;
                new_solution[r_new][c_new] = map[v];
            }
        }

        self.solution = new_solution;
        self.puzzle = self.solution.clone();
    }

    fn gen_puzzle(&mut self, clues: Option<usize>) {
        use rand::rng;
        use rand::seq::SliceRandom;

        let clues = clues.unwrap_or(30);

        self.puzzle = self.solution.clone();

        let mut rng = rng();
        let total_cells: usize = 81;
        let cells_to_remove = total_cells.saturating_sub(clues);

        let mut positions: Vec<usize> = (0..total_cells).collect();
        positions.shuffle(&mut rng);

        for &pos in positions.iter().take(cells_to_remove) {
            let row = pos / 9;
            let col = pos % 9;
            self.puzzle[row][col] = 0;
        }
    }

    pub fn init(&mut self, clues: Option<usize>) {
        self.base_mod();
        self.full_mod();
        self.gen_puzzle(clues);
    }

    pub fn gen_cast(&mut self) -> Vec<u8> {
        use rand::rng;
        use rand::seq::SliceRandom;

        let mut rng = rng();
        self.cast[1..].shuffle(&mut rng);

        return self.cast.clone();
    }

    pub fn get_solution(&self) -> Vec<Vec<u8>> {
        self.solution.clone()
    }

    pub fn get_puzzle(&self) -> Vec<Vec<u8>> {
        self.puzzle.clone()
    }

    pub fn get_cast(&self) -> Vec<u8> {
        self.cast.clone()
    }
}

// test block
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sudoku_generation() {
        let mut sudoku = Sudoku::new();
        sudoku.init(Some(30));

        sudoku.print_it(0);
        sudoku.print_it(1);
    }

    #[test]
    fn test_gen_cast() {
        let mut sudoku = Sudoku::new();
        let cast = sudoku.gen_cast();
        println!("Generated cast: {:?}", cast);
    }
}
