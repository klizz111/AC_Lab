pub mod commit;
pub mod sudoku_gen;
pub type Matrix = Vec<Vec<u8>>;
pub type CommitMat = Vec<Vec<u64>>;

pub trait MatrixP {
    fn print(&self);
}

impl MatrixP for Matrix {
    fn print(&self) {
        for row in 0..9 {
            for val in 0..9 {
                if val % 3 == 0 && val != 0 {
                    print!("| ");
                }
                if row % 3 == 0 && val == 0 {
                    println!("---------------------");
                }
                if self[row][val] == 0 {
                    print!("- ");
                } else {
                    print!("{} ", self[row][val]);
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
}

#[test]

fn test_print_matrix() {
    let mat: Matrix = vec![
        vec![5, 3, 0, 0, 7, 0, 0, 0, 0],
        vec![6, 0, 0, 1, 9, 5, 0, 0, 0],
        vec![0, 9, 8, 0, 0, 0, 0, 6, 0],
        vec![8, 0, 0, 0, 6, 0, 0, 0, 3],
        vec![4, 0, 0, 8, 0, 3, 0, 0, 1],
        vec![7, 0, 0, 0, 2, 0, 0, 0, 6],
        vec![0, 6, 0, 0, 0, 0, 2, 8, 0],
        vec![0, 0, 0, 4, 1, 9, 0, 0, 5],
        vec![0, 0, 0, 0, 8, 0, 0, 7, 9],
    ];
    mat.print();
}
