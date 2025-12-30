use std::{
    process::{Command, Stdio},
    thread,
    time::Duration,
};

#[test]
fn full_test() {
    let scene = vec![(0, 0), (0, 1), (1, 0), (1, 1)];
    let scene2 = scene.clone();

    for (x, y) in scene {
        for (a, b) in &scene2 {
            let _garbler = Command::new("cargo")
                .args([
                    "run",
                    "--bin",
                    "garbler",
                    "--",
                    "--input-a",
                    &a.to_string(),
                    "--input-b",
                    &b.to_string(),
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .expect("Failed to start garbler process");

            thread::sleep(Duration::from_secs(1));

            let evaluater = Command::new("cargo")
                .args([
                    "run",
                    "--bin",
                    "evaluater",
                    "--",
                    "--input-x",
                    &x.to_string(),
                    "--input-y",
                    &y.to_string(),
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .expect("Failed to start evaluater process");

            let output = evaluater.wait_with_output().expect("Failed to read stdout");
            let out = String::from_utf8_lossy(&output.stdout);

            let z = out
                .lines()
                .last() //  "Computation result z = 0"
                .and_then(|line| line.split("=").last()) // " 0"
                .and_then(|val| val.trim().parse::<i32>().ok()) // 0
                .expect("Failed to parse output");
            // a ⊕ ( (b ⊕ x) & y)
            println!("{} ⊕ (({} ⊕ {})& {}) = {}", x, y, x, y, z);
            assert_eq!(z, a ^ ((b ^ x) & y));
        }
    }
}
