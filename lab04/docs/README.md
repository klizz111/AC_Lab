# 高级密码第04次实验报告

### 系统环境

```sh
 Virtualization: wsl
 Operating System: Ubuntu 24.04.2 LTS                      
Kernel: Linux 5.15.153.1-microsoft-standard-WSL2
 Architecture: x86-64
```



##  1.  数独零知识证明



## 环境依赖

```shell
rustc 1.91.0 (f8297e351 2025-10-28)
cargo 1.91.0 (ea2d97820 2025-10-10)
rustup 1.28.2 (e4f3ad6f8 2025-04-28)
```

### 项目结构

```shell
zkp
├── Cargo.toml
├── compile.sh
├── install.sh
├── src
│   ├── bin
│   │   ├── prover.rs # prover 主程序
│   │   └── verifier.rs # verifier 主程序
│   ├── challenge.rs # 挑战对象相关
│   ├── lib.rs
│   ├── networks.rs # 网络通信实现
│   └── soduku
│       ├── commit.rs # 数独承诺与验证
│       ├── mod.rs 
│       └── sudoku_gen.rs # 数独对象生成
├── test.sh
```

### 项目编译

```shell
# install.sh
cargo install --path . --root ./bin
# 最后生成的文件在zkp/bin/bin下
tree ./bin
./bin
└── bin
    ├── prover
    └── verifier
```

### 程序运行

1. 直接运行

   ```sh
   $ ./bin/bin/prover
   Usage: prover <host> <port> <rounds> <clues>
   Use - to use default values for host and clues.
   $ ./bin/bin/verifier 
   Usage: verifier <port> <rounds>
   Pass <-> to use default opt
   ```

2. 进行5轮测试

   ```sh
   # 运行
   # test.sh
   ./bin/bin/verifier - 5 > verifier_log.txt &
   
   ./bin/bin/prover - - 5 - > prover_log.txt &
   
   wait
   ```

   ```sh
   # Prover输出
   $ cat ./prover_log.txt
   [Prover] port: 8899, host: 127.0.0.1, rounds: 5, clues: 30
   [Prover] Generated puzzle with 30 clues
   [Prover] Puzzle preview:
   ---------------------
   - 7 - | 2 - - | - 4 9 
   - - - | 3 - 8 | - - - 
   - - - | - - 1 | 8 3 7 
   ---------------------
   - 1 - | 5 - 2 | 4 - - 
   - - - | 9 6 - | 3 7 - 
   4 - - | 7 - - | - 5 8 
   ---------------------
   - - - | 1 - - | 5 - - 
   - 4 - | - - 5 | 9 - - 
   5 - 8 | - - - | - - 4 
   ---------------------
   
   
   [Prover] Connected to verifier at 127.0.0.1:8899 after 1 attempt(s)
   [Prover] Running at 127.0.0.1:48176
   [Prover] === Round 1 ===
   [Prover] Digit mapping (orig->mapped): 1->5 2->4 3->2 4->1 5->7 6->6 7->9 8->8 9->3
   [Prover]   Mapping result board (orig->mapped, [] = clue)
   [Prover]     ----------+-----------+----------
   [Prover]       8->8  [ 7->9]   3->2  | [ 2->4]   5->7    6->6  |   1->5  [ 4->1] [ 9->3]
   [Prover]       1->5    9->3    4->1  | [ 3->2]   7->9  [ 8->8] |   6->6    2->4    5->7
   [Prover]       6->6    5->7    2->4  |   4->1    9->3  [ 1->5] | [ 8->8] [ 3->2] [ 7->9]
   [Prover]     ----------+-----------+----------
   [Prover]       3->2  [ 1->5]   7->9  | [ 5->7]   8->8  [ 2->4] | [ 4->1]   9->3    6->6
   [Prover]       2->4    8->8    5->7  | [ 9->3] [ 6->6]   4->1  | [ 3->2] [ 7->9]   1->5
   [Prover]     [ 4->1]   6->6    9->3  | [ 7->9]   1->5    3->2  |   2->4  [ 5->7] [ 8->8]
   [Prover]     ----------+-----------+----------
   [Prover]       9->3    2->4    6->6  | [ 1->5]   4->1    7->9  | [ 5->7]   8->8    3->2
   [Prover]       7->9  [ 4->1]   1->5  |   8->8    3->2  [ 5->7] | [ 9->3]   6->6    2->4
   [Prover]     [ 5->7]   3->2  [ 8->8] |   6->6    2->4    9->3  |   7->9    1->5  [ 4->1]
   [Prover]     ----------+-----------+----------
   [Prover] Received CLUE challenge (all clue cells)
   [Prover]   CLUE reveal details:
   [Prover]   Digit mapping: 1->5 2->4 3->2 4->1 5->7 6->6 7->9 8->8 9->3
   [Prover]   当前承诺棋盘（方括号表示已揭示格子）
   [Prover]     ----------+-----------+----------
   [Prover]        .   [7->9]    .   | [2->4]    .      .   |    .   [4->1] [9->3]
   [Prover]        .      .      .   | [3->2]    .   [8->8] |    .      .      .
   [Prover]        .      .      .   |    .      .   [1->5] | [8->8] [3->2] [7->9]
   [Prover]     ----------+-----------+----------
   [Prover]        .   [1->5]    .   | [5->7]    .   [2->4] | [4->1]    .      .
   [Prover]        .      .      .   | [9->3] [6->6]    .   | [3->2] [7->9]    .
   [Prover]     [4->1]    .      .   | [7->9]    .      .   |    .   [5->7] [8->8]
   [Prover]     ----------+-----------+----------
   [Prover]        .      .      .   | [1->5]    .      .   | [5->7]    .      .
   [Prover]        .   [4->1]    .   |    .      .   [5->7] | [9->3]    .      .
   [Prover]     [5->7]    .   [8->8] |    .      .      .   |    .      .   [4->1]
   [Prover]     ----------+-----------+----------
   [Prover] Round 1 verified
   
   [Prover] === Round 2 ===
   [Prover] Digit mapping (orig->mapped): 1->4 2->1 3->9 4->5 5->7 6->8 7->2 8->3 9->6
   [Prover]   Mapping result board (orig->mapped, [] = clue)
   [Prover]     ----------+-----------+----------
   [Prover]       8->3  [ 7->2]   3->9  | [ 2->1]   5->7    6->8  |   1->4  [ 4->5] [ 9->6]
   [Prover]       1->4    9->6    4->5  | [ 3->9]   7->2  [ 8->3] |   6->8    2->1    5->7
   [Prover]       6->8    5->7    2->1  |   4->5    9->6  [ 1->4] | [ 8->3] [ 3->9] [ 7->2]
   [Prover]     ----------+-----------+----------
   [Prover]       3->9  [ 1->4]   7->2  | [ 5->7]   8->3  [ 2->1] | [ 4->5]   9->6    6->8
   [Prover]       2->1    8->3    5->7  | [ 9->6] [ 6->8]   4->5  | [ 3->9] [ 7->2]   1->4
   [Prover]     [ 4->5]   6->8    9->6  | [ 7->2]   1->4    3->9  |   2->1  [ 5->7] [ 8->3]
   [Prover]     ----------+-----------+----------
   [Prover]       9->6    2->1    6->8  | [ 1->4]   4->5    7->2  | [ 5->7]   8->3    3->9
   [Prover]       7->2  [ 4->5]   1->4  |   8->3    3->9  [ 5->7] | [ 9->6]   6->8    2->1
   [Prover]     [ 5->7]   3->9  [ 8->3] |   6->8    2->1    9->6  |   7->2    1->4  [ 4->5]
   [Prover]     ----------+-----------+----------
   [Prover] Received BOX challenge for box 0
   [Prover]   [BOX 0]
   [Prover]     +-----+-----+-----+
   [Prover]     | 3 | 2 | 9 |
   [Prover]     +-----+-----+-----+
   [Prover]     | 4 | 6 | 5 |
   [Prover]     +-----+-----+-----+
   [Prover]     | 8 | 7 | 1 |
   [Prover]     +-----+-----+-----+
   [Prover] Round 2 verified
   
   [Prover] === Round 3 ===
   [Prover] Digit mapping (orig->mapped): 1->5 2->2 3->9 4->1 5->7 6->8 7->3 8->6 9->4
   [Prover]   Mapping result board (orig->mapped, [] = clue)
   [Prover]     ----------+-----------+----------
   [Prover]       8->6  [ 7->3]   3->9  | [ 2->2]   5->7    6->8  |   1->5  [ 4->1] [ 9->4]
   [Prover]       1->5    9->4    4->1  | [ 3->9]   7->3  [ 8->6] |   6->8    2->2    5->7
   [Prover]       6->8    5->7    2->2  |   4->1    9->4  [ 1->5] | [ 8->6] [ 3->9] [ 7->3]
   [Prover]     ----------+-----------+----------
   [Prover]       3->9  [ 1->5]   7->3  | [ 5->7]   8->6  [ 2->2] | [ 4->1]   9->4    6->8
   [Prover]       2->2    8->6    5->7  | [ 9->4] [ 6->8]   4->1  | [ 3->9] [ 7->3]   1->5
   [Prover]     [ 4->1]   6->8    9->4  | [ 7->3]   1->5    3->9  |   2->2  [ 5->7] [ 8->6]
   [Prover]     ----------+-----------+----------
   [Prover]       9->4    2->2    6->8  | [ 1->5]   4->1    7->3  | [ 5->7]   8->6    3->9
   [Prover]       7->3  [ 4->1]   1->5  |   8->6    3->9  [ 5->7] | [ 9->4]   6->8    2->2
   [Prover]     [ 5->7]   3->9  [ 8->6] |   6->8    2->2    9->4  |   7->3    1->5  [ 4->1]
   [Prover]     ----------+-----------+----------
   [Prover] Received COL challenge for column 0
   [Prover]   [COLUMN 0] top → bottom
   [Prover]     r 0 : 6
   [Prover]     r 1 : 5
   [Prover]     r 2 : 8
   [Prover]     ------
   [Prover]     r 3 : 9
   [Prover]     r 4 : 2
   [Prover]     r 5 : 1
   [Prover]     ------
   [Prover]     r 6 : 4
   [Prover]     r 7 : 3
   [Prover]     r 8 : 7
   [Prover] Round 3 verified
   
   [Prover] === Round 4 ===
   [Prover] Digit mapping (orig->mapped): 1->6 2->1 3->4 4->5 5->7 6->2 7->8 8->3 9->9
   [Prover]   Mapping result board (orig->mapped, [] = clue)
   [Prover]     ----------+-----------+----------
   [Prover]       8->3  [ 7->8]   3->4  | [ 2->1]   5->7    6->2  |   1->6  [ 4->5] [ 9->9]
   [Prover]       1->6    9->9    4->5  | [ 3->4]   7->8  [ 8->3] |   6->2    2->1    5->7
   [Prover]       6->2    5->7    2->1  |   4->5    9->9  [ 1->6] | [ 8->3] [ 3->4] [ 7->8]
   [Prover]     ----------+-----------+----------
   [Prover]       3->4  [ 1->6]   7->8  | [ 5->7]   8->3  [ 2->1] | [ 4->5]   9->9    6->2
   [Prover]       2->1    8->3    5->7  | [ 9->9] [ 6->2]   4->5  | [ 3->4] [ 7->8]   1->6
   [Prover]     [ 4->5]   6->2    9->9  | [ 7->8]   1->6    3->4  |   2->1  [ 5->7] [ 8->3]
   [Prover]     ----------+-----------+----------
   [Prover]       9->9    2->1    6->2  | [ 1->6]   4->5    7->8  | [ 5->7]   8->3    3->4
   [Prover]       7->8  [ 4->5]   1->6  |   8->3    3->4  [ 5->7] | [ 9->9]   6->2    2->1
   [Prover]     [ 5->7]   3->4  [ 8->3] |   6->2    2->1    9->9  |   7->8    1->6  [ 4->5]
   [Prover]     ----------+-----------+----------
   [Prover] Received CLUE challenge (all clue cells)
   [Prover]   CLUE reveal details:
   [Prover]   Digit mapping: 1->6 2->1 3->4 4->5 5->7 6->2 7->8 8->3 9->9
   [Prover]   当前承诺棋盘（方括号表示已揭示格子）
   [Prover]     ----------+-----------+----------
   [Prover]        .   [7->8]    .   | [2->1]    .      .   |    .   [4->5] [9->9]
   [Prover]        .      .      .   | [3->4]    .   [8->3] |    .      .      .
   [Prover]        .      .      .   |    .      .   [1->6] | [8->3] [3->4] [7->8]
   [Prover]     ----------+-----------+----------
   [Prover]        .   [1->6]    .   | [5->7]    .   [2->1] | [4->5]    .      .
   [Prover]        .      .      .   | [9->9] [6->2]    .   | [3->4] [7->8]    .
   [Prover]     [4->5]    .      .   | [7->8]    .      .   |    .   [5->7] [8->3]
   [Prover]     ----------+-----------+----------
   [Prover]        .      .      .   | [1->6]    .      .   | [5->7]    .      .
   [Prover]        .   [4->5]    .   |    .      .   [5->7] | [9->9]    .      .
   [Prover]     [5->7]    .   [8->3] |    .      .      .   |    .      .   [4->5]
   [Prover]     ----------+-----------+----------
   [Prover] Round 4 verified
   
   [Prover] === Round 5 ===
   [Prover] Digit mapping (orig->mapped): 1->6 2->5 3->9 4->8 5->3 6->4 7->1 8->7 9->2
   [Prover]   Mapping result board (orig->mapped, [] = clue)
   [Prover]     ----------+-----------+----------
   [Prover]       8->7  [ 7->1]   3->9  | [ 2->5]   5->3    6->4  |   1->6  [ 4->8] [ 9->2]
   [Prover]       1->6    9->2    4->8  | [ 3->9]   7->1  [ 8->7] |   6->4    2->5    5->3
   [Prover]       6->4    5->3    2->5  |   4->8    9->2  [ 1->6] | [ 8->7] [ 3->9] [ 7->1]
   [Prover]     ----------+-----------+----------
   [Prover]       3->9  [ 1->6]   7->1  | [ 5->3]   8->7  [ 2->5] | [ 4->8]   9->2    6->4
   [Prover]       2->5    8->7    5->3  | [ 9->2] [ 6->4]   4->8  | [ 3->9] [ 7->1]   1->6
   [Prover]     [ 4->8]   6->4    9->2  | [ 7->1]   1->6    3->9  |   2->5  [ 5->3] [ 8->7]
   [Prover]     ----------+-----------+----------
   [Prover]       9->2    2->5    6->4  | [ 1->6]   4->8    7->1  | [ 5->3]   8->7    3->9
   [Prover]       7->1  [ 4->8]   1->6  |   8->7    3->9  [ 5->3] | [ 9->2]   6->4    2->5
   [Prover]     [ 5->3]   3->9  [ 8->7] |   6->4    2->5    9->2  |   7->1    1->6  [ 4->8]
   [Prover]     ----------+-----------+----------
   [Prover] Received COL challenge for column 6
   [Prover]   [COLUMN 6] top → bottom
   [Prover]     r 0 : 6
   [Prover]     r 1 : 4
   [Prover]     r 2 : 7
   [Prover]     ------
   [Prover]     r 3 : 8
   [Prover]     r 4 : 9
   [Prover]     r 5 : 5
   [Prover]     ------
   [Prover]     r 6 : 3
   [Prover]     r 7 : 2
   [Prover]     r 8 : 1
   [Prover] Round 5 verified
   
   [Prover] Protocol completed successfully

```sh
$ cat ./verifier_log.txt 
[Verifier] Listening on port 8899 (rounds = 5)
[Verifier] Prover connected from 127.0.0.1:48176
[Verifier] Puzzle received (30 clues).
---------------------
- 7 - | 2 - - | - 4 9 
- - - | 3 - 8 | - - - 
- - - | - - 1 | 8 3 7 
---------------------
- 1 - | 5 - 2 | 4 - - 
- - - | 9 6 - | 3 7 - 
4 - - | 7 - - | - 5 8 
---------------------
- - - | 1 - - | 5 - - 
- 4 - | - - 5 | 9 - - 
5 - 8 | - - - | - - 4 
---------------------


[Verifier] === Round 1 ===
[Verifier] Received commitment
[Verifier] Issuing CLUE challenge (all clue cells)
[Verifier]   Digit mapping (orig->mapped): 1->5 2->4 3->2 4->1 5->7 6->6 7->9 8->8 9->3
[Verifier]   Mapping result board (orig->mapped, [] = clue, '.'=unknown)
[Verifier]     ----------+-----------+----------
[Verifier]        .   [7->9]    .   | [2->4]    .      .   |    .   [4->1] [9->3]
[Verifier]        .      .      .   | [3->2]    .   [8->8] |    .      .      .
[Verifier]        .      .      .   |    .      .   [1->5] | [8->8] [3->2] [7->9]
[Verifier]     ----------+-----------+----------
[Verifier]        .   [1->5]    .   | [5->7]    .   [2->4] | [4->1]    .      .
[Verifier]        .      .      .   | [9->3] [6->6]    .   | [3->2] [7->9]    .
[Verifier]     [4->1]    .      .   | [7->9]    .      .   |    .   [5->7] [8->8]
[Verifier]     ----------+-----------+----------
[Verifier]        .      .      .   | [1->5]    .      .   | [5->7]    .      .
[Verifier]        .   [4->1]    .   |    .      .   [5->7] | [9->3]    .      .
[Verifier]     [5->7]    .   [8->8] |    .      .      .   |    .      .   [4->1]
[Verifier]     ----------+-----------+----------
[Verifier] Round 1 verified

[Verifier] === Round 2 ===
[Verifier] Received commitment
[Verifier] Issuing BOX challenge for box 0
[Verifier]   [BOX 0]
[Verifier]     +-----+-----+-----+
[Verifier]     | 3 | 2 | 9 |
[Verifier]     +-----+-----+-----+
[Verifier]     | 4 | 6 | 5 |
[Verifier]     +-----+-----+-----+
[Verifier]     | 8 | 7 | 1 |
[Verifier]     +-----+-----+-----+
[Verifier] Round 2 verified

[Verifier] === Round 3 ===
[Verifier] Received commitment
[Verifier] Issuing COL challenge for column 0
[Verifier]   [COLUMN 0] top → bottom
[Verifier]     r 0 : 6
[Verifier]     r 1 : 5
[Verifier]     r 2 : 8
[Verifier]     ------
[Verifier]     r 3 : 9
[Verifier]     r 4 : 2
[Verifier]     r 5 : 1
[Verifier]     ------
[Verifier]     r 6 : 4
[Verifier]     r 7 : 3
[Verifier]     r 8 : 7
[Verifier] Round 3 verified

[Verifier] === Round 4 ===
[Verifier] Received commitment
[Verifier] Issuing CLUE challenge (all clue cells)
[Verifier]   Digit mapping (orig->mapped): 1->6 2->1 3->4 4->5 5->7 6->2 7->8 8->3 9->9
[Verifier]   Mapping result board (orig->mapped, [] = clue, '.'=unknown)
[Verifier]     ----------+-----------+----------
[Verifier]        .   [7->8]    .   | [2->1]    .      .   |    .   [4->5] [9->9]
[Verifier]        .      .      .   | [3->4]    .   [8->3] |    .      .      .
[Verifier]        .      .      .   |    .      .   [1->6] | [8->3] [3->4] [7->8]
[Verifier]     ----------+-----------+----------
[Verifier]        .   [1->6]    .   | [5->7]    .   [2->1] | [4->5]    .      .
[Verifier]        .      .      .   | [9->9] [6->2]    .   | [3->4] [7->8]    .
[Verifier]     [4->5]    .      .   | [7->8]    .      .   |    .   [5->7] [8->3]
[Verifier]     ----------+-----------+----------
[Verifier]        .      .      .   | [1->6]    .      .   | [5->7]    .      .
[Verifier]        .   [4->5]    .   |    .      .   [5->7] | [9->9]    .      .
[Verifier]     [5->7]    .   [8->3] |    .      .      .   |    .      .   [4->5]
[Verifier]     ----------+-----------+----------
[Verifier] Round 4 verified

[Verifier] === Round 5 ===
[Verifier] Received commitment
[Verifier] Issuing COL challenge for column 6
[Verifier]   [COLUMN 6] top → bottom
[Verifier]     r 0 : 6
[Verifier]     r 1 : 4
[Verifier]     r 2 : 7
[Verifier]     ------
[Verifier]     r 3 : 8
[Verifier]     r 4 : 9
[Verifier]     r 5 : 5
[Verifier]     ------
[Verifier]     r 6 : 3
[Verifier]     r 7 : 2
[Verifier]     r 8 : 1
[Verifier] Round 5 verified

[Verifier] Proof accepted.
```

### 具体实现

1. 数独生成`zkp::soduku::soduku_gen`：定义了一个`Sudoku`对象，实现了数独及其线索的生成函数，实现了投影的生成。随机数生成上使用了`rand`库。

2. 挑战的生成`zkp::challenge`：定义了`ChallengeType`枚举对象以及其生成函数。

3. 承诺的生成与验证`zkp::soduku::commit`：主要定义了`Matrix`与`CommitMat`对象，通过`random`生成u64的数值作为随机数，调用`sha2`库进行哈希操作后再规约到一个`u64`矩阵中存储承诺值。

> [!NOTE]
> 以下部分的实现使用了AI辅助

4. 网络通信模块`zkp::network`：定义了一系列数据传输的所需的数据类型，通过`std::net::TcpStream`进行数据传输，使用`bincode`与`serde`库实现数据对象的序列化与反序列化。

5. 主程序`prover`与`verifier`：通过调用`std::env`获取程序入参列表；`verifier`通过`fn handle_session`函数获取`prover`参数并调用`fn verify_round`函数进行后续轮验证；`prover`通过调用`fn respond_to_challenge`响应轮挑战。



## 2. schnorr签名

### 运行结果

<img src="屏幕截图 2025-11-19 144232.png" alt="alt text" style="zoom:80%;" />

### 具体实现

1. 签名

```cpp
bool SchnorrSignature::sign(const std::string& message, const BIGNUM* private_key, 
                           BIGNUM*& r, BIGNUM*& s) {
    try
    {    
        m_ctx = BN_CTX_new();

        auto k = BN_new();
        BN_rand_range(k, m_order);
        if (BN_is_zero(k)) {
            BN_one(k);   
        }
        auto R = EC_POINT_new(m_group);
        EC_POINT_mul(m_group, R, k, m_generator, nullptr, m_ctx); // R = kG

        // set r = R.x
        r = BN_new();
        EC_POINT_get_affine_coordinates(m_group, R, r, nullptr, m_ctx);

        auto e = BN_new();
        auto P = EC_POINT_new(m_group);
        EC_POINT_mul(m_group, P, private_key, nullptr, nullptr, m_ctx);

        e = hashChallenge(R, P, message);

        s = BN_new();
        // s = (k - e * private_key) mod order
        auto e_priv = BN_new();
        BN_mod_mul(e_priv, e, private_key, m_order, m_ctx);
        BN_mod_sub(s, k, e_priv, m_order, m_ctx);

        // free
        BN_free(k);
        EC_POINT_free(R);
        BN_free(e);
        EC_POINT_free(P);
        BN_free(e_priv);

        return true;
    } catch (...)
    {
        std::cout << __LINE__ << " Sign Failed" << std::endl;
        r = nullptr;
        s = nullptr;
        BN_CTX_free(m_ctx);
        return false;
    }
}
```

2. 验证

```cpp
bool SchnorrSignature::verify(const std::string& message, const BIGNUM* r, const BIGNUM* s, 
                             const EC_POINT* public_key) {
    try {
        // check range
        if (BN_is_negative(r) || BN_is_negative(s) ||
            BN_cmp(r, m_order) >= 0 || BN_cmp(s, m_order) >= 0) {
            std::cout << "r or s out of range" << std::endl;
            return false;
        }
        // recover R from r
        auto R = EC_POINT_new(m_group);
        R = reconstructPoint(m_group, r, m_ctx);

        // calc e
        auto e = BN_new();
        e = hashChallenge(R, public_key, message);
        // calc sG + eP
        auto sG = EC_POINT_new(m_group);
        EC_POINT_mul(m_group, sG, s, nullptr, nullptr, m_ctx);

        auto eP = EC_POINT_new(m_group);
        EC_POINT_mul(m_group, eP, nullptr, public_key, e, m_ctx);

        auto R_dot = EC_POINT_new(m_group);
        EC_POINT_add(m_group, R_dot, sG, eP, m_ctx);

        auto x_R_dot = BN_new();
        EC_POINT_get_affine_coordinates(m_group, R_dot, x_R_dot, nullptr, m_ctx);

        if (BN_cmp(r, x_R_dot) == 0) {
            // free
            BN_free(x_R_dot);
            EC_POINT_free(R);
            EC_POINT_free(sG);
            EC_POINT_free(eP);
            EC_POINT_free(R_dot);
            BN_free(e);

            return true;
        } else {
            return false;
        }

    } catch (...) {
        (void)r;
        (void)s;
        return false;
    }
}
```