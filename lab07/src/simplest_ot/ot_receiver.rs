use crate::receive_json;

use super::common::*;
use super::utils;

pub struct OtReceiver {
    pub network: Network,
    choice: u8, // 0 or 1
    r: utils::SecretScalar,
}

impl OtReceiver {
    pub fn new(network: Network, choice: u8) -> Self {
        let r = utils::generate_scalar();
        OtReceiver { network, choice, r }
    }

    pub fn new_(stream: TcpStream, choice: u8) -> Self {
        assert!(choice == 0 || choice == 1, "Choice bit must be 0 or 1");
        let network = Network::new(stream);
        let r = utils::generate_scalar();
        OtReceiver { network, choice, r }
    }

    /// 执行完整的 OT 接收流程
    pub async fn execute(&mut self) -> Vec<u8> {
        let (a_point, comm) = self.step1_receive_init().await;
        self.step2_send_b(&a_point).await;
        let seed = self.step3_receive_seed_and_verify(&comm).await;
        let k = self.step4_derive_key(&a_point);
        self.step5_derive_message(&k, &seed)
    }

    /// Step 1: 接收 Sender 的公钥 A 和承诺 comm
    async fn step1_receive_init(&mut self) -> (utils::Point, Vec<u8>) {
        let (a_bytes, comm) = receive_json!(self.network => {
            A: Vec<u8>,
            comm: Vec<u8>
        });

        let a_point = utils::bytes_to_point(&a_bytes).expect("Invalid point A");
        (a_point, comm)
    }

    /// Step 2: 计算并发送 B
    async fn step2_send_b(&mut self, a_point: &utils::Point) {
        let g = utils::get_generator();
        // B0 = r * G
        let b0 = utils::mul_point(&g, &self.r);

        // If choice = 0, B = B0
        // If choice = 1, B = A + B0
        let b_point = if self.choice == 0 {
            b0
        } else {
            utils::add_points(a_point, &b0)
        };

        let data = json!({
            "B": utils::point_to_bytes(&b_point)
        });
        self.network.send(&data).await.unwrap();
    }

    /// Step 3: 接收 seed 并验证承诺
    async fn step3_receive_seed_and_verify(&mut self, expected_comm: &[u8]) -> Vec<u8> {
        let (seed,) = receive_json!(self.network => { seed: Vec<u8> });

        let calculated_comm = utils::sha256(&seed);
        if calculated_comm != expected_comm {
            panic!("Commitment verification failed!");
        }
        seed
    }

    /// Step 4: 计算共享密钥 K
    fn step4_derive_key(&self, a_point: &utils::Point) -> utils::Point {
        // K = r * A
        utils::mul_point(a_point, &self.r)
    }

    /// Step 5: 派生最终消息 m
    fn step5_derive_message(&self, k: &utils::Point, seed: &[u8]) -> Vec<u8> {
        utils::hash_point(k, seed, self.choice as u64)
    }
}
