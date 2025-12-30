use crate::receive_json;

use super::common::*;
use super::utils;

pub struct OtSender {
    pub network: Network,
    sk: utils::SecretScalar,
    pk: utils::Point,
    seed: Vec<u8>,
    commit: Vec<u8>,
}

impl OtSender {
    pub fn new(network: Network) -> Self {
        let sk = utils::generate_scalar();
        let pk = utils::mul_point(&utils::get_generator(), &sk);
        let seed = utils::generate_random_seed();
        let commit = utils::sha256(&seed);
        OtSender {
            network,
            sk,
            pk,
            seed,
            commit,
        }
    }

    pub fn new_(stream: TcpStream) -> Self {
        let network = Network::new(stream);
        let sk = utils::generate_scalar();
        let pk = utils::mul_point(&utils::get_generator(), &sk);
        let seed = utils::generate_random_seed();
        let commit = utils::sha256(&seed);
        OtSender {
            network,
            sk,
            pk,
            seed,
            commit,
        }
    }

    pub async fn execute(&mut self) -> (Vec<u8>, Vec<u8>) {
        self.step1_send_init().await;
        let b_point = self.step2_receive_b().await;
        let (k0, k1) = self.step3_derive_keys(&b_point);
        self.step4_open_seed().await;
        self.step5_derive_messages(&k0, &k1)
    }

    /// Step 1: 发送公钥 A 和承诺 comm
    async fn step1_send_init(&mut self) {
        let data = json!({
            "A": utils::point_to_bytes(&self.pk),
            "comm": self.commit,
        });
        self.network.send(&data).await.unwrap();
    }

    /// Step 2: 接收 Receiver 的公钥 B
    async fn step2_receive_b(&mut self) -> utils::Point {
        let (b_bytes,) = receive_json!(self.network => { B: Vec<u8> });
        utils::bytes_to_point(&b_bytes).expect("Invalid point B")
    }

    /// Step 3: 计算共享密钥 K0, K1
    fn step3_derive_keys(&self, b_point: &utils::Point) -> (utils::Point, utils::Point) {
        // K0 = a * B
        let k0 = utils::mul_point(b_point, &self.sk);
        // K1 = K0 - a * A = K0 - a^2 * G
        // 这里直接计算 a * A (即 sk * pk)
        let a_a = utils::mul_point(&self.pk, &self.sk);
        let k1 = utils::sub_points(&k0, &a_a);
        (k0, k1)
    }

    /// Step 4: 打开承诺，发送 seed
    async fn step4_open_seed(&mut self) {
        let data = json!({
            "seed": self.seed
        });
        self.network.send(&data).await.unwrap();
    }

    /// Step 5: 派生最终消息 m0, m1
    fn step5_derive_messages(&self, k0: &utils::Point, k1: &utils::Point) -> (Vec<u8>, Vec<u8>) {
        let m0 = utils::hash_point(k0, &self.seed, 0);
        let m1 = utils::hash_point(k1, &self.seed, 1);
        (m0, m1)
    }
}
