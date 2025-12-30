use sha2::{Digest, Sha256};
use k256::{
    elliptic_curve::{
        sec1::{FromEncodedPoint, ToEncodedPoint},
        Field,
        rand_core::{RngCore, OsRng}
    },
    ProjectivePoint, Scalar, AffinePoint,
};

pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

// --- 基础类型定义 ---
// 点元素
pub type Point = ProjectivePoint;
// 标量元素
pub type SecretScalar = Scalar;

/// 随机采样私钥/标量 (对应协议中的 a, r)
/// 
/// return: 随机标量
pub fn generate_scalar() -> SecretScalar {
    SecretScalar::random(&mut OsRng)
}

/// 获取生成元 G
pub fn get_generator() -> Point {
    Point::GENERATOR
}

/// 标量乘法 (对应 a*G, r*G, a*B 等)
/// point: 椭圆曲线点
/// scalar: 标量
/// return: point * scalar
pub fn mul_point(point: &Point, scalar: &SecretScalar) -> Point {
    point * scalar
}

/// 点加法 (对应 Receiver 计算 B1 = A + B0)
pub fn add_points(p1: &Point, p2: &Point) -> Point {
    p1 + p2
}

/// 点减法 (对应 Sender 计算 K1 = K0 - a*A)
pub fn sub_points(p1: &Point, p2: &Point) -> Point {
    p1 - p2
}

/// 序列化点 (用于网络发送 A, B)
/// 使用压缩格式 (33 bytes) 以节省带宽
pub fn point_to_bytes(point: &Point) -> Vec<u8> {
    point.to_affine().to_encoded_point(true).as_bytes().to_vec()
}

/// 7. 反序列化点 (用于接收 A, B)
pub fn bytes_to_point(bytes: &[u8]) -> Option<Point> {
    let encoded = k256::elliptic_curve::sec1::EncodedPoint::<k256::Secp256k1>::from_bytes(bytes).ok()?;
    let affine = AffinePoint::from_encoded_point(&encoded);
    
    // 检查点是否在曲线上 (from_encoded_point 返回 Option 或 CtOption)
    if bool::from(affine.is_some()) {
        Some(Point::from(affine.unwrap()))
    } else {
        None
    }
}

/// 8. 密钥派生哈希函数 (对应 H(K, seed, id))
/// key_point: 共享密钥点 K
/// seed: 公共种子
/// id: 消息索引或标识 (0 或 1)
pub fn hash_point(key_point: &Point, seed: &[u8], id: u64) -> Vec<u8> {
    let mut hasher = Sha256::new();
    
    // 输入 K (序列化后)
    hasher.update(point_to_bytes(key_point));
    
    // 输入 seed
    hasher.update(seed);
    
    // 输入 id (转为大端序字节)
    hasher.update(id.to_be_bytes());
    
    hasher.finalize().to_vec()
}

/// 计算数据的 SHA256 哈希 (用于 commitment)
pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// 辅助：生成随机 Seed
pub fn generate_random_seed() -> Vec<u8> {
    // use rand_core::RngCore;
    let mut seed = vec![0u8; 32];
    OsRng.fill_bytes(&mut seed);
    seed
}

#[test]

fn test_utils() {
    // 测试点的序列化与反序列化
    let g = get_generator();
    let g_bytes = point_to_bytes(&g);
    let g_recovered = bytes_to_point(&g_bytes).expect("Failed to deserialize point");
    assert_eq!(g, g_recovered);

    // 测试标量乘法与点加法
    let a = generate_scalar();
    let b = generate_scalar();
    let a_g = mul_point(&g, &a);
    let b_g = mul_point(&g, &b);
    let sum = add_points(&a_g, &b_g);
    let expected_sum = mul_point(&g, &(a + b));
    assert_eq!(sum, expected_sum);

    // 测试点减法
    let diff = sub_points(&sum, &a_g);
    assert_eq!(diff, b_g);

    // 测试哈希函数
    let seed = generate_random_seed();
    let hash1 = hash_point(&g, &seed, 0);
    let hash2 = hash_point(&g, &seed, 1);
    assert_ne!(hash1, hash2);
}