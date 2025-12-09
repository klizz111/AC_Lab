// BCP 公钥加密方案（Bresson, Catalano, Pointcheval），基于 Paillier 结构的双陷门变种。
// 方案概述：
// - 密钥结构：setup 生成公共参数 (n, n^2, g，其中 g 随机选取满足 L(g^λ) 可逆) 与主密钥 (p, q, λ=lcm(p-1, q-1), μ=L(g^λ)^{-1} mod n)，其中 p、q 为 safe prime。
//   每个用户通过 keygen 选择私钥指数 a ∈ Z*_{n^2}，公钥 h = g^a mod n^2。
// - 加密：随机 r ∈ (0, n^2)，输出密文 (A, B) = (g^r mod n^2, h^r * (1 + m n) mod n^2)，明文 m ∈ Z_n。
// - 解密（因子陷门）：先算 r = L(A^λ)μ mod n，再算 a = L(h^λ)μ mod n，最后 m = L(B^λ)μ - a·r mod n。
//   其中 L(x) = (x-1)/n，要求 x ≡ 1 (mod n)；因子陷门无需持有用户私钥，也可用于校验公钥。
// - 解密（指数陷门）：持有用户私钥 a，直接算 masked = B / A^a = 1 + m n，随后 m = L(masked)。
// - 性质：包含随机性 r，保持 Paillier 加法同态；任一陷门即可完成解密。

#include "utils.h"

#include <openssl/bn.h>

#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

// 公共参数 (n, n^2, g=n+1)：setup 阶段全局生成，所有用户共享。
struct BCPParams {
    Big n;
    Big n_square;
    Big g;

    BCPParams(Big n_in, Big n_square_in, Big g_in)
        : n(std::move(n_in)), n_square(std::move(n_square_in)), g(std::move(g_in)) {}
};

// 主密钥（因子陷门）：持有 p、q 及由它们推导的 λ、μ，可单独用于解密。
struct BCPMasterKey {
    Big p;
    Big q;
    Big lambda;  // lcm(p-1, q-1)
    Big mu;      // λ^{-1} mod n

    BCPMasterKey(Big p_in, Big q_in, Big lambda_in, Big mu_in)
        : p(std::move(p_in)), q(std::move(q_in)), lambda(std::move(lambda_in)), mu(std::move(mu_in)) {}
};

// 用户公钥 h = g^a mod n^2（依赖公共参数），用户私钥是指数 a。
struct BCPUserPublic {
    Big h;

    explicit BCPUserPublic(Big h_in) : h(std::move(h_in)) {}
};

// 密文：C = (A, B) = (g^r mod n^2, h^r * (1 + m n) mod n^2)。
struct BCPCiphertext {
    Big A;
    Big B;

    BCPCiphertext(Big a, Big b) : A(std::move(a)), B(std::move(b)) {}
};

// BCP 工具类：负责 setup/keygen 与加解密算法。所有成员静态，避免额外状态。
class BCP {
  public:
    BCP() = delete;

    // setup：生成公共参数与主密钥
    // - 输入 bit_length（安全至少 2048）。
    // - 输出 (params, master)：params 供所有用户共享，master（p,q,λ,μ）仅掌握因子陷门一方。
    static std::pair<BCPParams, BCPMasterKey> setup(size_t bit_length);

    // keygen：在公共参数下生成用户公钥/私钥对
    // - 随机选择 a ∈ Z*_n，公钥 h = g^a mod n^2。
    // - 输出 (pub, a)。
    static std::pair<BCPUserPublic, Big> keygen(const BCPParams& params);

    // encrypt：在 params、用户公钥 pub 下，加密明文 m ∈ Z_n，随机 r ∈ Z*_n（可逆）。
    // - 密文 (A, B) = (g^r, h^r * (1 + m n)) mod n^2。
    static BCPCiphertext encrypt(const BCPParams& params, const BCPUserPublic& pub, const Big& m);
    static BCPCiphertext encrypt_bytes(const BCPParams& params, const BCPUserPublic& pub,
                                       const std::vector<uint8_t>& data);

    // decrypt_with_factors：使用主密钥 (λ, μ) 解密，先恢复 r 和 a，再恢复 m。
    static Big decrypt_with_factors(const BCPParams& params,
                                    const BCPUserPublic& pub,
                                    const BCPMasterKey& master,
                                    const BCPCiphertext& ct);

    // decrypt_with_exponent：使用用户私钥 a 解密，计算 B / A^a 得到 1 + m n，取 L(x) 得 m。
    static Big decrypt_with_exponent(const BCPParams& params,
                                     const Big& priv_exp,
                                     const BCPCiphertext& ct);
};

std::pair<BCPParams, BCPMasterKey> BCP::setup(size_t bit_length) {
    // 待学生实现：生成 (params, master)
    // 实现提示（按步骤完成）：
    // 1) 校验 bit_length >= 2048，太小直接抛出异常。
    // 2) prime_bits = bit_length/2，调用 BNUtils::generate_prime 生成 safe prime p、q。
    // 3) 计算 n=p*q，n_square=n^2。
    // 4) 计算 λ=lcm(p-1,q-1)：可先算 p-1、q-1，再用 gcd 与 乘法求 lcm。
    // 5) 随机采样 g∈Z*_{n^2} 满足：
    //    - gcd(g, n^2)=1 且 g (mod n) ≠ 1；
    //    - n | (g^λ-1)（保证可做 L(x)）；L(g^λ) mod n 与 n 互素；
    //    - mu = L(g^λ)^{-1} mod n。
    // 6) 返回 {BCPParams(n,n_square,g), BCPMasterKey(p,q,λ,μ)}。
    throw std::logic_error("TODO: 请实现 setup");
}

std::pair<BCPUserPublic, Big> BCP::keygen(const BCPParams& params) {
    // 待学生实现：生成用户公私钥 (pub, a)
    // 实现提示：
    // 1) 随机选取 a ∈ Z*_{n^2}，若 gcd(a,n) ≠ 1 则重选。
    // 2) 公钥 h = g^a mod n^2。
    // 3) 返回 {BCPUserPublic(h), a}。
    throw std::logic_error("TODO: 请实现 keygen");
}

BCPCiphertext BCP::encrypt(const BCPParams& params, const BCPUserPublic& pub, const Big& m) {
    // 待学生实现：加密输出密文 (A, B)
    // 实现提示：
    // 1) 断言 m < n，否则抛异常。
    // 2) 取 r ∈ Z*_{n^2}（gcd(r,n)=1），求 A = g^r mod n^2。
    // 3) 计算 (1 + m·n)；再算 B = h^r * (1 + m n) mod n^2。
    // 4) 返回 BCPCiphertext(A, B)。
    throw std::logic_error("TODO: 请实现 encrypt");
}

Big BCP::decrypt_with_factors(const BCPParams& params,
                              const BCPUserPublic& pub,
                              const BCPMasterKey& master,
                              const BCPCiphertext& ct) {
    // 待学生实现：用因子陷门 (λ, μ) 解密
    // 实现提示：
    // 1) 定义 L(x)=(x-1)/n 并断言能整除。
    // 2) r = L(A^λ) * μ mod n，恢复随机数 r。
    // 3) a_from_lambda = L(h^λ) * μ mod n，恢复公钥指数 a（用于抵消）。
    // 4) ar_plus_m = L(B^λ) * μ mod n，包含 a*r + m·(λ t^{-1})。
    // 5) delta = ar_plus_m - a_from_lambda * r (mod n) 去掉 a*r。
    // 6) t = L(g^λ) mod n，lambda_inv = λ^{-1} mod n。
    // 7) m = delta * t * lambda_inv mod n。
    throw std::logic_error("TODO: 请实现 decrypt_with_factors");
}

Big BCP::decrypt_with_exponent(const BCPParams& params, const Big& priv_exp, const BCPCiphertext& ct) {
    // 待学生实现：用私钥指数 a 解密
    // 实现提示：
    // 1) 定义 L(x)=(x-1)/n 并校验能被 n 整除。
    // 2) 计算 A^a mod n^2，再求逆 inv = (A^a)^{-1} mod n^2。
    // 3) masked = B * inv mod n^2 = 1 + m·n。
    // 4) 返回 L(masked) 得到 m。
    throw std::logic_error("TODO: 请实现 decrypt_with_exponent");
}

// 演示入口：生成密钥对，加密/解密一次样例消息。
int main() {
    try {
    // 生成 2048 位模数的密钥对，满足现实安全需求；可按需要调大。
    auto [params, master] = BCP::setup(2048);
    auto [pub, priv_exp] = BCP::keygen(params);

    // 在明文空间 Z_n 内随机生成明文，避免超界。
    Big m = BNUtils::random_range(params.n);

    BCPCiphertext ct = BCP::encrypt(params, pub, m);

    // 使用两种陷门分别解密并打印结果（以 hex 展示），确保一致性。
        Big plain1 = BCP::decrypt_with_factors(params, pub, master, ct);
        Big plain2 = BCP::decrypt_with_exponent(params, priv_exp, ct);

        if (BNUtils::cmp(m, plain1) != 0 || BNUtils::cmp(m, plain2) != 0) {
            std::cerr << "解密不一致，m vs plain1: " << BNUtils::cmp(m, plain1)
                      << ", m vs plain2: " << BNUtils::cmp(m, plain2) << "\n";
            std::cerr << "m(hex):      " << BNUtils::to_hex(m) << "\n";
            std::cerr << "plain1(hex): " << BNUtils::to_hex(plain1) << "\n";
            std::cerr << "plain2(hex): " << BNUtils::to_hex(plain2) << "\n";
            throw std::runtime_error("解密结果不一致");
        }

        std::cout << "原始明文(hex): " << BNUtils::to_hex(m) << "\n";
        std::cout << "因子陷门解密(hex): " << BNUtils::to_hex(plain1) << "\n";
        std::cout << "指数陷门解密(hex): " << BNUtils::to_hex(plain2) << "\n";
    } catch (const std::exception& ex) {
        std::cerr << "错误: " << ex.what() << "\n";
        return 1;
    }
    return 0;
}
