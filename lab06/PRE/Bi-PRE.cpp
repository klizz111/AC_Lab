#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "utils.h"

// 双向代理重加密：基于 ElGamal 变体，使用 2048 位安全素数子群。
// 教学示例，仅演示算法流程，未包含填充/认证等工程加固。

class SystemParams {
  public:
    // 系统公共参数：群模数 p、生成元 g_sub，群阶 q（素数），满足 DDH 假设。
    SystemParams() {
        // 2048 位 MODP 群（RFC 3526 Group 14）。
        const std::string prime_hex =
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
            "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
            "4FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF";
        p_ = BNUtils::from_hex(prime_hex);  // 安全素数 p = 2q + 1

        // q = (p-1)/2
        Big p_minus_1 = BNUtils::dup(p_);
        BNUtils::sub_word(p_minus_1, 1);
        q_ = BNUtils::dup(p_minus_1);
        BNUtils::rshift1(q_);

        // 生成 q 阶子群的生成元：将大群生成元 2 升至 (p-1)/q = 2 的指数。
        Big base_g = BNUtils::from_uint(2);
        Big exp = BNUtils::from_uint(2);  // (p-1)/q = 2 对于安全素数 p=2q+1
        g_ = BNUtils::mod_exp(base_g, exp, p_);
    }

    std::string hex_p() const { return BNUtils::to_hex(p_); }
    std::string hex_g() const { return BNUtils::to_hex(g_); }
    const Big& p() const { return p_; }
    const Big& g() const { return g_; }
    const Big& q() const { return q_; }
    bool plaintext_fits(const Big& m) const { return BNUtils::cmp(m, p_) < 0; }
    // 采样一个子群元素：g^{r}，r∈Z_q。
    Big random_element() const {
        Big r = BNUtils::random_range(q_);
        return BNUtils::mod_exp(g_, r, p_);
    }

  private:
    Big p_;
    Big g_;
    Big q_;
};

class KeyPair {
    friend class ReKey;
    friend class ProxyReEncryption;
  public:
    // 生成一对公私钥，要求 sk 与群阶互素以保证可逆。
    KeyPair(const SystemParams& params) { generate(params); }

    std::string hex_pk() const { return BNUtils::to_hex(pk_); }
    std::string hex_sk() const { return BNUtils::to_hex(sk_); }

  private:
    void generate(const SystemParams& params) {
        Big gcd = BNUtils::make();
        do {
            sk_ = BNUtils::random_range(params.q());
            gcd = BNUtils::gcd(sk_, params.q());
        } while (!BNUtils::is_one(gcd));
        pk_ = BNUtils::mod_exp(params.g(), sk_, params.p());
    }

    Big pk_;
    Big sk_;
};

class ReKey {
    friend class ProxyReEncryption;
  public:
    // 生成双向重加密密钥 rk = x_j * x_i^{-1} mod q（素数阶，确保可逆）。
    ReKey(const SystemParams& params, const KeyPair& from, const KeyPair& to) {
        // 待学生实现：计算 rk = sk_to * sk_from^{-1} mod q
        // 实现提示：
        // 1) 计算 inv = from.sk_ 的模逆（模 q）。
        // 2) factor_ = to.sk_ * inv mod q。
        // 3) factor_ 存储在成员变量中。
        throw std::logic_error("TODO: 请实现 ReKey 构造函数");
    }

    std::string hex_factor() const { return BNUtils::to_hex(factor_); }

  private:
    Big factor_;
};

class Ciphertext {
    friend class ProxyReEncryption;
  public:
    // ElGamal 变体密文对 (c1, c2)。
    Ciphertext(Big&& c1, Big&& c2) : c1_(std::move(c1)), c2_(std::move(c2)) {}

    std::string hex_c1() const { return BNUtils::to_hex(c1_); }
    std::string hex_c2() const { return BNUtils::to_hex(c2_); }

  private:
    Big c1_;
    Big c2_;
};

class ProxyReEncryption {
  public:
    explicit ProxyReEncryption(const SystemParams& params) : params_(params) {}

    // 加密（授权者）：随机 r∈Z_q，输出 c1 = h^r，c2 = m * g^r mod p。
    // 其中 h = g^x，是接收者公钥；g^r 作为一次性掩码。
    Ciphertext encrypt(const KeyPair& kp, const Big& m) const {
        // 待学生实现：ElGamal 形式的加密
        // 实现提示：
        // 1) 检查明文 m < p，否则抛异常（超界）。
        // 2) 随机 r∈Z_q。
        // 3) c1 = h^r mod p，其中 h = kp.pk_。
        // 4) g_r = g^r mod p；c2 = m * g_r mod p。
        // 5) 返回 Ciphertext(c1, c2)。
        throw std::logic_error("TODO: 请实现 encrypt");
    }

    // 代理重加密：c1' = (c1)^{x_j/x_i} = (g^{x_i r})^{x_j/x_i} = g^{x_j r} = h_j^r，c2 不变。
    // 不泄露明文，也不需要私钥，代理仅用重加密密钥（标量）。
    Ciphertext reencrypt(const ReKey& rk, const Ciphertext& ct) const {
        // 待学生实现：使用 rk.factor_ 重新加密 c1
        // 实现提示：
        // 1) new_c1 = c1^{rk.factor_} mod p，等效替换公钥指数。
        // 2) c2 保持不变（可直接 dup）。
        // 3) 返回新的 Ciphertext(new_c1, c2)。
        throw std::logic_error("TODO: 请实现 reencrypt");
    }

    // 解密：先恢复 g^r = (h^r)^{1/x}，再用其逆消去 c2 的随机掩码，得到 m。
    Big decrypt(const KeyPair& kp, const Ciphertext& ct) const {
        // 待学生实现：用私钥 x 解密
        // 实现提示：
        // 1) inv_sk = sk^{-1} mod q。
        // 2) g_r = (c1)^{inv_sk} mod p，恢复 g^r。
        // 3) g_r_inv = g_r^{-1} mod p。
        // 4) m = c2 * g_r_inv mod p。
        throw std::logic_error("TODO: 请实现 decrypt");
    }

  private:
    const SystemParams& params_;
};

int main() {
    SystemParams params;
    KeyPair alice(params);
    KeyPair bob(params);
    ProxyReEncryption proxy(params);

    // 选择群元素作为“明文”：随机 r_m，m = g^{r_m} ∈ 子群，避免任意字节落在小子群。
    Big m_bn = params.random_element();

    Ciphertext ct_from_alice = proxy.encrypt(alice, m_bn);
    ReKey rk(params, alice, bob);
    Ciphertext ct_for_bob = proxy.reencrypt(rk, ct_from_alice);

    Big recovered_bn = proxy.decrypt(bob, ct_for_bob);

    std::cout << "p (hex): " << params.hex_p() << "\n";
    std::cout << "g: " << params.hex_g() << "\n\n";

    std::cout << "Alice sk (hex): " << alice.hex_sk() << "\n";
    std::cout << "Alice pk (hex): " << alice.hex_pk() << "\n\n";
    std::cout << "Bob   sk (hex): " << bob.hex_sk() << "\n";
    std::cout << "Bob   pk (hex): " << bob.hex_pk() << "\n\n";

    std::cout << "Plaintext (group element m): " << BNUtils::to_hex(m_bn) << "\n";
    std::cout << "Ciphertext (Alice) c1: " << ct_from_alice.hex_c1() << "\n";
    std::cout << "Ciphertext (Alice) c2: " << ct_from_alice.hex_c2() << "\n";
    std::cout << "Re-encryption key (x_j / x_i mod p-1): " << rk.hex_factor() << "\n\n";

    std::cout << "Ciphertext (for Bob) c1: " << ct_for_bob.hex_c1() << "\n";
    std::cout << "Ciphertext (for Bob) c2: " << ct_for_bob.hex_c2() << "\n\n";

    std::cout << "Recovered m: " << BNUtils::to_hex(recovered_bn) << "\n";
    std::cout << (BNUtils::cmp(recovered_bn, m_bn) == 0 ? "Re-encryption succeeded." : "Mismatch!") << "\n";

    return 0;
}
