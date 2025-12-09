#include <iostream>
#include <stdexcept>
#include <string>

#include "common.h"

// 单向代理重加密
// Enc1: c1 = h_i^r ∈ G1, c2 = m * Z^r ∈ GT
// ReEnc: c1' = e(c1, rki→j) = Z^{x_j r} ∈ GT, c2' = c2
    // Dec2: m = c2' / (c1')^{1/x_j}（这里的 c2' 就是传入的 ct.c2）
// 明文 m 直接取 GT 随机元素，避免映射风险。

inline std::string hex(const common::ZrElement& e) { return common::toHex(common::serializeElement(e)); }
inline std::string hex(const common::G1Element& e) { return common::toHex(common::serializeElement(e)); }
inline std::string hex(const common::GTElement& e) { return common::toHex(common::serializeElement(e)); }

class SystemParams {
  public:
    SystemParams()
        : ctx_(common::kDefaultRbits, common::kDefaultQbits),
          g_(ctx_.pairing()),
          Z_(ctx_.pairing()) {
        g_.randomize();
        Z_.setPairing(g_, g_, ctx_.pairing());  // Z = e(g, g)
    }

    pairing_t& pairing() const { return const_cast<pairing_t&>(ctx_.pairing()); }
    const common::G1Element& g() const { return g_; }
    const common::GTElement& Z() const { return Z_; }

    common::GTElement random_plaintext() const {
        common::GTElement m(ctx_.pairing());
        m.randomize();
        return m;
    }

  private:
    common::PairingContext ctx_;
    common::G1Element g_;
    common::GTElement Z_;
};

class KeyPair {
  public:
    KeyPair(pairing_t pairing, const common::G1Element& g) : sk_(pairing), pk_(pairing) {
        sk_.randomize();
        pk_.setPowZn(g, sk_);  // pk = g^x
    }

    const common::ZrElement& sk() const { return sk_; }
    const common::G1Element& pk() const { return pk_; }

  private:
    common::ZrElement sk_;
    common::G1Element pk_;
};

class ReKey {
  public:
    explicit ReKey(pairing_t pairing) : k_(pairing) {}
    const common::G1Element& value() const { return k_; }

    static ReKey derive(pairing_t pairing, const KeyPair& from, const KeyPair& to, const common::G1Element& g) {
        // 待学生实现：生成单向重加密密钥 k = g^{x_j/x_i} ∈ G1
        // 实现提示：
        // 1) 创建 ReKey rk(pairing) 作为返回值。
        // 2) 计算 inv = x_i^{-1}（模群阶，pbc 内部处理）。
        // 3) 先算 temp = g^{inv}，再 temp^{x_j}，得到 g^{x_j / x_i}。
        // 4) 将结果写入 rk.k_，最后返回 rk。
        throw std::logic_error("TODO: 请实现 ReKey::derive");
    }

  private:
    common::G1Element k_;  // g^{x_j / x_i} ∈ G1
};

// 转换前密文：c1 = h_i^r ∈ G1，c2 = m * Z^r ∈ GT。
class Ciphertext1 {
  public:
    Ciphertext1(pairing_t pairing) : c1(pairing), c2(pairing) {}
    common::G1Element c1;
    common::GTElement c2;
};

// 转换后密文：c1 = Z^{x_j r} ∈ GT，c2 = m * Z^r ∈ GT。
class Ciphertext2 {
  public:
    Ciphertext2(pairing_t pairing) : c1(pairing), c2(pairing) {}
    common::GTElement c1;  // Z^{x_j r}
    common::GTElement c2;  // m * Z^r
};

class ProxyReEncryption {
  public:
    explicit ProxyReEncryption(const SystemParams& params) : params_(params) {}

    // Enc1: 生成 h_i^r, m*Z^r
    Ciphertext1 enc1(const KeyPair& kp, const common::GTElement& m) const {
        // 待学生实现：一次加密生成 (c1, c2)
        // 实现提示：
        // 1) Ciphertext1 ct(pairing) 初始化。
        // 2) 随机 r ∈ Z_r。
        // 3) c1 = h_i^r，使用 setPowZn(kp.pk(), r)。
        // 4) 计算 Z_r = Z^r；c2 = m * Z_r。
        // 5) 返回 ct。
        throw std::logic_error("TODO: 请实现 enc1");
    }

    // ReEnc: c1' = e(c1, rki→j) = Z^{x_j r}, c2' = c2
    Ciphertext2 reencrypt(const ReKey& rk, const Ciphertext1& ct) const {
        // 待学生实现：代理用 rk 生成第二阶段密文
        // 实现提示：
        // 1) Ciphertext2 out(pairing) 初始化。
        // 2) out.c1 = e(ct.c1, rk.value())，调用 setPairing。
        // 3) out.c2 直接复制 ct.c2（无需变动）。
        // 4) 返回 out。
        throw std::logic_error("TODO: 请实现 reencrypt");
    }

    // Dec2: m = c2' / (c1')^{1/x_j}，其中 c2' 就是传入的 ct.c2
    common::GTElement dec2(const KeyPair& kp, const Ciphertext2& ct) const {
        // 待学生实现：接收方用自身私钥解密第二阶段密文
        // 实现提示：
        // 1) inv_sk = sk^{-1}（Z_r 元素）。
        // 2) Z_r = (ct.c1)^{inv_sk} = Z^r。
        // 3) 求 Z_r 的逆 inv = (Z^r)^{-1}。
        // 4) m = ct.c2 * inv。
        // 5) 返回明文 m。
        throw std::logic_error("TODO: 请实现 dec2");
    }

  private:
    const SystemParams& params_;
};

int main() {
    SystemParams params;
    ProxyReEncryption pre(params);

    KeyPair alice(params.pairing(), params.g());
    KeyPair bob(params.pairing(), params.g());

    common::GTElement m = params.random_plaintext();

    Ciphertext1 ct_alice = pre.enc1(alice, m);
    ReKey rk = ReKey::derive(params.pairing(), alice, bob, params.g());
    Ciphertext2 ct_bob = pre.reencrypt(rk, ct_alice);
    common::GTElement recovered = pre.dec2(bob, ct_bob);

    std::cout << "g: " << hex(params.g()) << "\n";
    std::cout << "Z: " << hex(params.Z()) << "\n\n";

    std::cout << "Alice sk: " << hex(alice.sk()) << "\n";
    std::cout << "Alice pk: " << hex(alice.pk()) << "\n\n";
    std::cout << "Bob   sk: " << hex(bob.sk()) << "\n";
    std::cout << "Bob   pk: " << hex(bob.pk()) << "\n\n";

    std::cout << "Plaintext m (GT): " << hex(m) << "\n";
    std::cout << "Ciphertext (Alice) c1: " << hex(ct_alice.c1) << "\n";
    std::cout << "Ciphertext (Alice) c2: " << hex(ct_alice.c2) << "\n";
    std::cout << "ReKey k = g^{x_j/x_i}: " << hex(rk.value()) << "\n\n";

    std::cout << "Ciphertext (Bob) c1: " << hex(ct_bob.c1) << "\n";
    std::cout << "Ciphertext (Bob) c2: " << hex(ct_bob.c2) << "\n\n";

    std::cout << "Recovered m: " << hex(recovered) << "\n";
    std::cout << (element_cmp(m.get(), recovered.get()) == 0 ? "Re-encryption succeeded."
                                                             : "Mismatch!") << "\n";
    return 0;
}
