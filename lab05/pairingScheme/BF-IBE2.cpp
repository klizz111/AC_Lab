#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "common.h"

// 使用common中的RAII封装类
using common::ZrElement;
using common::G1Element;
using common::GTElement;

// IBE2 类：封装 Boneh-Franklin 随机化版本的 Setup / Keygen / Encrypt / Decrypt 流程
// 方案说明：
// Setup(λ) → (pp, msk):
//   - 生成双线性映射群: G × G → G_T, p, g ∈ G
//   - 选择随机数 α ∈ Z_p, Hash函数 H: {0,1}* → G
//   - pp = (G, G_T, p, g, e, H, e(g,g)^α), msk = g^α
// KeyGen(ID, msk) → sk_ID:
//   - 选择 r ← Z_p
//   - sk_ID = (d_1, d_2) = (g^α · H(ID)^r, g^r)
// Enc(pp, ID, m) → c:
//   - 选择 s ← Z_p
//   - c = (c_0, c_1, c_2) = (m ⊕ KDF(e(g,g)^(αs)), g^s, H(ID)^s)
// Dec(c, sk_ID) → m:
//   - 计算 K = e(d_1, c_1) / e(d_2, c_2) = e(g,g)^(αs)
//   - m = c_0 ⊕ KDF(K)
class IBE2 {
   public:
    // PrivateKey 保存身份字符串及两个元素 (d_1, d_2)
    // d_1 = g^α · H(ID)^r
    // d_2 = g^r
    struct PrivateKey {
        std::string identity;
        std::vector<uint8_t> d1_serialized;  // d_1 的序列化（位于 G1）
        std::vector<uint8_t> d2_serialized;  // d_2 的序列化（位于 G1）
    };

    // Ciphertext = (c_0, c_1, c_2, identity)
    // c_0 = m ⊕ KDF(e(g,g)^(αs)) （混合加密的对称密文部分）
    // c_1 = g^s （在 G1 中）
    // c_2 = H(ID)^s （在 G1 中）
    struct Ciphertext {
        std::string identity;
        std::vector<uint8_t> payload;  // 对称密文（m ⊕ KDF）
        std::vector<uint8_t> c1;  // G1 元素序列化
        std::vector<uint8_t> c2;  // G1 元素序列化
    };

    // 构造函数允许自定义安全参数；默认使用 rbits=256, qbits=1536
    explicit IBE2(int rbits = common::kDefaultRbits, int qbits = common::kDefaultQbits)
        : rbits_(rbits),
          qbits_(qbits),
          context_(rbits, qbits),
          initialized_(false),
          generator_(context_.pairing()),
          master_secret_(context_.pairing()),
          master_key_(context_.pairing()),
          pairing_value_(context_.pairing()) {}

    IBE2(const IBE2&) = delete;
    IBE2& operator=(const IBE2&) = delete;

    ~IBE2() = default;

    // setup()：PKG 初始化阶段，只能调用一次
    // 1. 随机选择 G1 的生成元 g；
    // 2. 随机抽取 α ∈ Z_r；
    // 3. 计算 master_key = g^α (主密钥 msk) 和 pairing_value = e(g,g)^α (公共参数)。
    void setup() {
        // TODO: 学生在此补全随机化 BF-IBE 的 Setup 步骤
        // 提示:
        // 1) generator_.randomize() 生成 g；master_secret_.randomize() 生成 α。
        // 2) master_key_ = g^α (setPowZn)，作为 msk。
        // 3) 先算 e(g,g)，再求 (e(g,g))^α，存入 pairing_value_。
        // 4) 设置 initialized_ = true。

        // 1)
        generator_.randomize();
        master_secret_.randomize();

        // 2)
        master_key_.setPowZn(generator_, master_secret_);

        // 3)
        auto temp = GTElement(context_.pairing());
        temp.setPairing(generator_, generator_, context_.pairing());
        pairing_value_.setPowZn(temp, master_secret_);

        // 4)
        initialized_ = true;

        return;

        throw std::logic_error("TODO: implement IBE2::setup (see comments)");
    }

    // keygen()：PKG 按身份字符串生成用户私钥
    // 1. 计算 Q_ID = H(identity) ∈ G1；
    // 2. 选择随机 r ∈ Z_r；
    // 3. 计算 d_1 = g^α · Q_ID^r 和 d_2 = g^r。
    PrivateKey keygen(const std::string& identity) {
        // TODO: 学生在此补全随机化 BF-IBE 的 KeyGen
        // 提示:
        // 1) ensureInitialized(); 计算 q_id = H(identity)。
        // 2) 随机 r ∈ Z_r；计算 d_2 = g^r。
        // 3) 计算 q_id^r；再计算 d_1 = master_key_ * q_id^r （setMul）。
        // 4) 返回 PrivateKey{identity, serialize(d1), serialize(d2)}。

        // 1)
        ensureInitialized();
        auto q_id = G1Element(context_.pairing());
        common::hashStringToG1(context_.pairing(), identity, q_id);

        // 2) 
        auto r = ZrElement(context_.pairing());
        r.randomize();

        auto d2 = G1Element(context_.pairing());
        d2.setPowZn(generator_, r);

        // 3)
        auto qidr = G1Element(context_.pairing());
        qidr.setPowZn(q_id, r);

        auto d1 = G1Element(context_.pairing());
        d1.setMul(master_key_, qidr);

        // 4)
        return PrivateKey{identity, common::serializeElement(d1), common::serializeElement(d2)};

        throw std::logic_error("TODO: implement IBE2::keygen (see comments)");
    }

    // encrypt()：发送方使用随机化版本加密消息（混合加密方案）
    // 1. 计算 Q_ID = H(identity)；
    // 2. 选择随机 s ∈ Z_r；
    // 3. 计算 mask = e(g,g)^(αs)，通过 KDF 派生密钥流；
    // 4. 计算 c_0 = m ⊕ KDF(mask), c_1 = g^s, c_2 = Q_ID^s。
    Ciphertext encrypt(const std::string& identity, const std::vector<uint8_t>& message) {
        // TODO: 学生在此补全随机化 BF-IBE 的 Encrypt
        // 提示:
        // 1) ensureInitialized(); 计算 q_id = H(identity)。
        // 2) 随机 s；c1 = g^s；c2 = q_id^s。
        // 3) mask = pairing_value_^s = e(g,g)^(αs)。
        // 4) 生成 keystream 加密 message，返回 Ciphertext{identity, payload, serialize(c1), serialize(c2)}。

        // 1)
        ensureInitialized();

        auto q_id = G1Element(context_.pairing());
        common::hashStringToG1(context_.pairing(), identity, q_id);

        // 2)
        auto s = ZrElement(context_.pairing());
        s.randomize();

        auto c1 = G1Element(context_.pairing());
        c1.setPowZn(generator_, s);

        auto c2 = G1Element(context_.pairing());
        c2.setPowZn(q_id, s);

        // 3)        
        auto mask = GTElement(context_.pairing());
        mask.setPowZn(pairing_value_, s);
        
        // 4)
        auto keystream = common::sharedSecretToKeystream(mask, message.size());

        return Ciphertext{  identity, common::xorWithKeystream(message, keystream),
                            common::serializeElement(c1), common::serializeElement(c2)};

        throw std::logic_error("TODO: implement IBE2::encrypt (see comments)");
    }

    // decrypt()：接收方使用私钥 (d_1, d_2) 解密
    // 1. 恢复 mask = e(d_1, c_1) / e(d_2, c_2)
    //    验证：e(d_1, c_1) / e(d_2, c_2) 
    //        = e(g^α · H(ID)^r, g^s) / e(g^r, H(ID)^s)
    //        = e(g^α, g^s) · e(H(ID)^r, g^s) / e(g^r, H(ID)^s)
    //        = e(g,g)^(αs) · e(H(ID), g)^(rs) / e(g, H(ID))^(rs)
    //        = e(g,g)^(αs)
    // 2. 恢复消息 m = c_0 / mask。
    std::vector<uint8_t> decrypt(const PrivateKey& sk, const Ciphertext& ct) {
        // TODO: 学生在此补全随机化 BF-IBE 的 Decrypt
        // 提示:
        // 1) ensureInitialized(); 校验身份一致。
        // 2) 反序列化 d1、d2、c1、c2。
        // 3) numerator = e(d1, c1); denominator = e(d2, c2); 求逆 denominator.invert()。
        // 4) mask = numerator * denominator；用 mask 生成密钥流解密 payload。

        // 1)
        ensureInitialized();
        if (sk.identity != ct.identity) {
            throw std::invalid_argument("Identity mismatch");
        }

        // 2)
        auto d1 = G1Element(context_.pairing());
        auto d2 = G1Element(context_.pairing());
        auto c1 = G1Element(context_.pairing());
        auto c2 = G1Element(context_.pairing());

        d1.fromBytes(sk.d1_serialized);
        d2.fromBytes(sk.d2_serialized);
        c1.fromBytes(ct.c1);
        c2.fromBytes(ct.c2);

        // 3)
        auto numerator = GTElement(context_.pairing());
        numerator.setPairing(d1, c1, context_.pairing());

        auto denominator = GTElement(context_.pairing());       
        denominator.setPairing(d2, c2, context_.pairing());
        denominator.invert();

        // 4)
        auto mask = GTElement(context_.pairing());
        mask.setMul(numerator, denominator);

        auto keystream = common::sharedSecretToKeystream(mask, ct.payload.size());

        return common::xorWithKeystream(ct.payload, keystream);

        throw std::logic_error("TODO: implement IBE2::decrypt (see comments)");
    }

    int subgroupBitLength() const { return rbits_; }
    int fieldBitLength() const { return qbits_; }

   private:
    // 辅助函数：保证用户在调用 keygen/encrypt/decrypt 前已经执行过 setup()
    void ensureInitialized() const {
        if (!initialized_) {
            throw std::logic_error("IBE2 system is not initialized. Call setup() first.");
        }
    }

    const int rbits_;
    const int qbits_;
    common::PairingContext context_;
    common::G1Element generator_;        // 公开生成元 g
    common::ZrElement master_secret_;    // PKG 主密钥参数 α (保密)
    common::G1Element master_key_;       // msk = g^α (主密钥，保密)
    common::GTElement pairing_value_;    // e(g,g)^α
    bool initialized_;
};

int main() {
    try {
        // 默认使用 rbits=256, qbits=1536
        IBE2 ibe;
        ibe.setup();

        // ==== 测试 1：ALICE 身份：生成私钥、加密、解密 ====
        const std::string alice_id = "alice@example.com";
        const std::string alice_message = "Hello from Randomized BF-IBE!";
        std::vector<uint8_t> alice_bytes(alice_message.begin(), alice_message.end());

        auto alice_sk = ibe.keygen(alice_id);
        auto alice_ct = ibe.encrypt(alice_id, alice_bytes);
        auto alice_pt = ibe.decrypt(alice_sk, alice_ct);

        std::cout << "Type A params (rbits= " << ibe.subgroupBitLength()
                  << ", qbits= " << ibe.fieldBitLength() << ")\n";
        std::cout << "[Alice] Identity: " << alice_id << '\n';
        std::cout << "[Alice] Private Key d1 (hex): " << common::toHex(alice_sk.d1_serialized) << '\n';
        std::cout << "[Alice] Private Key d2 (hex): " << common::toHex(alice_sk.d2_serialized) << '\n';
        std::cout << "[Alice] Ciphertext payload (hex): " << common::toHex(alice_ct.payload) << '\n';
        std::cout << "[Alice] Ciphertext c1 (hex): " << common::toHex(alice_ct.c1) << '\n';
        std::cout << "[Alice] Ciphertext c2 (hex): " << common::toHex(alice_ct.c2) << '\n';
        std::cout << "[Alice] Decrypted message: "
                  << std::string(alice_pt.begin(), alice_pt.end()) << "\n\n";

        // ==== 测试 2：BOB 身份 ====
        const std::string bob_id = "bob@example.com";
        const std::string bob_message = "Randomized BF-IBE second identity test.";
        std::vector<uint8_t> bob_bytes(bob_message.begin(), bob_message.end());

        auto bob_sk = ibe.keygen(bob_id);
        auto bob_ct = ibe.encrypt(bob_id, bob_bytes);
        auto bob_pt = ibe.decrypt(bob_sk, bob_ct);

        std::cout << "[Bob] Identity: " << bob_id << '\n';
        std::cout << "[Bob] Private Key d1 (hex): " << common::toHex(bob_sk.d1_serialized) << '\n';
        std::cout << "[Bob] Private Key d2 (hex): " << common::toHex(bob_sk.d2_serialized) << '\n';
        std::cout << "[Bob] Ciphertext payload (hex): " << common::toHex(bob_ct.payload) << '\n';
        std::cout << "[Bob] Ciphertext c1 (hex): " << common::toHex(bob_ct.c1) << '\n';
        std::cout << "[Bob] Ciphertext c2 (hex): " << common::toHex(bob_ct.c2) << '\n';
        std::cout << "[Bob] Decrypted message: "
                  << std::string(bob_pt.begin(), bob_pt.end()) << "\n\n";

        // ==== 测试 3：错误身份解密（验证身份绑定） ====
        try {
            (void)ibe.decrypt(bob_sk, alice_ct);
            std::cerr << "[Mismatch] Unexpectedly succeeded decrypting with wrong identity!\n";
        } catch (const std::exception& mismatch) {
            std::cout << "[Mismatch] 正确地拒绝了错误身份的解密请求: " << mismatch.what()
                      << "\n";
        }

        // ==== 测试 4：同一身份多次提取密钥应产生不同随机化私钥 ====
        auto alice_sk2 = ibe.keygen(alice_id);
        std::cout << "\n[Randomization Test] Alice's second key extraction:\n";
        std::cout << "  First d1:  " << common::toHex(alice_sk.d1_serialized) << '\n';
        std::cout << "  Second d1: " << common::toHex(alice_sk2.d1_serialized) << '\n';
        std::cout << "  First d2:  " << common::toHex(alice_sk.d2_serialized) << '\n';
        std::cout << "  Second d2: " << common::toHex(alice_sk2.d2_serialized) << '\n';
        
        // 验证第二个密钥也能正确解密
        auto alice_pt2 = ibe.decrypt(alice_sk2, alice_ct);
        std::cout << "  Decrypted with second key: "
                  << std::string(alice_pt2.begin(), alice_pt2.end()) << "\n";

    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << '\n';
        return 1;
    }
    return 0;
}
