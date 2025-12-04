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

// IBE 类：封装 Boneh-Franklin BasicIdent 方案的 Setup / Keygen / Encrypt / Decrypt 流程
// 方案说明 (Boneh-Franklin 2001):
// Setup(λ) → (pp, msk):
//   - 生成双线性映射群: G × G → G_T, q (素数阶), g ∈ G
//   - 选择主密钥 s ← Z_q, 哈希函数 H1: {0,1}* → G
//   - pp = (G, G_T, q, g, e, H1, P_pub = g^s), msk = s
// KeyGen(ID, msk) → sk_ID:
//   - 计算 Q_ID = H1(ID) ∈ G
//   - sk_ID = d_ID = Q_ID^s
// Enc(pp, ID, m) → c:
//   - 选择 r ← Z_q
//   - 计算 gid = e(H1(ID), P_pub) ∈ G_T
//   - c = (U, V) = (g^r, m ⊕ KDF(gid^r))
// Dec(c, sk_ID) → m:
//   - m = V ⊕ KDF(e(d_ID, U))
//   - 正确性: e(d_ID, U) = e(Q_ID^s, g^r) = e(Q_ID, g)^{sr} = e(Q_ID, g^s)^r = e(Q_ID, P_pub)^r = gid^r
class IBE {
   public:
    // PrivateKey 保存身份字符串及用户私钥
    // sk_ID = d_ID = H1(ID)^s (位于 G1)
    struct PrivateKey {
        std::string identity;
        std::vector<uint8_t> serialized;  // d_ID 的序列化
    };

    // Ciphertext = (U, payload, identity)  
    // U = g^r (位于 G1)
    // payload = m ⊕ KDF(e(H1(ID), P_pub)^r) (混合加密的对称密文部分)
    struct Ciphertext {
        std::string identity;
        std::vector<uint8_t> U;       // U = g^r 的序列化
        std::vector<uint8_t> payload;  // 加密后的消息（使用流密码）
    };

    // 构造函数允许自定义安全参数；默认使用 rbits=256, qbits=1536
    explicit IBE(int rbits = common::kDefaultRbits, int qbits = common::kDefaultQbits)
        : rbits_(rbits),
          qbits_(qbits),
          context_(rbits, qbits),
          initialized_(false),
          generator_(context_.pairing()),
          master_secret_(context_.pairing()),
          public_point_(context_.pairing()) {}

    IBE(const IBE&) = delete;
    IBE& operator=(const IBE&) = delete;

    ~IBE() = default;

    // setup()：PKG 初始化阶段，只能调用一次
    // 1. 随机选择 G1 的生成元 g；
    // 2. 随机抽取主密钥 master_secret ∈ Z_r；
    // 3. 计算公共参数 P_pub = g^{master_secret} 并对外公开。
    void setup() {
        // TODO: 学生在此补全 BF-IBE 的 Setup 步骤
        // 提示:
        // 1) 使用 generator_.randomize() 随机生成 G1 生成元 g。
        // 2) 使用 master_secret_.randomize() 生成主密钥 s ∈ Z_r。
        // 3) 调用 public_point_.setPowZn(g, s) 计算 P_pub = g^s。
        // 4) 设置 initialized_ = true; 表示系统已完成初始化。
        generator_.randomize();
        master_secret_.randomize();
        public_point_.setPowZn(generator_,master_secret_);
        initialized_ = true;

        return;

        throw std::logic_error("TODO: implement BF-IBE::setup (see comments)");
    }

    // keygen()：PKG 按身份字符串生成用户私钥
    // 1. 计算 Q_ID = H1(identity) ∈ G1；
    // 2. 输出 d_ID = Q_ID^{master_secret}，供该身份安全分发。
    PrivateKey keygen(const std::string& identity) {
        // TODO: 学生在此补全 BF-IBE 的 KeyGen 步骤
        // 提示:
        // 1) 调用 ensureInitialized() 确保已 setup。
        // 2) 定义 G1Element q_id，调用 common::hashStringToG1(pairing, identity, q_id) 得到 H1(ID)。
        // 3) 定义 G1Element d_id，计算 d_id = q_id^master_secret_（setPowZn）。
        // 4) 返回 PrivateKey{identity, common::serializeElement(d_id)}。
        ensureInitialized();
        G1Element q_id(context_.pairing());
        common::hashStringToG1(context_.pairing(), identity, q_id);
        G1Element d_id(context_.pairing());
        d_id.setPowZn(q_id, master_secret_);

        return PrivateKey{identity, common::serializeElement(d_id)};

        throw std::logic_error("TODO: implement BF-IBE::keygen (see comments)");
    }

    // encrypt()：发送方使用 BasicIdent 流程加密消息
    // 1. 计算 Q_ID = H1(identity)；
    // 2. 挑选随机 r ∈ Z_r，并令 U = g^r；
    // 3. 计算共享秘密 K = e(Q_ID, P_pub)^r；
    // 4. 将 K 通过 KDF 拓展为密钥流，再与消息异或得到 payload。
    Ciphertext encrypt(const std::string& identity, const std::vector<uint8_t>& message) {
        // TODO: 学生在此补全 BF-IBE 的 Encrypt 步骤
        // 提示:
        // 1) ensureInitialized(); 并计算 q_id = H1(identity)。
        // 2) 抽取随机 r ∈ Z_r；计算 U = g^r（G1）。
        // 3) 计算 pairing_value = e(q_id, public_point_)，再算 shared = pairing_value^r。
        // 4) 使用 common::sharedSecretToKeystream(shared, message.size()) 生成密钥流，
        //    与 message 异或得到 payload。
        // 5) 返回 Ciphertext{identity, serialize(U), payload}。

        // 1)
        ensureInitialized();

        auto q_id = G1Element(context_.pairing());
        common::hashStringToG1(context_.pairing(), identity, q_id);

        // 2)
        auto r = ZrElement(context_.pairing());
        r.randomize();

        auto U = G1Element(context_.pairing());
        U.setPowZn(generator_, r);

        // 3)
        auto pairing_value = GTElement(context_.pairing());
        pairing_value.setPairing(q_id, public_point_, context_.pairing());

        auto shared = GTElement(context_.pairing());   
        shared.setPowZn(pairing_value, r);

        // 4)
        auto keystream = common::sharedSecretToKeystream(shared, message.size());
        auto payload = common::xorWithKeystream(message, keystream);

        return Ciphertext{identity, common::serializeElement(U), payload};

        throw std::logic_error("TODO: implement BF-IBE::encrypt (see comments)");
    }

    // decrypt()：接收方使用私钥 d_ID 解密
    // 1. 计算共享秘密 K = e(d_ID, U)；
    //    验证：e(d_ID, U) = e(Q_ID^msk, g^r) = e(Q_ID, g)^{msk*r} = e(Q_ID, g^msk)^r = e(Q_ID, P_pub)^r
    // 2. 恢复消息 payload ⊕ KDF(K)。
    std::vector<uint8_t> decrypt(const PrivateKey& sk, const Ciphertext& ct) {
        // TODO: 学生在此补全 BF-IBE 的 Decrypt 步骤
        // 提示:
        // 1) ensureInitialized(); 并检查 sk.identity 与 ct.identity 是否一致，否则抛出异常。
        // 2) 反序列化私钥 d_ID 与密文 U：d_id.fromBytes(sk.serialized); U.fromBytes(ct.U)。
        // 3) 计算 shared = e(d_ID, U)。
        // 4) 用 shared 生成密钥流并与 ct.payload 异或得到明文。

        // 1)
        ensureInitialized();
        if (sk.identity != ct.identity) {
            throw std::invalid_argument("Identity mismatch");
        }

        // 2)
        auto d_id = G1Element(context_.pairing());
        d_id.fromBytes(sk.serialized);

        auto U = G1Element(context_.pairing());
        U.fromBytes(ct.U);

        // 3)
        auto shared = GTElement(context_.pairing());
        shared.setPairing(d_id, U, context_.pairing());

        // 4)
        auto keystream = common::sharedSecretToKeystream(shared, ct.payload.size());
        auto plaintext = common::xorWithKeystream(ct.payload, keystream);

        return plaintext;

        throw std::logic_error("TODO: implement BF-IBE::decrypt (see comments)");
    }

    int subgroupBitLength() const { return rbits_; }
    int fieldBitLength() const { return qbits_; }

   private:
    // 辅助函数：保证用户在调用 keygen/encrypt/decrypt 前已经执行过 setup()
    void ensureInitialized() const {
        if (!initialized_) {
            throw std::logic_error("IBE system is not initialized. Call setup() first.");
        }
    }

    // rbits_/qbits_ 决定 Type A 曲线参数，context_ 封装 pairing_t 生命周期
    const int rbits_;
    const int qbits_;
    common::PairingContext context_;
    common::G1Element generator_;     // 公开生成元 g
    common::ZrElement master_secret_; // PKG 主密钥 msk
    common::G1Element public_point_;  // P_pub = g^msk
    bool initialized_;
};

int main() {
    try {
        // 默认使用 rbits=256, qbits=1536，可自行调整构造函数参数
        IBE ibe;
        ibe.setup();

        // ==== 测试 1：ALICE 身份：生成私钥、加密、解密 ====
        const std::string alice_id = "alice@example.com";
        const std::string alice_message = "Hello from Boneh-Franklin IBE!";
        std::vector<uint8_t> alice_bytes(alice_message.begin(), alice_message.end());

        auto alice_sk = ibe.keygen(alice_id);
        auto alice_ct = ibe.encrypt(alice_id, alice_bytes);
        auto alice_pt = ibe.decrypt(alice_sk, alice_ct);

        std::cout << "Type A params (rbits= " << ibe.subgroupBitLength()
                  << ", qbits= " << ibe.fieldBitLength() << ")\n";
        std::cout << "[Alice] Identity: " << alice_id << '\n';
        std::cout << "[Alice] Ciphertext U (hex): " << common::toHex(alice_ct.U) << '\n';
        std::cout << "[Alice] Ciphertext V (hex): " << common::toHex(alice_ct.payload) << '\n';
        std::cout << "[Alice] Decrypted message: "
                  << std::string(alice_pt.begin(), alice_pt.end()) << "\n\n";

        // ==== 测试 2：BOB 身份 ====
        const std::string bob_id = "bob@example.com";
        const std::string bob_message = "Boneh-Franklin IBE second identity test.";
        std::vector<uint8_t> bob_bytes(bob_message.begin(), bob_message.end());

        auto bob_sk = ibe.keygen(bob_id);
        auto bob_ct = ibe.encrypt(bob_id, bob_bytes);
        auto bob_pt = ibe.decrypt(bob_sk, bob_ct);

        std::cout << "[Bob] Identity: " << bob_id << '\n';
        std::cout << "[Bob] Ciphertext U (hex): " << common::toHex(bob_ct.U) << '\n';
        std::cout << "[Bob] Ciphertext V (hex): " << common::toHex(bob_ct.payload) << '\n';
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
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << '\n';
        return 1;
    }
    return 0;
}
