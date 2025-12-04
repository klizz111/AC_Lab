#include <pbc/pbc.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "common.h"

// FuzzyIBE 类：封装 Sahai-Waters Fuzzy IBE 方案
// 方案说明 (Sahai-Waters 2005):
// Setup(λ, d) → (pp, msk):
//   - 生成双线性映射群: G × G → G_T, q (素数阶), g ∈ G
//   - 选择主密钥 y ← Z_q
//   - 对每个属性 i ∈ Universe: 选择 t_i ← Z_q, 计算 T_i = g^{t_i}
//   - pp = (G, G_T, q, g, e, {T_i}, e(g,g)^y), msk = (y, {t_i}), d 为错误容忍阈值
//   - 注: 预计算 e(g,g)^y 存储在公开参数中，加快加密速度
// KeyGen(ω, msk) → sk_ω (其中 |ω| ≥ d):
//   - 构造 d-1 次随机多项式 q(x)，常数项 q(0) = y
//   - 对每个 i ∈ ω: 计算 D_i = g^{q(H(i))/t_i}
//   - sk_ω = {D_i}_{i∈ω}
// Enc(ω', m, pp) → c (其中 |ω'| ≥ d):
//   - 选择 s ← Z_q
//   - 对每个 i ∈ ω': 计算 C_i = T_i^s = g^{t_i·s}
//   - c = ({C_i}_{i∈ω'}, m ⊕ KDF(e(g,g)^{ys}))
// Dec(c, sk_ω) → m:
//   - 如果 |ω ∩ ω'| ≥ d, 选择 S ⊆ (ω ∩ ω'), |S| = d
//   - 计算 e(g,g)^{ys} = ∏_{i∈S} (e(C_i, D_i))^{λ_i}
//      其中 λ_i 为拉格朗日系数
//   - m = payload ⊕ KDF(e(g,g)^{ys})
//   - 正确性: e(C_i, D_i) = e(g^{t_i·s}, g^{q(H(i))/t_i}) = e(g,g)^{s·q(H(i))}
//            使用拉格朗日插值: ∏_{i∈S} e(g,g)^{s·q(H(i))·λ_i} = e(g,g)^{s·q(0)} = e(g,g)^{ys}

// 使用common中的RAII封装类
using common::ZrElement;
using common::GTElement;
using common::G1Element;

// FuzzyIBE：实现 Sahai-Waters Fuzzy IBE，身份=属性集合，阈值容错
class FuzzyIBE {
   public:
    // AttributeComponent 以 (attribute, serialized element) 表示密钥/密文字段
    struct AttributeComponent {
        std::string attribute;
        std::vector<uint8_t> value;
    };

    // PrivateKey = { (attr, D_attr) } 针对用户属性集的 share
    struct PrivateKey {
        std::vector<AttributeComponent> components;
    };

    // Ciphertext = { (attr, C_attr) } + 对称密文 payload
    struct Ciphertext {
        std::vector<AttributeComponent> components;
        std::vector<uint8_t> payload;
    };

    // universe 定义允许的属性全集，threshold 为可容忍的最多 |ω∩ω'| 下限
    FuzzyIBE(std::vector<std::string> universe, size_t threshold,
             int rbits = common::kDefaultRbits, int qbits = common::kDefaultQbits)
        : universe_(std::move(universe)),
          threshold_(threshold),
          context_(rbits, qbits),
          initialized_(false),
          generator_(context_.pairing()),
          public_component_(context_.pairing()),
          master_secret_(context_.pairing()) {
    }

    ~FuzzyIBE() = default;

    // setup(): 生成公开参数(pp)和主密钥(msk)
    // pp = (G, G_T, q, g, e, {T_i}, e(g,g)^y) - 公开
    // msk = (y, {t_i}) - 保密
    void setup() {
        // TODO: 学生在此补全 Fuzzy IBE 的 Setup 步骤
        // 提示:
        // 1) generator_.randomize() 生成 g；master_secret_.randomize() 生成 y。
        // 2) 先算 e(g,g)，再求 (e(g,g))^y 存入 public_component_（作为 pp）。
        // 3) 对于 universe_ 中的每个属性:
        //    - 生成非零 t_i；存入 attribute_secrets_；
        //    - 计算 T_i = g^{t_i}，存入 attribute_publics_。
        // 4) 设置 initialized_ = true。

        // 1)
        generator_.randomize();
        master_secret_.randomize();

        // 2)
        auto temp = GTElement(context_.pairing());
        temp.setPairing(generator_, generator_, context_.pairing());
        public_component_.setPowZn(temp, master_secret_);

        // 3)
        for (const auto& attr : universe_) {
            auto t_i = std::make_unique<ZrElement>(context_.pairing());

            do {
                t_i->randomize();
            } while (t_i->isZero());

            auto tt_i = std::make_unique<G1Element>(context_.pairing());
            tt_i->setPowZn(generator_, *t_i);

            attribute_secrets_.emplace(attr, std::move(t_i));
            attribute_publics_.emplace(attr, std::move(tt_i));
        }

        // 4)
        initialized_ = true;

        return;

        throw std::logic_error("TODO: implement FuzzyIBE::setup (see comments)");
    }

    // keygen(): 为拥有属性集合 ω 的用户生成私钥
    //   - 构造度为 threshold-1 的随机多项式 q(x)，常数项为主密钥 y
    //   - 对每个属性 i ∈ ω 计算 D_i = g^{q(H(i))/t_i}
    //   - 私钥为所有 D_i 的集合
    PrivateKey keygen(const std::vector<std::string>& identity) {
        // TODO: 学生在此补全 Fuzzy IBE 的 KeyGen
        // 提示:
        // 1) ensureInitialized(); 检查 identity.size() ≥ threshold_。
        // 2) 构造度 threshold_-1 的多项式 q，常数项设为 master_secret_，其他系数随机。
        // 3) 对每个属性 attr:
        //    - 取 t_attr = getAttributeSecret(attr)；
        //    - attr_scalar = Hash(attr) 作为 x 坐标；
        //    - q_value = q(attr_scalar)（evaluatePolynomial）；
        //    - exponent = q_value * (1/t_attr)；
        //    - D_attr = g^{exponent}；序列化后存入 key.components。

        // 1)
        ensureInitialized();
        if (identity.size() < threshold_) {
            throw std::invalid_argument("identity size less than threshold");
        }

        // 2)
        std::vector<ZrElement> coefficients;
        coefficients.reserve(threshold_);

        ZrElement c0(context_.pairing());
        c0.set(master_secret_);
        coefficients.emplace_back(std::move(c0));

        // 3)
        PrivateKey key;

        for (const auto& attr : identity) {
            try {
                auto& t_attr = getAttributeSecret(attr);

                auto attr_scalar = ZrElement(context_.pairing());
                attr_scalar.setFromHash(attr.data(), attr.size());

                auto q_value = ZrElement(context_.pairing());
                common::evaluatePolynomial(context_.pairing(), coefficients, attr_scalar, q_value);

                auto exponent = ZrElement(context_.pairing());
                exponent.setDiv(q_value, t_attr);

                auto D_attr = G1Element(context_.pairing());
                D_attr.setPowZn(generator_, exponent);

                AttributeComponent comp;
                comp.attribute = attr;
                comp.value = common::serializeElement(D_attr);       
                
                key.components.emplace_back(std::move(comp));
            } catch(...) {
                throw std::invalid_argument("attribute not part of universe: " + attr);
            }
        }

        return key;

        throw std::logic_error("TODO: implement FuzzyIBE::keygen (see comments)");
    }

    // encrypt(): 对目标身份(属性集合) ω' 加密
    //   - 随机 s ∈ Z_r
    //   - 计算 shared = (e(g,g)^y)^s = e(g,g)^{ys}
    //   - C_i = T_i^s, 并用 e(g,g)^{ys} 作为对称密钥
    Ciphertext encrypt(const std::vector<std::string>& receiver_identity,
                       const std::vector<uint8_t>& message) {
        // TODO: 学生在此补全 Fuzzy IBE 的 Encrypt
        // 提示:
        // 1) ensureInitialized(); 检查 receiver_identity.size() ≥ threshold_。
        // 2) 抽取随机 s；shared = public_component_^s = e(g,g)^{ys}。
        // 3) 对每个属性 attr: 取 T_attr=getAttributePublic(attr)，计算 C_attr = T_attr^s，序列化存入 ct.components。
        // 4) 用 shared 生成密钥流加密 message，得到 ct.payload。

        // 1)
        ensureInitialized();
        if (receiver_identity.size() < threshold_) {
            throw std::invalid_argument("receiver identity size less than threshold");
        }

        // 2)
        auto s = ZrElement(context_.pairing());
        s.randomize();

        auto shared = GTElement(context_.pairing());
        shared.setPowZn(public_component_, s);

        // 3)
        Ciphertext ct;

        for (auto& attr : receiver_identity) {
            try {
                auto& T_attr = getAttributePublic(attr);

                auto C_attr = G1Element(context_.pairing());
                C_attr.setPowZn(T_attr, s);

                AttributeComponent comp;
                comp.attribute = attr;
                comp.value = common::serializeElement(C_attr);

                ct.components.emplace_back(std::move(comp));
            } catch(...) {
                throw std::runtime_error("attribute not part of universe: " + attr);
            }
        }

        // 4)
        std::vector<uint8_t> keystream = common::sharedSecretToKeystream(shared, message.size());
        ct.payload = common::xorWithKeystream(message, keystream);

        return ct;
        
        throw std::logic_error("TODO: implement FuzzyIBE::encrypt (see comments)");
    }

    // decrypt(): 若 |ω ∩ ω'| ≥ threshold，则利用拉格朗日插值恢复 e(g,g)^{ys}
    std::vector<uint8_t> decrypt(const PrivateKey& key, const Ciphertext& ct) {
        // TODO: 学生在此补全 Fuzzy IBE 的 Decrypt
        // 提示:
        // 1) ensureInitialized(); 将 key.components 做成 map 方便查找。
        // 2) 遍历密文组件，找出与私钥重合的属性，收集前 threshold_ 个:
        //    - 反序列化 C_i、D_i，计算 pairing_result = e(C_i, D_i)；
        //    - 计算 attr_scalar = Hash(attr) 并序列化存储。
        // 3) 若重合数量不足 threshold_，抛出异常。
        // 4) 反序列化 pairing_result 与 attr_scalar，使用 lagrangeCoefficient 对 x=0 做插值，
        //    reconstructed = ∏ pairing_result^{λ_i}，得到 e(g,g)^{ys}。
        // 5) 用 reconstructed 派生密钥流解密 ct.payload。

        // 1)
        ensureInitialized();
        std::unordered_map<std::string, std::vector<uint8_t>> key_map;
        for (const auto& comp : key.components) {
            key_map[comp.attribute] = comp.value;
        }

        // 2)
        int count = 0;
        std::vector<G1Element> C;
        std::vector<G1Element> D;
        std::vector<GTElement> pairing_results;
        std::vector<ZrElement> attr_scalars;

        for (const auto& comp : ct.components) {
            auto it = key_map.find(comp.attribute);
            if (it != key_map.end()) {
                G1Element C_i(context_.pairing());
                C_i.fromBytes(comp.value.data());

                G1Element D_i(context_.pairing());
                D_i.fromBytes(it->second.data());

                GTElement pairing_result(context_.pairing());
                pairing_result.setPairing(C_i, D_i, context_.pairing());

                C.emplace_back(std::move(C_i));
                pairing_results.emplace_back(std::move(pairing_result));

                auto attr_scalar = ZrElement(context_.pairing());
                attr_scalar.setFromHash(comp.attribute.data(), comp.attribute.size());
                attr_scalars.emplace_back(std::move(attr_scalar));

                count++;
                if (count >= threshold_) {
                    break;
                }
            }
        }

        // 3)
        if (count < threshold_) {
            throw std::runtime_error("insufficient attribute overlap for decryption");
        }

        // 4)
        GTElement reconstructed(context_.pairing());
        reconstructed.setOne();

        for (size_t i = 0; i < pairing_results.size(); ++i) {
            ZrElement lambda(context_.pairing());
            common::lagrangeCoefficient(context_.pairing(), attr_scalars, i, lambda);

            GTElement term(context_.pairing());
            term.setPowZn(pairing_results[i], lambda);

            reconstructed.setMul(reconstructed, term);
        }

        // 5)
        std::vector<uint8_t> keystream = common::sharedSecretToKeystream(reconstructed, ct.payload.size());
        return common::xorWithKeystream(ct.payload, keystream);
        
        throw std::logic_error("TODO: implement FuzzyIBE::decrypt (see comments)");
    }

   private:
    // 确保 PKG 已执行 setup
    void ensureInitialized() const {
        if (!initialized_) {
            throw std::logic_error("Fuzzy IBE not initialized. Call setup() first.");
        }
    }

    // 读取属性对应的 msk 部分 (t_i)
    common::ZrElement& getAttributeSecret(const std::string& attr) {
        auto it = attribute_secrets_.find(attr);
        if (it == attribute_secrets_.end()) {
            throw std::invalid_argument("attribute not part of universe: " + attr);
        }
        return *(it->second);
    }

    // 读取属性对应的 pp 部分 (T_i)
    common::G1Element& getAttributePublic(const std::string& attr) {
        auto it = attribute_publics_.find(attr);
        if (it == attribute_publics_.end()) {
            throw std::invalid_argument("attribute not part of universe: " + attr);
        }
        return *(it->second);
    }

    std::vector<std::string> universe_;  // 属性全集
    size_t threshold_;                   // 允许的最小交集大小
    common::PairingContext context_;
    common::G1Element generator_;        // g
    common::GTElement public_component_;  // e(g,g)^y（预计算的配对值）
    common::ZrElement master_secret_;    // y
    bool initialized_;
    // msk 部分：每个属性的秘密值 {t_i}
    std::unordered_map<std::string, std::unique_ptr<common::ZrElement>> attribute_secrets_;
    // pp 部分：每个属性的公开值 {T_i}
    std::unordered_map<std::string, std::unique_ptr<common::G1Element>> attribute_publics_;
};

// 演示：Alice 满足策略 (student, dept:cs, country:us) 能解密，Bob 不满足失败
int main() {
    try {
        // 示例使用“特征”集合来代表身份（可类比生物特征/设备指纹），阈值按交集计数
        std::vector<std::string> universe = {"feat-height-tall",    "feat-voice-low",
                                             "feat-iris-blue",      "feat-city-sf",
                                             "feat-hobby-hiking",   "feat-lang-en",
                                             "feat-birth-1988",     "feat-fingerprint-arch",
                                             "feat-gait-fast",      "feat-typing-rhythm"};
        const size_t threshold = 3;

        FuzzyIBE fibe(universe, threshold);
        fibe.setup();

        auto overlapCount = [](const std::vector<std::string>& a,
                               const std::vector<std::string>& b) {
            std::unordered_set<std::string> set(a.begin(), a.end());
            size_t cnt = 0;
            for (const auto& attr : b) {
                if (set.count(attr)) {
                    ++cnt;
                }
            }
            return cnt;
        };

        // 策略属性集（密文携带），需要至少 threshold 个属性重合
        std::vector<std::string> receiver_identity = {"feat-height-tall",  "feat-voice-low",
                                                      "feat-iris-blue",    "feat-city-sf"};
        std::string message = "Hello from Sahai-Waters Fuzzy IBE!";
        std::vector<uint8_t> message_bytes(message.begin(), message.end());
        auto ciphertext = fibe.encrypt(receiver_identity, message_bytes);

        // Alice：交集 size=4，成功解密
        std::vector<std::string> alice_identity = {"feat-height-tall",  "feat-voice-low",
                                                   "feat-iris-blue",    "feat-city-sf",
                                                   "feat-hobby-hiking"};
        auto alice_key = fibe.keygen(alice_identity);
        auto plaintext = fibe.decrypt(alice_key, ciphertext);
        std::cout << "Alice overlap=" << overlapCount(alice_identity, receiver_identity)
                  << " >= " << threshold << ", Recovered message: "
                  << std::string(plaintext.begin(), plaintext.end()) << "\n";

        // Carol：正好等于阈值 3，也应成功
        std::vector<std::string> carol_identity = {"feat-height-tall", "feat-voice-low",
                                                   "feat-city-sf"};
        auto carol_key = fibe.keygen(carol_identity);
        auto carol_plain = fibe.decrypt(carol_key, ciphertext);
        std::cout << "Carol overlap=" << overlapCount(carol_identity, receiver_identity)
                  << " == " << threshold << ", Recovered message: "
                  << std::string(carol_plain.begin(), carol_plain.end()) << "\n";

        // Bob 只命中 1 个属性，交集不足阈值
        std::vector<std::string> bob_identity = {"feat-height-tall", "feat-lang-en",
                                                 "feat-birth-1988"};
        auto bob_key = fibe.keygen(bob_identity);
        try {
            auto bob_plain = fibe.decrypt(bob_key, ciphertext);
            std::cout << "[Unexpected] Bob (overlap="
                      << overlapCount(bob_identity, receiver_identity) << ") decrypted: "
                      << std::string(bob_plain.begin(), bob_plain.end()) << "\n";
        } catch (const std::exception& ex) {
            std::cout << "Bob failed (overlap=" << overlapCount(bob_identity, receiver_identity)
                      << " < " << threshold << "): " << ex.what() << "\n";
        }
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
    return 0;
}
