/**
 * KP-ABE (Key-Policy Attribute-Based Encryption) 实现
 * 基于 GPSW06 方案 (Goyal, Pandey, Sahai, Waters, 2006)
 *
 * 在KP-ABE中:
 * - 密文与属性集合关联
 * - 密钥与访问策略关联
 * - 只有当密文的属性满足密钥的策略时,才能成功解密
 */

#include <pbc/pbc.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "common.h"


 // 使用common中的RAII封装类
using common::G1Element;
using common::GTElement;
using common::ZrElement;

/**
 * 策略树节点
 * 表示访问策略的树形结构
 * - 叶子节点: 表示单个属性
 * - 内部节点: 表示阈值门(threshold gate)
 */
struct PolicyNode
{
    int threshold;  // 阈值:需要满足的子节点数量
    int index;      // 节点在父节点中的索引(用于拉格朗日插值)
    std::string attribute;  // 属性名(仅叶子节点使用)
    std::vector<std::unique_ptr<PolicyNode>> children;  // 子节点列表

    /**
     * 创建叶子节点(表示单个属性)
     * @param attr 属性名
     * @return 叶子节点指针
     */
    static std::unique_ptr<PolicyNode> Leaf(std::string attr) {
        auto node = std::make_unique<PolicyNode>();
        node->threshold = 1;
        node->index = 0;
        node->attribute = std::move(attr);
        return node;
    }

    /**
     * 创建内部节点(表示阈值门)
     * @param threshold 阈值(需要满足的子节点数量)
     * @param kids 子节点列表
     * @return 内部节点指针
     *
     * 例如:
     * - threshold=1: OR门(任意一个子节点满足即可)
     * - threshold=n(n为子节点总数): AND门(所有子节点都要满足)
     * - 1<threshold<n: 一般阈值门(至少threshold个子节点满足)
     */
    static std::unique_ptr<PolicyNode> Node(int threshold,
        std::vector<std::unique_ptr<PolicyNode>> kids) {
        auto node = std::make_unique<PolicyNode>();
        node->threshold = threshold;
        node->index = 0;
        node->children = std::move(kids);
        // 为每个子节点分配索引(从1开始,用于拉格朗日插值)
        for (size_t i = 0; i < node->children.size(); ++i) {
            node->children[i]->index = static_cast<int>(i) + 1;
        }
        return node;
    }
};

/**
 * 密钥树节点
 * 与策略树对应,存储解密所需的密钥组件
 */
struct KeyNode
{
    int threshold;  // 阈值(从策略树复制)
    int index;      // 节点索引(从策略树复制)
    std::string attribute;  // 属性名(仅叶子节点)
    std::vector<uint8_t> component;  // 密钥组件 D_x = g^{q_x(0)/t_i}
    std::vector<std::unique_ptr<KeyNode>> children;  // 子节点列表
};

/**
 * KP-ABE主类
 * 实现GPSW06方案的四个核心算法: Setup, KeyGen, Encrypt, Decrypt
 */
class KPABE
{
public:
    /**
     * 私钥结构
     * 包含与访问策略对应的密钥树
     */
    struct SecretKey
    {
        std::unique_ptr<KeyNode> root;  // 密钥树的根节点
    };

    /**
     * 密文结构
     * 包含属性集合和对应的密文组件
     */
    struct Ciphertext
    {
        std::vector<std::string> attributes;  // 密文关联的属性集合
        std::unordered_map<std::string, std::vector<uint8_t>> components;  // 每个属性的密文组件 C_i = T_i^s
        std::vector<uint8_t> payload;  // 加密的消息(使用对称加密)
    };

    /**
     * 构造函数
     * @param universe 属性全集
     * @param rbits 基域大小(比特)
     * @param qbits 椭圆曲线阶数大小(比特)
     */
    KPABE(std::vector<std::string> universe, int rbits = common::kDefaultRbits,
        int qbits = common::kDefaultQbits)
        : universe_(std::move(universe)),
        context_(rbits, qbits),
        g_(context_.pairing()),
        alpha_(context_.pairing()),
        pairing_alpha_(context_.pairing()),
        initialized_(false) {
    }

    /**
     * 析构函数
     * 清理密码学元素
     */
    ~KPABE() = default;

    /**
     * Setup算法
     * 生成系统公开参数和主密钥
     *
     * 公开参数 PK: g, e(g,g)^α, {T_i = g^{t_i}}_{i∈Universe}
     * 主密钥 MSK: α, {t_i}_{i∈Universe}
     */
    void setup() {
        // TODO: 学生在此补全 KP-ABE 的 Setup 步骤
        // 提示:
        // 1) 随机生成 g_ 与 alpha_。
        g_.randomize();
        alpha_.randomize();
        // 2) pairing_alpha_ = e(g_, g_)^alpha_（先算 e(g_,g_) 再 setPowZn）。
        auto egg = GTElement(context_.pairing());
        egg.setPairing(g_, g_, context_.pairing());
        pairing_alpha_.setPowZn(egg, alpha_);

        // 3) 对于每个属性 attribute:
        for (auto& attr : universe_) {
            //    - 生成非零 t_i 存入 attribute_secrets_;
            auto t_i = ZrElement(context_.pairing());
            t_i.randomize();
            attribute_secrets_[attr] = std::make_unique<ZrElement>(std::move(t_i));
            //    - 计算 T_i = g_^t_i 存入 attribute_publics_。
            auto T_i =  G1Element(context_.pairing());
            T_i.setPowZn(g_, t_i);
            attribute_publics_[attr] = std::make_unique<G1Element>(std::move(T_i));
            
        }
        // 4) 设置 initialized_ = true。
        initialized_ = true;
        return;
        throw std::logic_error("TODO: implement KPABE::setup (see comments)");
    }

    /**
     * KeyGen算法
     * 根据访问策略生成私钥
     *
     * @param policy 访问策略树
     * @return 私钥SK,包含策略树的每个节点对应的密钥组件
     *
     * 算法流程:
     * 1. 从根节点开始,将主密钥α作为秘密值
     * 2. 对于每个内部节点,使用阈值秘密共享分发秘密值给子节点
     * 3. 对于每个叶子节点x(对应属性i),计算 D_x = g^{q_x(0)/t_i}
     */
    SecretKey keygen(const PolicyNode& policy) {
        // TODO: 学生在此补全 KP-ABE 的 KeyGen
        // 提示:
        // 1) ensureInitialized();
        ensureInitialized();
        // 2) 分配 key.root，并调用 distributeSecret(policy, alpha_, *key.root) 递归生成密钥树。
        SecretKey sk;
        sk.root =  std::make_unique<KeyNode>();
        distributeSecret(policy, alpha_, *sk.root);
        // 3) 返回填充好的 SecretKey。
        return sk;
        throw std::logic_error("TODO: implement KPABE::keygen (see comments)");
    }

    /**
     * Encrypt算法
     * 使用属性集合加密消息
     *
     * @param attributes 属性集合
     * @param message 明文消息
     * @return 密文CT
     *
     * 算法流程:
     * 1. 随机选择 s ∈ Zr
     * 2. 计算共享密钥 K = e(g,g)^{αs}
     * 3. 对每个属性i,计算密文组件 C_i = T_i^s = g^{t_i·s}
     * 4. 使用K派生对称密钥加密消息
     */
    Ciphertext encrypt(const std::vector<std::string>& attributes,
        const std::vector<uint8_t>& message) {
        // TODO: 学生在此补全 KP-ABE 的 Encrypt
        // 提示:
        // 1) ensureInitialized(); 校验 attributes 非空。
        ensureInitialized();
        if (attributes.empty()) {
            throw std::runtime_error("attribute set cannot be empty");
        }
        Ciphertext ct;
        ct.attributes = attributes;
        // 2) 抽取随机 s；shared = pairing_alpha_^s = e(g,g)^{αs}。
        auto s = ZrElement(context_.pairing());
        s.randomize();
        auto shared = GTElement(context_.pairing());
        shared.setPowZn(pairing_alpha_, s);
        // 3) 对每个 attr: 取 T_i=getAttributePublic(attr)，计算 C_i = T_i^s，序列化存入 ct.components[attr]。
        for (auto & attr : attributes) {
            G1Element& T_i = getAttributePublic(attr);
            auto C_i = G1Element(context_.pairing());
            C_i.setPowZn(T_i, s);
            ct.components[attr] = common::serializeElement(C_i);
        }
        // 4) 使用 shared 生成密钥流，加密 message 到 ct.payload；填充 ct.attributes。
        auto keystream = common::sharedSecretToKeystream(shared, message.size());
        ct.payload = common::xorWithKeystream(message, keystream);
        return ct;
        throw std::logic_error("TODO: implement KPABE::encrypt (see comments)");
    }

    /**
     * Decrypt算法
     * 使用私钥解密密文
     *
     * @param key 私钥SK
     * @param ct 密文CT
     * @return 明文消息
     * @throws std::runtime_error 当属性不满足策略时
     *
     * 算法流程:
     * 1. 递归地从叶子节点向上计算,每个节点计算 e(D_x, C_i)
     * 2. 对于内部节点,使用拉格朗日插值恢复秘密值
     * 3. 最终在根节点恢复共享密钥 K = e(g,g)^{αs}
     * 4. 使用K解密消息
     */
    std::vector<uint8_t> decrypt(const SecretKey& key, const Ciphertext& ct) {
        // TODO: 学生在此补全 KP-ABE 的 Decrypt
        // 提示:
        // 1) ensureInitialized(); 检查 key.root 是否存在。
        ensureInitialized();
        if (key.root == nullptr) {
            throw std::runtime_error("invalid secret key");
        }
        // 2) 调用 decryptNode(*key.root, ct, aggregate) 递归聚合，若返回 false 抛出异常。
        auto aggregate = GTElement(context_.pairing());
        auto res = decryptNode(*key.root, ct, aggregate);
        if (!res) {
            throw std::runtime_error("attributes do not satisfy policy");
        }
        // 3) 使用 aggregate 生成 keystream 解密 ct.payload 并返回。
        auto keystream = common::sharedSecretToKeystream(aggregate, ct.payload.size()); 
        auto message = common::xorWithKeystream(ct.payload, keystream);
        return message;
        throw std::logic_error("TODO: implement KPABE::decrypt (see comments)");
    }

private:
    /**
     * 确保系统已初始化
     * @throws std::logic_error 如果系统未调用setup()
     */
    void ensureInitialized() const {
        if (!initialized_) {
            throw std::logic_error("KP-ABE system not setup");
        }
    }

private:
    // 获取属性的 msk 部分 (t_i)
    common::ZrElement& getAttributeSecret(const std::string& attr) {
        auto it = attribute_secrets_.find(attr);
        if (it == attribute_secrets_.end()) {
            throw std::invalid_argument("Attribute not in universe: " + attr);
        }
        return *(it->second);
    }

    // 获取属性的 pp 部分 (T_i)
    common::G1Element& getAttributePublic(const std::string& attr) {
        auto it = attribute_publics_.find(attr);
        if (it == attribute_publics_.end()) {
            throw std::invalid_argument("Attribute not in universe: " + attr);
        }
        return *(it->second);
    }

    /**
     * 分发秘密值(递归函数)
     * 使用Shamir秘密共享将秘密值分发给子节点
     *
     * @param policy 策略树节点
     * @param secret 当前节点的秘密值
     * @param node 密钥树节点(输出)
     *
     * 算法流程:
     * - 如果是叶子节点: 计算 D_x = g^{q_x(0)/t_i}
     * - 如果是内部节点:
     *   1. 构造阈值为k的随机多项式 q_x(z) = a_0 + a_1*z + ... + a_{k-1}*z^{k-1}
     *   2. 对每个子节点y,计算 q_x(index(y)) 并递归分发
     */
    void distributeSecret(const PolicyNode& policy, const ZrElement& secret, KeyNode& node) {
        node.threshold = policy.threshold;
        node.index = policy.index;
        node.attribute = policy.attribute;

        // 叶子节点:计算密钥组件
        if (policy.children.empty()) {
            common::ZrElement& t_i = getAttributeSecret(policy.attribute);  // 获取 msk 部分

            // 计算 1/t_i
            ZrElement inv_secret(context_.pairing());
            inv_secret.setInvert(t_i);

            // 计算 q_x(0)/t_i
            ZrElement exponent(context_.pairing());
            exponent.setMul(secret, inv_secret);

            // 计算 D_x = g^{q_x(0)/t_i}
            G1Element component(context_.pairing());
            component.setPowZn(g_, exponent);
            node.component = common::serializeElement(component);
            return;
        }

        // 内部节点:使用秘密共享
        // 构造阈值为k的随机多项式 q_x(z) = a_0 + a_1*z + ... + a_{k-1}*z^{k-1}
        // 其中 a_0 = secret
        std::vector<std::unique_ptr<ZrElement>> polynomial;
        polynomial.reserve(static_cast<size_t>(policy.threshold));
        polynomial.push_back(std::make_unique<ZrElement>(context_.pairing()));
        polynomial[0]->set(secret);  // a_0 = secret
        for (int i = 1; i < policy.threshold; ++i) {
            auto coeff = std::make_unique<ZrElement>(context_.pairing());
            coeff->randomize();  // 随机选择 a_i
            polynomial.push_back(std::move(coeff));
        }

        // 对每个子节点计算 q_x(index(y)) 并递归分发
        ZrElement child_secret(context_.pairing());
        node.children.clear();
        for (const auto& child : policy.children) {
            node.children.push_back(std::make_unique<KeyNode>());
            common::evaluatePolynomial(context_.pairing(), polynomial, child->index, child_secret);  // q_x(index(y))
            distributeSecret(*child, child_secret, *node.children.back());  // 递归分发
        }
    }



    /**
     * 解密节点(递归函数)
     * 从叶子节点向上递归计算,恢复共享密钥
     *
     * @param node 密钥树节点
     * @param ct 密文
     * @param out 输出值
     * @return true 如果节点满足, false 否则
     *
     * 算法流程:
     * - 叶子节点: 计算 e(D_x, C_i) = e(g^{q_x(0)/t_i}, g^{t_i*s}) = e(g,g)^{q_x(0)*s}
     * - 内部节点:
     *   1. 递归计算满足的子节点的值
     *   2. 如果满足的子节点数量 < 阈值,返回false
     *   3. 使用拉格朗日插值恢复: F_x = ∏_{i∈S} F_i^{Δ_{i,S}(0)}
     */
    bool decryptNode(const KeyNode& node, const Ciphertext& ct, GTElement& out) const {
        // 叶子节点:计算配对
        if (node.children.empty()) {
            if (node.component.empty()) {
                return false;
            }
            // 检查密文是否包含该属性
            auto it = ct.components.find(node.attribute);
            if (it == ct.components.end()) {
                return false;  // 属性不匹配
            }

            // 计算 e(D_x, C_i)
            G1Element D_attr(context_.pairing());  // D_x = g^{q_x(0)/t_i}
            G1Element C_attr(context_.pairing());  // C_i = g^{t_i*s}
            D_attr.fromBytes(node.component);
            C_attr.fromBytes(it->second);

            // e(D_x, C_i) = e(g^{q_x(0)/t_i}, g^{t_i*s}) = e(g,g)^{q_x(0)*s)
            out.setPairing(D_attr, C_attr, context_.pairing());
            return true;
        }

        // 内部节点:递归计算子节点
        std::vector<std::pair<int, GTElement>> child_values;
        for (const auto& child : node.children) {
            GTElement value(context_.pairing());
            if (decryptNode(*child, ct, value)) {
                child_values.emplace_back(child->index, std::move(value));
            }
        }

        // 检查是否满足阈值
        if (static_cast<int>(child_values.size()) < node.threshold) {
            return false;  // 不满足阈值
        }

        // 选择前 threshold 个满足的子节点
        std::vector<int> indexes;
        indexes.reserve(node.threshold);
        for (int i = 0; i < node.threshold; ++i) {
            indexes.push_back(child_values[i].first);
        }

        // 使用拉格朗日插值恢复: F_x = ∏_{i∈S} F_i^{Δ_{i,S}(0)}
        out.setOne();
        for (int i = 0; i < node.threshold; ++i) {
            ZrElement lambda(context_.pairing());  // 拉格朗日系数 Δ_{i,S}(0)
            common::lagrangeCoefficient(context_.pairing(), indexes, child_values[i].first, lambda);

            GTElement temp(context_.pairing());
            temp.setPowZn(child_values[i].second, lambda);  // F_i^{Δ_{i,S}(0)}
            out.setMul(out, temp);  // 累乘
        }

        return true;
    }



    // 成员变量
    std::vector<std::string> universe_;  // 属性全集
    common::PairingContext context_;     // 双线性配对上下文
    common::G1Element g_;                        // 生成元 g ∈ G1
    common::ZrElement alpha_;                    // 主密钥 α ∈ Zr
    common::GTElement pairing_alpha_;            // 公开参数 e(g,g)^α ∈ GT
    bool initialized_;                   // 系统是否已初始化
    // msk 部分：属性秘密值 {t_i}
    std::unordered_map<std::string, std::unique_ptr<common::ZrElement>> attribute_secrets_;
    // pp 部分：属性公开值 {T_i}
    std::unordered_map<std::string, std::unique_ptr<common::G1Element>> attribute_publics_;
};

/**
 * 主函数 - KP-ABE测试程序
 * 演示8个测试用例,包括策略满足和不满足的情况
 */
int main() {
    try {
        // 定义属性全集
        std::vector<std::string> universe = {"role:engineer",   "role:manager", "dept:security",
                                             "dept:rnd",        "clearance:top", "project:red"};

        // 初始化KP-ABE系统
        KPABE abe(universe);
        abe.setup();

        // 准备测试消息
        const std::string message = "Confidential Data";
        std::vector<uint8_t> message_bytes(message.begin(), message.end());

        // ========== 测试1: 简单叶子策略(满足) ==========
        // 策略: role:engineer
        // 密文属性: {role:engineer, dept:security}
        // 预期结果: 解密成功
        std::cout << "========== Test 1: Simple Leaf Policy (Satisfied) ==========\n";
        {
            auto policy = PolicyNode::Leaf("role:engineer");
            auto secret_key = abe.keygen(*policy);

            std::vector<std::string> attributes = {"role:engineer", "dept:security"};
            auto ciphertext = abe.encrypt(attributes, message_bytes);

            try {
                auto recovered = abe.decrypt(secret_key, ciphertext);
                std::cout << "✓ Decryption SUCCESS: "
                    << std::string(recovered.begin(), recovered.end()) << "\n\n";
            }
            catch (const std::exception& ex) {
                std::cout << "✗ Decryption FAILED: " << ex.what() << "\n\n";
            }
        }

        // ========== 测试2: 简单叶子策略(不满足) ==========
        // 策略: role:engineer
        // 密文属性: {role:manager, dept:security} (缺少role:engineer)
        // 预期结果: 解密失败
        std::cout << "========== Test 2: Simple Leaf Policy (NOT Satisfied) ==========\n";
        {
            auto policy = PolicyNode::Leaf("role:engineer");
            auto secret_key = abe.keygen(*policy);

            // 密文不包含 "role:engineer" 属性
            std::vector<std::string> attributes = {"role:manager", "dept:security"};
            auto ciphertext = abe.encrypt(attributes, message_bytes);

            try {
                auto recovered = abe.decrypt(secret_key, ciphertext);
                std::cout << "✓ Decryption SUCCESS: "
                    << std::string(recovered.begin(), recovered.end()) << "\n\n";
            }
            catch (const std::exception& ex) {
                std::cout << "✗ Decryption FAILED (Expected): " << ex.what() << "\n\n";
            }
        }

        // ========== 测试3: AND策略(2-of-2) - 满足 ==========
        // 策略: (role:engineer AND dept:security)
        // 密文属性: {role:engineer, dept:security, clearance:top}
        // 预期结果: 解密成功
        std::cout << "========== Test 3: AND Policy (2-of-2) - Satisfied ==========\n";
        {
            // 策略: (role:engineer AND dept:security)
            std::vector<std::unique_ptr<PolicyNode>> children;
            children.push_back(PolicyNode::Leaf("role:engineer"));
            children.push_back(PolicyNode::Leaf("dept:security"));
            auto policy = PolicyNode::Node(2, std::move(children));

            auto secret_key = abe.keygen(*policy);

            std::vector<std::string> attributes = {"role:engineer", "dept:security", "clearance:top"};
            auto ciphertext = abe.encrypt(attributes, message_bytes);

            try {
                auto recovered = abe.decrypt(secret_key, ciphertext);
                std::cout << "✓ Decryption SUCCESS: "
                    << std::string(recovered.begin(), recovered.end()) << "\n\n";
            }
            catch (const std::exception& ex) {
                std::cout << "✗ Decryption FAILED: " << ex.what() << "\n\n";
            }
        }

        // ========== 测试4: AND策略(2-of-2) - 不满足 ==========
        // 策略: (role:engineer AND dept:security)
        // 密文属性: {role:engineer, dept:rnd} (缺少dept:security)
        // 预期结果: 解密失败
        std::cout << "========== Test 4: AND Policy (2-of-2) - NOT Satisfied ==========\n";
        {
            // 策略: (role:engineer AND dept:security)
            std::vector<std::unique_ptr<PolicyNode>> children;
            children.push_back(PolicyNode::Leaf("role:engineer"));
            children.push_back(PolicyNode::Leaf("dept:security"));
            auto policy = PolicyNode::Node(2, std::move(children));

            auto secret_key = abe.keygen(*policy);

            // 密文只有 "role:engineer", 缺少 "dept:security"
            std::vector<std::string> attributes = {"role:engineer", "dept:rnd"};
            auto ciphertext = abe.encrypt(attributes, message_bytes);

            try {
                auto recovered = abe.decrypt(secret_key, ciphertext);
                std::cout << "✓ Decryption SUCCESS: "
                    << std::string(recovered.begin(), recovered.end()) << "\n\n";
            }
            catch (const std::exception& ex) {
                std::cout << "✗ Decryption FAILED (Expected): " << ex.what() << "\n\n";
            }
        }

        // ========== 测试5: OR策略(1-of-2) - 满足 ==========
        // 策略: (role:engineer OR role:manager)
        // 密文属性: {role:manager, dept:security} (有role:manager)
        // 预期结果: 解密成功
        std::cout << "========== Test 5: OR Policy (1-of-2) - Satisfied ==========\n";
        {
            // 策略: (role:engineer OR role:manager)
            std::vector<std::unique_ptr<PolicyNode>> children;
            children.push_back(PolicyNode::Leaf("role:engineer"));
            children.push_back(PolicyNode::Leaf("role:manager"));
            auto policy = PolicyNode::Node(1, std::move(children));

            auto secret_key = abe.keygen(*policy);

            // 有 "role:manager" 满足OR条件
            std::vector<std::string> attributes = {"role:manager", "dept:security"};
            auto ciphertext = abe.encrypt(attributes, message_bytes);

            try {
                auto recovered = abe.decrypt(secret_key, ciphertext);
                std::cout << "✓ Decryption SUCCESS: "
                    << std::string(recovered.begin(), recovered.end()) << "\n\n";
            }
            catch (const std::exception& ex) {
                std::cout << "✗ Decryption FAILED: " << ex.what() << "\n\n";
            }
        }

        // ========== 测试6: OR策略(1-of-2) - 不满足 ==========
        // 策略: (role:engineer OR role:manager)
        // 密文属性: {dept:security, clearance:top} (两个都没有)
        // 预期结果: 解密失败
        std::cout << "========== Test 6: OR Policy (1-of-2) - NOT Satisfied ==========\n";
        {
            // 策略: (role:engineer OR role:manager)
            std::vector<std::unique_ptr<PolicyNode>> children;
            children.push_back(PolicyNode::Leaf("role:engineer"));
            children.push_back(PolicyNode::Leaf("role:manager"));
            auto policy = PolicyNode::Node(1, std::move(children));

            auto secret_key = abe.keygen(*policy);

            // 既没有 "role:engineer" 也没有 "role:manager"
            std::vector<std::string> attributes = {"dept:security", "clearance:top"};
            auto ciphertext = abe.encrypt(attributes, message_bytes);

            try {
                auto recovered = abe.decrypt(secret_key, ciphertext);
                std::cout << "✓ Decryption SUCCESS: "
                    << std::string(recovered.begin(), recovered.end()) << "\n\n";
            }
            catch (const std::exception& ex) {
                std::cout << "✗ Decryption FAILED (Expected): " << ex.what() << "\n\n";
            }
        }

        // ========== 测试7: 阈值策略(2-of-3) - 满足 ==========
        // 策略: 2-of-3 (role:engineer, dept:security, clearance:top)
        // 密文属性: {role:engineer, clearance:top, project:red} (有2个)
        // 预期结果: 解密成功
        std::cout << "========== Test 7: Threshold Policy (2-of-3) - Satisfied ==========\n";
        {
            // 策略: 2-of-3 (role:engineer, dept:security, clearance:top)
            std::vector<std::unique_ptr<PolicyNode>> children;
            children.push_back(PolicyNode::Leaf("role:engineer"));
            children.push_back(PolicyNode::Leaf("dept:security"));
            children.push_back(PolicyNode::Leaf("clearance:top"));
            auto policy = PolicyNode::Node(2, std::move(children));

            auto secret_key = abe.keygen(*policy);

            // 有3个属性中的2个
            std::vector<std::string> attributes = {"role:engineer", "clearance:top", "project:red"};
            auto ciphertext = abe.encrypt(attributes, message_bytes);

            try {
                auto recovered = abe.decrypt(secret_key, ciphertext);
                std::cout << "✓ Decryption SUCCESS: "
                    << std::string(recovered.begin(), recovered.end()) << "\n\n";
            }
            catch (const std::exception& ex) {
                std::cout << "✗ Decryption FAILED: " << ex.what() << "\n\n";
            }
        }

        // ========== 测试8: 阈值策略(2-of-3) - 不满足 ==========
        // 策略: 2-of-3 (role:engineer, dept:security, clearance:top)
        // 密文属性: {role:engineer, dept:rnd, project:red} (只有1个)
        // 预期结果: 解密失败
        std::cout << "========== Test 8: Threshold Policy (2-of-3) - NOT Satisfied ==========\n";
        {
            // 策略: 2-of-3 (role:engineer, dept:security, clearance:top)
            std::vector<std::unique_ptr<PolicyNode>> children;
            children.push_back(PolicyNode::Leaf("role:engineer"));
            children.push_back(PolicyNode::Leaf("dept:security"));
            children.push_back(PolicyNode::Leaf("clearance:top"));
            auto policy = PolicyNode::Node(2, std::move(children));

            auto secret_key = abe.keygen(*policy);

            // 只有3个属性中的1个
            std::vector<std::string> attributes = {"role:engineer", "dept:rnd", "project:red"};
            auto ciphertext = abe.encrypt(attributes, message_bytes);

            try {
                auto recovered = abe.decrypt(secret_key, ciphertext);
                std::cout << "✓ Decryption SUCCESS: "
                    << std::string(recovered.begin(), recovered.end()) << "\n\n";
            }
            catch (const std::exception& ex) {
                std::cout << "✗ Decryption FAILED (Expected): " << ex.what() << "\n\n";
            }
        }

        // ========== 测试9: 嵌套策略 ((A AND B) OR C) - 满足 ==========
        // 策略: (role:engineer AND dept:security) OR clearance:top
        // 密文属性: {clearance:top, project:red} (满足右支)
        // 预期结果: 解密成功
        std::cout << "========== Test 9: Nested Policy ((A AND B) OR C) - Satisfied ==========\n";
        {
            // 左支: role:engineer AND dept:security (2-of-2)
            std::vector<std::unique_ptr<PolicyNode>> left_children;
            left_children.push_back(PolicyNode::Leaf("role:engineer"));
            left_children.push_back(PolicyNode::Leaf("dept:security"));
            auto left_branch = PolicyNode::Node(2, std::move(left_children));

            // 右支: clearance:top (叶子)
            auto right_branch = PolicyNode::Leaf("clearance:top");

            // 根节点: 1-of-2 (OR)
            std::vector<std::unique_ptr<PolicyNode>> root_children;
            root_children.push_back(std::move(left_branch));
            root_children.push_back(std::move(right_branch));
            auto policy = PolicyNode::Node(1, std::move(root_children));

            auto secret_key = abe.keygen(*policy);

            // 只有 clearance:top，满足右支
            std::vector<std::string> attributes = {"clearance:top", "project:red"};
            auto ciphertext = abe.encrypt(attributes, message_bytes);

            try {
                auto recovered = abe.decrypt(secret_key, ciphertext);
                std::cout << "✓ Decryption SUCCESS: "
                    << std::string(recovered.begin(), recovered.end()) << "\n\n";
            }
            catch (const std::exception& ex) {
                std::cout << "✗ Decryption FAILED: " << ex.what() << "\n\n";
            }
        }

        // ========== 测试10: 嵌套策略 (A AND (B OR C)) - 满足 ==========
        // 策略: role:engineer AND (dept:security OR dept:rnd)
        // 密文属性: {role:engineer, dept:rnd, project:red}
        // 预期结果: 解密成功
        std::cout << "========== Test 10: Nested Policy (A AND (B OR C)) - Satisfied ==========\n";
        {
            // 左支: role:engineer (叶子)
            auto left_branch = PolicyNode::Leaf("role:engineer");

            // 右支: dept:security OR dept:rnd (1-of-2)
            std::vector<std::unique_ptr<PolicyNode>> right_children;
            right_children.push_back(PolicyNode::Leaf("dept:security"));
            right_children.push_back(PolicyNode::Leaf("dept:rnd"));
            auto right_branch = PolicyNode::Node(1, std::move(right_children));

            // 根节点: 2-of-2 (AND)
            std::vector<std::unique_ptr<PolicyNode>> root_children;
            root_children.push_back(std::move(left_branch));
            root_children.push_back(std::move(right_branch));
            auto policy = PolicyNode::Node(2, std::move(root_children));

            auto secret_key = abe.keygen(*policy);

            // 有 role:engineer 和 dept:rnd，满足策略
            std::vector<std::string> attributes = {"role:engineer", "dept:rnd", "project:red"};
            auto ciphertext = abe.encrypt(attributes, message_bytes);

            try {
                auto recovered = abe.decrypt(secret_key, ciphertext);
                std::cout << "✓ Decryption SUCCESS: "
                    << std::string(recovered.begin(), recovered.end()) << "\n\n";
            }
            catch (const std::exception& ex) {
                std::cout << "✗ Decryption FAILED: " << ex.what() << "\n\n";
            }
        }

        // ========== 测试11: 深度嵌套 3层策略树 - 满足 ==========
        // 策略: ((A OR B) AND C) OR (D AND E)
        // 密文属性: {dept:security, clearance:top} (满足左支)
        // 预期结果: 解密成功
        std::cout << "========== Test 11: Deep Nested 3-Level Tree - Satisfied ==========\n";
        {
            // 左支的左子树: role:engineer OR role:manager (1-of-2)
            std::vector<std::unique_ptr<PolicyNode>> left_left_children;
            left_left_children.push_back(PolicyNode::Leaf("role:engineer"));
            left_left_children.push_back(PolicyNode::Leaf("role:manager"));
            auto left_left = PolicyNode::Node(1, std::move(left_left_children));

            // 左支的右子树: dept:security (叶子)
            auto left_right = PolicyNode::Leaf("dept:security");

            // 左支: (role:engineer OR role:manager) AND dept:security (2-of-2)
            std::vector<std::unique_ptr<PolicyNode>> left_children;
            left_children.push_back(std::move(left_left));
            left_children.push_back(std::move(left_right));
            auto left_branch = PolicyNode::Node(2, std::move(left_children));

            // 右支: clearance:top AND project:red (2-of-2)
            std::vector<std::unique_ptr<PolicyNode>> right_children;
            right_children.push_back(PolicyNode::Leaf("clearance:top"));
            right_children.push_back(PolicyNode::Leaf("project:red"));
            auto right_branch = PolicyNode::Node(2, std::move(right_children));

            // 根节点: 左支 OR 右支 (1-of-2)
            std::vector<std::unique_ptr<PolicyNode>> root_children;
            root_children.push_back(std::move(left_branch));
            root_children.push_back(std::move(right_branch));
            auto policy = PolicyNode::Node(1, std::move(root_children));

            auto secret_key = abe.keygen(*policy);

            // 有 role:manager 和 dept:security，满足左支
            std::vector<std::string> attributes = {"role:manager", "dept:security"};
            auto ciphertext = abe.encrypt(attributes, message_bytes);

            try {
                auto recovered = abe.decrypt(secret_key, ciphertext);
                std::cout << "✓ Decryption SUCCESS: "
                    << std::string(recovered.begin(), recovered.end()) << "\n\n";
            }
            catch (const std::exception& ex) {
                std::cout << "✗ Decryption FAILED: " << ex.what() << "\n\n";
            }
        }

        std::cout << "========== All Tests Completed ==========\n";

    }
    catch (const std::exception& ex) {
        std::cerr << "Fatal Error: " << ex.what() << "\n";
        return 1;
    }
    return 0;
}
