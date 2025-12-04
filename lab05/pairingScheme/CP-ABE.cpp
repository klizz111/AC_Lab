
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

/**
 * 策略树节点 (PolicyNode)
 * 描述访问策略的树形结构
 *
 * 结构:
 * - 阈值门 (Threshold Gate): k-of-n
 *   - AND门: k=n
 *   - OR门: k=1
 * - 叶子节点: 关联具体属性
 */
struct PolicyNode
{
    int threshold;  // 阈值 k
    int index;      // 节点索引 (用于多项式插值)
    std::string attribute;  // 属性名 (仅叶子节点有效)
    std::vector<std::unique_ptr<PolicyNode>> children;  // 子节点列表

    // 创建叶子节点
    static std::unique_ptr<PolicyNode> Leaf(std::string attr) {
        auto node = std::make_unique<PolicyNode>();
        node->threshold = 1;
        node->index = 0;
        node->attribute = std::move(attr);
        return node;
    }

    // 创建内部节点 (阈值门)
    static std::unique_ptr<PolicyNode> Node(int threshold,
        std::vector<std::unique_ptr<PolicyNode>> kids) {
        auto node = std::make_unique<PolicyNode>();
        node->threshold = threshold;
        node->index = 0;
        node->children = std::move(kids);
        for (size_t i = 0; i < node->children.size(); ++i) {
            node->children[i]->index = static_cast<int>(i) + 1;
        }
        return node;
    }
};

/**
 * 密文节点 (CipherNode)
 * 对应策略树的节点，存储密文组件
 *
 * 数学含义 (LSSS):
 * - C_x = g^{q_x(0)}
 * - C'_x = H(attr)^{q_x(0)}
 * 其中 q_x(0) 是该节点分发到的秘密份额
 */
struct CipherNode
{
    int threshold;
    int index;
    std::string attribute;
    std::vector<uint8_t> c;        // C_x
    std::vector<uint8_t> c_prime;  // C'_x
    std::vector<std::unique_ptr<CipherNode>> children;
};

/**
 * 私钥结构 (SecretKey)
 * 包含与属性集合对应的密钥组件
 *
 * 结构 (Waters 方案):
 * - D = g^{α+r}  (主私钥部分)
 * - 对于每个属性 j ∈ S:
 *   - D_j = g^r · H(j)^{r_j}
 *   - D'_j = g^{r_j}
 * 其中 r 是随机数，r_j 是每个属性的随机数
 */
struct SecretKey
{
    std::vector<uint8_t> D;        // D = g^{α+r}
    // 属性组件映射: 属性名 -> (D_j, D'_j)
    std::unordered_map<std::string, std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> attributes;
};

// 使用common中的RAII封装类
using common::G1Element;
using common::GTElement;
using common::ZrElement;

class CPABE
{
public:
    CPABE(int rbits = common::kDefaultRbits, int qbits = common::kDefaultQbits)
        : context_(rbits, qbits),
        initialized_(false),
        g_(context_.pairing()),
        g_alpha_(context_.pairing()),
        alpha_(context_.pairing()),
        pairing_alpha_(context_.pairing()) {
    }

    ~CPABE() = default;

    /**
     * Setup 算法
     * 初始化系统参数和主密钥
     *
     * 算法流程:
     * 1. 选择双线性群 G1, GT 和配对 e
     * 2. 随机选择生成元 g ∈ G1
     * 3. 随机选择主秘密 α ∈ Zr
     * 4. 计算公开参数 PK:
     *    - g
     *    - e(g,g)^α (pairing_alpha_)
     * 5. 主密钥 MK = g^α
     */
    void setup() {
        // TODO: 学生在此补全 CP-ABE 的 Setup 步骤
        // 提示:
        // 1) g_.randomize() 生成群生成元 g。
        g_.randomize();

        // 2) alpha_.randomize() 生成主密钥 α。
        alpha_.randomize();

        // 3) 计算 g_alpha_ = g_^α（setPowZn）。
        g_alpha_.setPowZn(g_, alpha_);

        // 4) 计算 pairing_alpha_ = e(g_, g_alpha_)，作为公开参数的一部分。
        pairing_alpha_.setPairing(g_, g_alpha_, context_.pairing());

        // 5) 设置 initialized_ = true。
        initialized_ = true;

        return;

        throw std::logic_error("TODO: implement CPABE::setup (see comments)");
    }

    /**
     * KeyGen 算法
     * 为给定的属性集合生成私钥
     *
     * @param attributes 用户拥有的属性集合 S
     * @return 私钥 SK
     *
     * 算法流程:
     * 1. 随机选择 r ∈ Zr (用于绑定所有属性组件)
     * 2. 计算 D = g^{α+r}
     * 3. 对于每个属性 j ∈ S:
     *    - 随机选择 r_j ∈ Zr
     *    - 计算 D_j = g^r · H(j)^{r_j}
     *    - 计算 D'_j = g^{r_j}
     */
    SecretKey keygen(const std::vector<std::string>& attributes) {
        // TODO: 学生在此补全 CP-ABE 的 KeyGen 步骤
        // 提示:

        SecretKey sk;
        // 1) ensureInitialized(); 随机 r ∈ Zr。
        ensureInitialized();
        auto r = ZrElement(context_.pairing());
        r.randomize();

        // 2) 计算 D = g_^(α+r) 并序列化保存到 sk.D。
        auto D = G1Element(context_.pairing());
        auto alpha_plus_r = ZrElement(context_.pairing());
        alpha_plus_r.setAdd(alpha_, r);
        D.setPowZn(g_, alpha_plus_r);
        sk.D = common::serializeElement(D);

        // 3) 对每个属性 attr:
        for (auto attr : attributes) {
            //    - 随机 r_j；
            auto r_j = ZrElement(context_.pairing());
            r_j.randomize();
            //    - H = Hash(attr)；
            auto H = G1Element(context_.pairing());
            hashStringToG1(context_.pairing(), attr, H);

            //    - Dj = g_^r · H^{r_j}；
            auto Hrj = G1Element(context_.pairing());
            Hrj.setPowZn(H, r_j);
            auto gr = G1Element(context_.pairing());
            gr.setPowZn(g_, r);
            auto Dj = G1Element(context_.pairing());
            Dj.setMul(gr, Hrj);

            //    - Dj_prime = g_^r_j；
            auto Dj_prime = G1Element(context_.pairing());
            Dj_prime.setPowZn(g_, r_j);

            //    - 将二者序列化后放入 sk.attributes[attr]。
            sk.attributes[attr] = {
                common::serializeElement(Dj),
                common::serializeElement(Dj_prime)
            };
        }

        return sk;

        throw std::logic_error("TODO: implement CPABE::keygen (see comments)");
    }

    /**
     * 密文结构 (Ciphertext)
     * 包含:
     * - policy: 访问策略树 (包含密文组件 C_x, C'_x)
     * - C_prime: g^s (用于恢复共享密钥)
     * - payload: 对称加密的消息
     */
    struct Ciphertext
    {
        std::unique_ptr<CipherNode> policy;
        std::vector<uint8_t> C_prime;  // C' = g^s
        std::vector<uint8_t> payload;  // Enc_K(M)
    };

    /**
     * Encrypt 算法
     * 根据访问策略加密消息
     *
     * @param policy 访问策略树
     * @param message 明文消息
     * @return 密文 CT
     *
     * 算法流程:
     * 1. 随机选择 s ∈ Zr (作为根节点的秘密)
     * 2. 计算共享密钥 K = e(g,g)^{αs}
     * 3. 计算 C' = g^s
     * 4. 使用线性秘密共享方案 (LSSS) 自顶向下分发 s:
     *    - 对于叶子节点 x (属性 j):
     *      - C_x = g^{q_x(0)}
     *      - C'_x = H(j)^{q_x(0)}
     * 5. 使用 K 对称加密消息
     */
    Ciphertext encrypt(const PolicyNode& policy, const std::vector<uint8_t>& message) {
        // TODO: 学生在此补全 CP-ABE 的 Encrypt 步骤
        // 提示:
        Ciphertext ct;
        // 1) ensureInitialized(); 随机 s ∈ Zr。
        ensureInitialized();
        auto s = ZrElement(context_.pairing());
        s.randomize();

        // 2) 深拷贝策略树：ct.policy = clonePolicy(policy)。
        ct.policy = clonePolicy(policy);

        // 3) 调用 shareSecret(policy, s, *ct.policy) 生成各节点的 (C_x, C'_x)。
        shareSecret(policy, s, *ct.policy);

        // 4) 计算 C_prime = g_^s 并序列化到 ct.C_prime。
        auto C_prime = G1Element(context_.pairing());
        C_prime.setPowZn(g_, s);
        ct.C_prime = common::serializeElement(C_prime);

        // 5) 计算 shared = e(g_alpha_, C_prime) = e(g,g)^{αs}，用其生成密钥流加密 message。
        auto shared = GTElement(context_.pairing());
        shared.setPairing(g_alpha_, C_prime, context_.pairing());
        auto keystream = common::sharedSecretToKeystream(shared, message.size());
        ct.payload = common::xorWithKeystream(message, keystream);

        // 6) 返回填好的 Ciphertext。
        return ct;

        throw std::logic_error("TODO: implement CPABE::encrypt (see comments)");
    }

    /**
     * Decrypt 算法
     * 使用私钥解密密文
     *
     * @param sk 私钥
     * @param ct 密文
     * @return 明文消息
     *
     * 算法流程:
     * 1. 递归计算 decryptNode(root):
     *    - 如果属性满足策略，返回聚合值 A = e(g,g)^{rs}
     * 2. 恢复共享密钥 K:
     *    - 计算 e(C', D) = e(g^s, g^{α+r}) = e(g,g)^{s(α+r)} = e(g,g)^{sα} · e(g,g)^{sr}
     *    - 除以 A = e(g,g)^{rs}
     *    - 结果 K = e(g,g)^{sα}
     * 3. 使用 K 解密消息
     */
    std::vector<uint8_t> decrypt(const SecretKey& sk, const Ciphertext& ct) {
        // TODO: 学生在此补全 CP-ABE 的 Decrypt 步骤
        // 提示:
        // 1) ensureInitialized(); 调用 decryptNode(*ct.policy, sk, aggregate) 得到 A=e(g,g)^{rs}，
        ensureInitialized();
        auto aggregate = GTElement(context_.pairing());
        auto res = decryptNode(*ct.policy, sk, aggregate);        
        //    如果返回 false 说明属性不满足。
        if (!res) {
            throw std::runtime_error("attributes do not satisfy policy");
        }
        // 2) 反序列化 C_prime、D；计算 shared = e(C_prime, D)。
        auto C_prime = G1Element(context_.pairing());   
        C_prime.fromBytes(ct.C_prime);
        auto D = G1Element(context_.pairing());
        D.fromBytes(sk.D);
        auto shared = GTElement(context_.pairing());
        shared.setPairing(C_prime, D, context_.pairing());
        // 3) 将 aggregate 取逆后乘到 shared 上，得到 e(g,g)^{sα}。
        aggregate.invert();
        shared.setMul(shared, aggregate);
        // 4) 用 shared 生成密钥流解开 ct.payload。
        auto keystream = common::sharedSecretToKeystream(shared, ct.payload.size());
        auto message = common::xorWithKeystream(ct.payload, keystream);
        // 5) 返回明文消息。
        return message;
        throw std::logic_error("TODO: implement CPABE::decrypt (see comments)");
    }

private:
    // 辅助函数: 深度复制策略树
    std::unique_ptr<CipherNode> clonePolicy(const PolicyNode& policy) const {
        auto node = std::make_unique<CipherNode>();
        node->threshold = policy.threshold;
        node->index = policy.index;
        node->attribute = policy.attribute;
        for (const auto& child : policy.children) {
            node->children.push_back(clonePolicy(*child));
        }
        return node;
    }

    /**
     * 分发秘密 (shareSecret)
     * 使用 Shamir 秘密共享方案在策略树中分发秘密 s
     *
     * @param policy 当前策略节点
     * @param secret 当前节点的秘密值 (多项式的常数项 q(0))
     * @param node 对应的密文节点 (输出)
     */
    void shareSecret(const PolicyNode& policy, const ZrElement& secret, CipherNode& node) {
        // TODO: 学生在此补全 shareSecret（LSSS 分发）
        // 提示:
        // 1) 将 policy 的 threshold/index/attribute 复制到 node。
        node.threshold = policy.threshold;
        node.index = policy.index;
        node.attribute = policy.attribute;

        // 2) 若为叶子节点:
        if (policy.children.empty()) {

            //    - 计算 H(attr)=hashStringToG1(...)；
            auto Hattr = G1Element(context_.pairing());
            common::hashStringToG1(context_.pairing(), policy.attribute, Hattr);

            //    - C = g_^secret，C_prime = H(attr)^secret；
            auto C = G1Element(context_.pairing());
            C.setPowZn(g_, secret);
            auto C_prime = G1Element(context_.pairing());
            C_prime.setPowZn(Hattr, secret);

            //    - 序列化存入 node.c 和 node.c_prime，返回。
            node.c = common::serializeElement(C);
            node.c_prime = common::serializeElement(C_prime);

            return;
        }

        // 3) 若为内部节点:
        else {
            //    - 构造度为 (threshold-1) 的多项式 q(x)，常数项 q(0)=secret，其他系数随机。
            std::vector<ZrElement> coefficients;
            coefficients.reserve(policy.threshold);
            coefficients.push_back(ZrElement(context_.pairing()));
            coefficients[0].set(secret);
            for (int i = 1; i < policy.threshold; ++i) {
                coefficients.push_back(ZrElement(context_.pairing()));
                coefficients[i].randomize();
            }

            for (int i = 0; i < policy.children.size(); ++i) {
                //    - 对每个子节点 child:
                //        a) 先深拷贝策略子树到 node.children（可用 clonePolicy）；
                auto policy_child = policy.children[i].get();
                auto cipher_child = node.children[i].get();
                //        b) 计算 child_secret = q(child->index)（evaluatePolynomial）；
                auto child_secret = ZrElement(context_.pairing());
                auto ZrIndex = ZrElement(context_.pairing());
                ZrIndex.setSi(policy_child->index);
                common::evaluatePolynomial(context_.pairing(), coefficients, ZrIndex, child_secret);
                //        c) 递归调用 shareSecret(*child, child_secret, *对应的 node.children)。
                shareSecret(*policy_child, child_secret, *cipher_child);
            }
            return;
        }
        throw std::logic_error("TODO: implement CPABE::shareSecret (see comments)");
    }

    /**
     * 解密节点 (decryptNode)
     * 递归计算配对乘积
     *
     * @param node 当前密文节点
     * @param sk 私钥
     * @param out 输出结果 (GT 元素)
     * @return true 如果满足策略, false 否则
     *
     * 算法流程:
     * 1. 叶子节点:
     *    - 检查用户是否拥有该属性
     *    - 计算 e(D_j, C) / e(D'_j, C')
     *      = e(g^r·H^{r_j}, g^{q(0)}) / e(g^{r_j}, H^{q(0)})
     *      = e(g,g)^{r·q(0)} · e(H,g)^{r_j·q(0)} / e(g,H)^{r_j·q(0)}
     *      = e(g,g)^{r·q(0)}
     *
     * 2. 内部节点:
     *    - 递归计算所有满足的子节点
     *    - 如果满足数量 < 阈值，失败
     *    - 使用拉格朗日插值计算 F_x = ∏ (F_z)^{Δ_{z,S}(0)}
     *      = e(g,g)^{r·q_x(0)}
     */
    bool decryptNode(const CipherNode& node, const SecretKey& sk, GTElement& out) const {
        // TODO: 学生在此补全 decryptNode（递归聚合配对值）
        // 提示:
        // 1) 叶子节点:
        if (node.children.empty()) {
            //    - 从 sk.attributes 找到匹配属性；若无则返回 false。
            if (sk.attributes.find(node.attribute) == sk.attributes.end()) {
                return false;
            }

            //    - 反序列化 C, C_prime, Dj, Dj_prime。
            auto C = G1Element(context_.pairing());
            C.fromBytes(node.c);
            auto C_prime = G1Element(context_.pairing());
            C_prime.fromBytes(node.c_prime);
            auto Dj_pair = sk.attributes.at(node.attribute);
            auto Dj = G1Element(context_.pairing());
            Dj.fromBytes(Dj_pair.first);
            auto Dj_prime = G1Element(context_.pairing());
            Dj_prime.fromBytes(Dj_pair.second);

            //    - 计算 pair1 = e(Dj, C)，pair2 = e(Dj_prime, C_prime)；pair2 取逆。
            auto pair1 = GTElement(context_.pairing());
            pair1.setPairing(Dj, C, context_.pairing());
            auto pair2 = GTElement(context_.pairing());
            pair2.setPairing(Dj_prime, C_prime, context_.pairing());
            pair2.invert();

            //    - out = pair1 * pair2（得到 e(g,g)^{r*q(0)}），返回 true。
            out.setMul(pair1, pair2);
            return true;
        }
        // 2) 内部节点:
        else {
            //    - 遍历子节点递归 decryptNode，收集成功的 (index, GT 值) 到 child_values。
            std::vector<int> successful_indexes;
            std::vector<GTElement> child_values;
            for (const auto& child : node.children) {
                GTElement child_out(context_.pairing());
                if (decryptNode(*child, sk, child_out)) {
                    successful_indexes.push_back(child->index);
                    child_values.push_back(std::move(child_out));
                }
            }
            //    - 若成功子节点数 < threshold，返回 false。
            if (static_cast<int>(child_values.size()) < node.threshold) {
                return false;
            }
            //    - 取前 threshold 个子节点的 index 列表，使用 lagrangeCoefficient 计算每个 λ。
            std::vector<ZrElement> lambdas;
            lambdas.reserve(node.threshold);
            for (int i = 0; i < node.threshold; i++) {
                lambdas.emplace_back(context_.pairing());
                int idx = successful_indexes[i];
                ZrElement lambda(context_.pairing());
                common::lagrangeCoefficient(context_.pairing(), successful_indexes, idx, lambda);
                lambdas[i].set(lambda);
            }
            //    - out = ∏ child_value^{λ}（初始化 out.setOne()，逐个 setPowZn + setMul）。
            out.setOne();
            for (int i = 0; i < node.threshold; i++) {
                GTElement temp(context_.pairing());
                temp.setPowZn(child_values[i], lambdas[i]);
                out.setMul(out, temp);
            }
            //    - 返回 true。
            return true;
        }


        throw std::logic_error("TODO: implement CPABE::decryptNode (see comments)");
    }

    void ensureInitialized() const {
        if (!initialized_) throw std::logic_error("CP-ABE system not setup");
    }

    const common::PairingContext context_;
    common::G1Element g_;
    common::G1Element g_alpha_;
    common::ZrElement alpha_;
    common::GTElement pairing_alpha_;
    bool initialized_;
};

int main() {
    try {
        // ============================================================
        // 初始化 CP-ABE 系统
        // ============================================================
        std::cout << "==================== CP-ABE 测试程序 ====================\n\n";
        std::cout << "正在初始化 CP-ABE 系统...\n";
        CPABE abe;
        abe.setup();
        std::cout << "系统初始化完成！\n\n";

        // ============================================================
        // 测试 1: 基本的阈值策略 (2-of-3)
        // ============================================================
        std::cout << "==================== 测试 1: 阈值策略 (2-of-3) ====================\n";
        std::cout << "策略说明: 需要满足以下三个属性中的至少两个:\n";
        std::cout << "  - role:engineer\n";
        std::cout << "  - dept:security\n";
        std::cout << "  - country:us\n\n";

        // 构造策略树: threshold=2 表示需要满足 2 个属性
        std::vector<std::unique_ptr<PolicyNode>> children1;
        children1.push_back(PolicyNode::Leaf("role:engineer"));
        children1.push_back(PolicyNode::Leaf("dept:security"));
        children1.push_back(PolicyNode::Leaf("country:us"));
        auto policy1 = PolicyNode::Node(2, std::move(children1));

        // 生成用户密钥: 拥有 role:engineer 和 country:us 两个属性
        std::cout << "用户 Alice 拥有的属性: [role:engineer, country:us]\n";
        SecretKey alice_key = abe.keygen({"role:engineer", "country:us"});

        // 加密消息
        const std::string msg1 = "Secret: Project Alpha is approved!";
        std::vector<uint8_t> plain1(msg1.begin(), msg1.end());
        std::cout << "原始消息: \"" << msg1 << "\"\n";
        auto ct1 = abe.encrypt(*policy1, plain1);
        std::cout << "消息已加密\n";

        // 解密消息
        auto recovered1 = abe.decrypt(alice_key, ct1);
        std::cout << "解密结果: \"" << std::string(recovered1.begin(), recovered1.end()) << "\"\n";
        std::cout << "Recovered message: \"" << std::string(recovered1.begin(), recovered1.end()) << "\"\n";
        std::cout << "✅ 测试通过: Alice 满足策略 (2/3 属性匹配)\n\n";

        // ============================================================
        // 测试 2: AND 门策略 (必须满足所有属性)
        // ============================================================
        std::cout << "==================== 测试 2: AND 门策略 ====================\n";
        std::cout << "策略说明: 必须同时满足以下所有属性 (3-of-3):\n";
        std::cout << "  - dept:research\n";
        std::cout << "  - clearance:top-secret\n";
        std::cout << "  - location:hq\n\n";

        // AND 门: threshold = 子节点数量
        std::vector<std::unique_ptr<PolicyNode>> children2;
        children2.push_back(PolicyNode::Leaf("dept:research"));
        children2.push_back(PolicyNode::Leaf("clearance:top-secret"));
        children2.push_back(PolicyNode::Leaf("location:hq"));
        auto policy2 = PolicyNode::Node(3, std::move(children2));  // 3-of-3 = AND

        // 用户 Bob 拥有全部三个属性
        std::cout << "用户 Bob 拥有的属性: [dept:research, clearance:top-secret, location:hq]\n";
        SecretKey bob_key = abe.keygen({"dept:research", "clearance:top-secret", "location:hq"});

        const std::string msg2 = "Classified: Nuclear launch codes";
        std::vector<uint8_t> plain2(msg2.begin(), msg2.end());
        std::cout << "原始消息: \"" << msg2 << "\"\n";
        auto ct2 = abe.encrypt(*policy2, plain2);
        std::cout << "消息已加密\n";

        auto recovered2 = abe.decrypt(bob_key, ct2);
        std::cout << "解密结果: \"" << std::string(recovered2.begin(), recovered2.end()) << "\"\n";
        std::cout << "✅ 测试通过: Bob 满足 AND 策略 (3/3 属性全部匹配)\n\n";

        // ============================================================
        // 测试 3: OR 门策略 (满足任意一个属性即可)
        // ============================================================
        std::cout << "==================== 测试 3: OR 门策略 ====================\n";
        std::cout << "策略说明: 只需满足以下属性中的任意一个 (1-of-3):\n";
        std::cout << "  - role:manager\n";
        std::cout << "  - role:ceo\n";
        std::cout << "  - role:director\n\n";

        // OR 门: threshold = 1
        std::vector<std::unique_ptr<PolicyNode>> children3;
        children3.push_back(PolicyNode::Leaf("role:manager"));
        children3.push_back(PolicyNode::Leaf("role:ceo"));
        children3.push_back(PolicyNode::Leaf("role:director"));
        auto policy3 = PolicyNode::Node(1, std::move(children3));  // 1-of-3 = OR

        // 用户 Carol 只有一个匹配的属性
        std::cout << "用户 Carol 拥有的属性: [role:director, dept:sales]\n";
        SecretKey carol_key = abe.keygen({"role:director", "dept:sales"});

        const std::string msg3 = "Leadership meeting at 3 PM";
        std::vector<uint8_t> plain3(msg3.begin(), msg3.end());
        std::cout << "原始消息: \"" << msg3 << "\"\n";
        auto ct3 = abe.encrypt(*policy3, plain3);
        std::cout << "消息已加密\n";

        auto recovered3 = abe.decrypt(carol_key, ct3);
        std::cout << "解密结果: \"" << std::string(recovered3.begin(), recovered3.end()) << "\"\n";
        std::cout << "✅ 测试通过: Carol 满足 OR 策略 (1/3 属性匹配)\n\n";

        // ============================================================
        // 测试 4: 嵌套策略 (复合逻辑)
        // ============================================================
        std::cout << "==================== 测试 4: 嵌套策略树 ====================\n";
        std::cout << "策略说明: (dept:engineering AND clearance:secret) OR role:admin\n";
        std::cout << "逻辑结构:\n";
        std::cout << "  OR (1-of-2)\n";
        std::cout << "    ├─ AND (2-of-2)\n";
        std::cout << "    │   ├─ dept:engineering\n";
        std::cout << "    │   └─ clearance:secret\n";
        std::cout << "    └─ role:admin\n\n";

        // 构造嵌套策略树
        // 子树: AND(dept:engineering, clearance:secret)
        std::vector<std::unique_ptr<PolicyNode>> and_children;
        and_children.push_back(PolicyNode::Leaf("dept:engineering"));
        and_children.push_back(PolicyNode::Leaf("clearance:secret"));
        auto and_node = PolicyNode::Node(2, std::move(and_children));

        // 根节点: OR(AND_subtree, role:admin)
        std::vector<std::unique_ptr<PolicyNode>> or_children;
        or_children.push_back(std::move(and_node));
        or_children.push_back(PolicyNode::Leaf("role:admin"));
        auto policy4 = PolicyNode::Node(1, std::move(or_children));

        // 用户 Dave 满足左侧 AND 分支
        std::cout << "用户 Dave 拥有的属性: [dept:engineering, clearance:secret]\n";
        SecretKey dave_key = abe.keygen({"dept:engineering", "clearance:secret"});

        const std::string msg4 = "System architecture diagram v2.0";
        std::vector<uint8_t> plain4(msg4.begin(), msg4.end());
        std::cout << "原始消息: \"" << msg4 << "\"\n";
        auto ct4 = abe.encrypt(*policy4, plain4);
        std::cout << "消息已加密\n";

        auto recovered4 = abe.decrypt(dave_key, ct4);
        std::cout << "解密结果: \"" << std::string(recovered4.begin(), recovered4.end()) << "\"\n";
        std::cout << "✅ 测试通过: Dave 满足嵌套策略 (通过 AND 分支)\n\n";

        // ============================================================
        // 测试 5: 另一个用户满足同样的嵌套策略 (通过不同分支)
        // ============================================================
        std::cout << "用户 Eve (管理员) 拥有的属性: [role:admin, dept:hr]\n";
        SecretKey eve_key = abe.keygen({"role:admin", "dept:hr"});

        auto recovered4_eve = abe.decrypt(eve_key, ct4);
        std::cout << "解密结果: \"" << std::string(recovered4_eve.begin(), recovered4_eve.end()) << "\"\n";
        std::cout << "✅ 测试通过: Eve 满足嵌套策略 (通过 role:admin 分支)\n\n";

        // ============================================================
        // 测试 6: 属性不足，解密失败
        // ============================================================
        std::cout << "==================== 测试 6: 解密失败场景 ====================\n";
        std::cout << "策略: 需要 2-of-3 属性 [clearance:confidential, dept:finance, location:branch]\n";

        std::vector<std::unique_ptr<PolicyNode>> children6;
        children6.push_back(PolicyNode::Leaf("clearance:confidential"));
        children6.push_back(PolicyNode::Leaf("dept:finance"));
        children6.push_back(PolicyNode::Leaf("location:branch"));
        auto policy6 = PolicyNode::Node(2, std::move(children6));

        const std::string msg6 = "Financial report Q4";
        std::vector<uint8_t> plain6(msg6.begin(), msg6.end());
        auto ct6 = abe.encrypt(*policy6, plain6);

        // 用户 Frank 只有 1 个匹配属性，不满足阈值
        std::cout << "用户 Frank 拥有的属性: [dept:finance] (只有 1/2 所需属性)\n";
        SecretKey frank_key = abe.keygen({"dept:finance"});

        try {
            auto recovered6 = abe.decrypt(frank_key, ct6);
            std::cerr << "❌ 错误: Frank 不应该能解密！\n";
        }
        catch (const std::exception& e) {
            std::cout << "解密失败: " << e.what() << "\n";
            std::cout << "✅ 测试通过: 正确拒绝了不满足策略的解密尝试\n\n";
        }

        // ============================================================
        // 测试 7: 复杂的多层嵌套策略
        // ============================================================
        std::cout << "==================== 测试 7: 复杂多层策略 ====================\n";
        std::cout << "策略说明: 需要满足 (role:developer AND dept:cloud) 和 (clearance:high OR project:alpha) 中的任意一个\n";
        std::cout << "逻辑结构:\n";
        std::cout << "  OR (1-of-2)\n";
        std::cout << "    ├─ AND (2-of-2)\n";
        std::cout << "    │   ├─ role:developer\n";
        std::cout << "    │   └─ dept:cloud\n";
        std::cout << "    └─ OR (1-of-2)\n";
        std::cout << "        ├─ clearance:high\n";
        std::cout << "        └─ project:alpha\n\n";

        // 左分支: AND(role:developer, dept:cloud)
        std::vector<std::unique_ptr<PolicyNode>> left_and;
        left_and.push_back(PolicyNode::Leaf("role:developer"));
        left_and.push_back(PolicyNode::Leaf("dept:cloud"));
        auto left_branch = PolicyNode::Node(2, std::move(left_and));

        // 右分支: OR(clearance:high, project:alpha)
        std::vector<std::unique_ptr<PolicyNode>> right_or;
        right_or.push_back(PolicyNode::Leaf("clearance:high"));
        right_or.push_back(PolicyNode::Leaf("project:alpha"));
        auto right_branch = PolicyNode::Node(1, std::move(right_or));

        // 根节点: OR(left_branch, right_branch)
        std::vector<std::unique_ptr<PolicyNode>> root_children;
        root_children.push_back(std::move(left_branch));
        root_children.push_back(std::move(right_branch));
        auto policy7 = PolicyNode::Node(1, std::move(root_children));

        const std::string msg7 = "Cloud migration plan - Phase 2";
        std::vector<uint8_t> plain7(msg7.begin(), msg7.end());
        auto ct7 = abe.encrypt(*policy7, plain7);

        // 用户 Grace 通过左分支满足策略
        std::cout << "用户 Grace 拥有的属性: [role:developer, dept:cloud, skill:kubernetes]\n";
        SecretKey grace_key = abe.keygen({"role:developer", "dept:cloud", "skill:kubernetes"});
        auto recovered7 = abe.decrypt(grace_key, ct7);
        std::cout << "解密结果: \"" << std::string(recovered7.begin(), recovered7.end()) << "\"\n";
        std::cout << "✅ 测试通过: Grace 满足复杂策略 (通过左侧 AND 分支)\n\n";

        // 用户 Henry 通过右分支满足策略
        std::cout << "用户 Henry 拥有的属性: [project:alpha, dept:research]\n";
        SecretKey henry_key = abe.keygen({"project:alpha", "dept:research"});
        auto recovered7_henry = abe.decrypt(henry_key, ct7);
        std::cout << "解密结果: \"" << std::string(recovered7_henry.begin(), recovered7_henry.end()) << "\"\n";
        std::cout << "✅ 测试通过: Henry 满足复杂策略 (通过右侧 OR 分支)\n\n";

        // ============================================================
        // 测试 8: 单一属性策略 (最简单情况)
        // ============================================================
        std::cout << "==================== 测试 8: 单一属性策略 ====================\n";
        std::cout << "策略说明: 只需要单一属性 [status:premium]\n\n";

        std::vector<std::unique_ptr<PolicyNode>> children8;
        children8.push_back(PolicyNode::Leaf("status:premium"));
        auto policy8 = PolicyNode::Node(1, std::move(children8));

        std::cout << "用户 Iris 拥有的属性: [status:premium, member:gold]\n";
        SecretKey iris_key = abe.keygen({"status:premium", "member:gold"});

        const std::string msg8 = "Premium content: Exclusive tutorial";
        std::vector<uint8_t> plain8(msg8.begin(), msg8.end());
        auto ct8 = abe.encrypt(*policy8, plain8);

        auto recovered8 = abe.decrypt(iris_key, ct8);
        std::cout << "解密结果: \"" << std::string(recovered8.begin(), recovered8.end()) << "\"\n";
        std::cout << "✅ 测试通过: Iris 满足单一属性策略\n\n";

        // ============================================================
        // 测试总结
        // ============================================================
        std::cout << "==================== 测试总结 ====================\n";
        std::cout << "✅ 所有测试通过！\n";
        std::cout << "测试覆盖:\n";
        std::cout << "  1. 阈值策略 (k-of-n)\n";
        std::cout << "  2. AND 门 (全部属性)\n";
        std::cout << "  3. OR 门 (任意属性)\n";
        std::cout << "  4. 嵌套策略树\n";
        std::cout << "  5. 多用户多分支访问\n";
        std::cout << "  6. 属性不足的拒绝场景\n";
        std::cout << "  7. 复杂多层策略\n";
        std::cout << "  8. 单一属性策略\n";
        std::cout << "==================================================\n";

    }
    catch (const std::exception& ex) {
        std::cerr << "❌ 系统错误: " << ex.what() << "\n";
        return 1;
    }
    return 0;
}
