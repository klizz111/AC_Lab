#include <gmp.h>
#include <openssl/rand.h>
#include <pbc/pbc.h>

#include <cmath>
#include <iostream>
#include <random>
#include <string>
#include <unordered_map>
#include <vector>
#include <stdexcept>

namespace {

// 为满足现实安全性：同时选取 1024 位的 p 与 q，使得 N = p*q 的因式分解难度与 2048-bit RSA 相当。
constexpr unsigned int kPrivatePrimeBits = 1024;     // 解密私钥素数 p 的比特长度。
constexpr unsigned int kRandomPrimeBits = 1024;      // 随机素数 q 的比特长度。

// 限制可支持的明文最大值，以保证解密离散对数的复杂度可控。
constexpr unsigned long kMaxPlaintextValue = 1024;
constexpr unsigned long kDiscreteLogUpperBound = kMaxPlaintextValue * kMaxPlaintextValue;

// 将 PBC 的 element_t 打印为字符串，方便调试输出。
// PBC 内部的 element 可能是二进制表示，这里通过 element_snprint
// 统一转成十六进制文本，便于在日志中观察具体数值。
std::string ElementToString(element_t element) {
    const int estimate = element_length_in_bytes(element);
    std::vector<char> buffer(static_cast<size_t>(estimate) * 2 + 1, 0);
    const int written = element_snprint(buffer.data(), buffer.size(), element);
    if (written < 0) {
        return {};
    }
    std::string result(buffer.data(), static_cast<size_t>(written));
    const auto zero_pos = result.find('\0');
    if (zero_pos != std::string::npos) {
        result.resize(zero_pos);
    }
    return result;
}

}  // namespace

/**
 * @brief BGN 同态加密的核心实现
 *
 * 该类负责：
 * 1. 用 Type A1 配对生成满足阶 N=pq 的对称双线性群；
 * 2. 生成满足 BGN 需求的基元 g、h 以及子群生成元；
 * 3. 提供加密、解密、同态加法及一次乘法的接口。
 */
class BGN {
private:
    pairing_t pairing_;  // PBC 的配对结构，封装了所有群及双线性映射。

    // 同一个对称群里取两份生成元，便于调用 PBC 的 G1/G2 接口。
    // 在 Type A1 配对中，G1 与 G2 实际相同，这里共享同一个底层元素的拷贝。
    element_t g1_;
    element_t g2_;
    // h1 = g1^q、h2 = g2^q：这些元素的阶为 p。
    element_t h1_;
    element_t h2_;
    // g1^p、g2^p：阶为 q 的元素，解密时取 p 次幂后只剩消息部分。
    element_t g1_p_;
    element_t g2_p_;
    // (e(g1,g2))^p：GT 群中阶为 q 的生成元，用于乘法结果的解密。
    element_t gt_generator_p_;

    // p、q 和 n = p*q 的多精度表示（运行时动态生成）。
    mpz_t p_;
    mpz_t q_;
    mpz_t n_;

    /**
     * @brief 生成指定比特长度的随机素数
     *
     * 利用 OpenSSL 的 RAND_bytes 生成高熵随机数，强制最高位为 1，
     * 然后调用 mpz_nextprime 得到指定比特长度的素数。
     */
    static void GenerateRandomPrime(mpz_t target,
                                    unsigned int bits) {
        if (bits < 2) {
            throw std::runtime_error("Prime bit length must be >= 2.");
        }
        const size_t byte_len = static_cast<size_t>((bits + 7) / 8);
        std::vector<unsigned char> buffer(byte_len);

        while (true) {
            if (RAND_bytes(buffer.data(), static_cast<int>(buffer.size())) != 1) {
                throw std::runtime_error("RAND_bytes failed to produce random data.");
            }

            // 规范化：设置最高位为 1，确保位数满足要求。
            const unsigned int msb_index = bits - 1;
            const size_t msb_byte = msb_index / 8;
            const unsigned int msb_bit = msb_index % 8;
            if (msb_bit < 7) {
                const unsigned char mask = static_cast<unsigned char>((1u << (msb_bit + 1)) - 1u);
                buffer[msb_byte] &= mask;
            }
            buffer[msb_byte] |= static_cast<unsigned char>(1u << msb_bit);

            // 设置最低位为 1，避免生成偶数（节省 nextprime 的工作量）。
            buffer[0] |= 0x01u;

            mpz_import(target,
                       buffer.size(),
                       -1,   // 以最低有效字节在前的顺序导入。
                       1,
                       -1,
                       0,
                       buffer.data());

            mpz_nextprime(target, target);

            if (mpz_sizeinbase(target, 2) == static_cast<int>(bits)) {
                break;
            }
        }
    }

    // 调用 Type A1 参数生成器，得到阶为 n=pq 的双线性群。
    void GenerateCompositeParameter() {
        mpz_mul(n_, p_, q_);

        pbc_param_t param;
        pbc_param_init_a1_gen(param, n_);
        pairing_init_pbc_param(pairing_, param);
        pbc_param_clear(param);
    }

    /**
     * @brief 在对称群中挑选一个满足阶为 n 的生成元
     *
     * 候选元素需要同时满足 g^p != 1 且 g^q != 1 才能确保阶为 pq。
     */
    static void SampleGenerator(element_t& result,
                                pairing_ptr pairing,
                                mpz_t p,
                                mpz_t q,
                                void (*init_fn)(element_t, pairing_t)) {
        element_t candidate, test;
        init_fn(candidate, pairing);
        init_fn(test, pairing);

        while (true) {
            element_random(candidate);

            // Ensure candidate^p != 1.
            element_pow_mpz(test, candidate, p);
            if (element_is1(test)) {
                // g^p = 1 说明该元素落在阶为 p 的子群，无法生成整个群，需重新抽样。
                continue;
            }

            // Ensure candidate^q != 1.
            element_pow_mpz(test, candidate, q);
            if (element_is1(test)) {
                // g^q = 1 则元素落在阶为 q 的子群，同样不符合要求。
                continue;
            }

            element_set(result, candidate);
            break;
        }

        element_clear(candidate);
        element_clear(test);
    }

    // 初始化所有需要的生成元及其幂。
    void InitialiseGenerators() {
        element_init_G1(g1_, mutable_pairing());
        element_init_G1(h1_, mutable_pairing());
        element_init_G1(g1_p_, mutable_pairing());

        element_init_G2(g2_, mutable_pairing());
        element_init_G2(h2_, mutable_pairing());
        element_init_G2(g2_p_, mutable_pairing());

        element_init_GT(gt_generator_p_, mutable_pairing());

        // g1/g2 是阶为 pq 的生成元，后续由它们派生出阶为 p、q 的子群基。
        SampleGenerator(g1_, mutable_pairing(), p_, q_, element_init_G1);
        element_set(g2_, Mutable(g1_));

        element_pow_mpz(h1_, g1_, q_);
        element_pow_mpz(h2_, g2_, q_);

        element_pow_mpz(g1_p_, g1_, p_);
        element_pow_mpz(g2_p_, g2_, p_);

        element_t gt_generator;
        element_init_GT(gt_generator, mutable_pairing());
        pairing_apply(gt_generator, g1_, g2_, mutable_pairing());
        element_pow_mpz(gt_generator_p_, gt_generator, p_);
        element_clear(gt_generator);
    }

    // 将 pairing_t 转换成可写指针，便于传入 PBC 接口。
    pairing_ptr mutable_pairing() const {
        return const_cast<pairing_ptr>(&pairing_[0]);
    }

    // 将任意整数规范到明文空间 Z_q。
    unsigned long NormalizePlaintext(long long value) const {
        const long long modulus = static_cast<long long>(kMaxPlaintextValue) + 1;
        long long adjusted = value % modulus;
        if (adjusted < 0) {
            adjusted += modulus;
        }
        return static_cast<unsigned long>(adjusted);
    }

    /**
     * @brief 求解离散对数 m，使得 target = generator^m
     *
     * 使用 Baby-step Giant-step 算法，在上界 upper_bound 内查找。
     * BGN 中 upper_bound = p-1，因此算法复杂度约为 O(sqrt(p))。
     */
    static long long BabyStepGiantStep(element_t target,
                                       element_t generator,
                                       unsigned long upper_bound) {
        if (upper_bound == 0) {
            return 0;
        }

        const unsigned long m =
            static_cast<unsigned long>(std::sqrt(static_cast<long double>(upper_bound))) + 1;

        std::unordered_map<std::string, unsigned long> table;
        table.reserve(m * 2);
        // baby-step：预先计算 generator 的前 m 个幂并存入哈希表，
        // 通过字符串序列化作为键，避免处理底层二进制格式。

        element_t baby_step;
        element_init_same_as(baby_step, generator);
        element_set1(baby_step);

        for (unsigned long j = 0; j <= m; ++j) {
            table.emplace(ElementToString(baby_step), j);
            element_mul(baby_step, baby_step, generator);
        }

        element_t factor;
        element_init_same_as(factor, generator);

        mpz_t exponent;
        mpz_init_set_ui(exponent, m);
        element_pow_mpz(factor, generator, exponent);
        element_invert(factor, factor);  // factor = generator^{-m}
        mpz_clear(exponent);

        element_t giant_step;
        element_init_same_as(giant_step, target);
        element_set(giant_step, target);

        for (unsigned long i = 0; i <= m; ++i) {
            const auto it = table.find(ElementToString(giant_step));
            if (it != table.end()) {
                const unsigned long candidate = i * m + it->second;
                if (candidate <= upper_bound) {
                    element_clear(baby_step);
                    element_clear(factor);
                    element_clear(giant_step);
                    return static_cast<long long>(candidate);
                }
            }
            element_mul(giant_step, giant_step, factor);
        }

        element_clear(baby_step);
        element_clear(factor);
        element_clear(giant_step);
        return -1;
    }

public:
    // Mutable 将 const element_t 包装成可写指针，方便传入只接收 element_ptr 的 PBC API
    static element_ptr Mutable(const element_t& e) {
        return const_cast<element_ptr>(&e[0]);
    }

    /**
     * @brief G1 群密文结构
     *
     * 维护 element_t 并处理拷贝/移动语义，避免重复初始化或释放。
     */
    struct CipherG1 {
        // pairing_ref 指向外部提供的 pairing_t，结构体不负责其销毁
        pairing_ptr pairing_ref;
        // value 保存 G1 群中的元素，只有在 initialized 为 true 时才有效
        element_t value;
        // initialized 表示是否已经完成 element_init_G1，避免重复 init/clear
        bool initialized;

        // 默认构造只记录状态，方便容器中延迟初始化
        CipherG1() : pairing_ref(nullptr), initialized(false) {}

        // 显式构造时立即初始化为单位元，便于后续乘法累积
        explicit CipherG1(pairing_ptr pairing) : pairing_ref(pairing), initialized(true) {
            element_init_G1(value, pairing_ref);
            element_set1(value);
        }

        // 拷贝构造深拷贝底层 element，确保两个密文互不干扰
        CipherG1(const CipherG1& other) : pairing_ref(other.pairing_ref), initialized(other.initialized) {
            if (initialized) {
                element_init_G1(value, pairing_ref);
                element_set(value, Mutable(other.value));
            }
        }

        // 拷贝赋值需处理目标未初始化的情况，同时避免自赋值
        CipherG1& operator=(const CipherG1& other) {
            if (this == &other) {
                return *this;
            }
            if (!other.initialized) {
                release();
                pairing_ref = nullptr;
                return *this;
            }
            if (!initialized) {
                pairing_ref = other.pairing_ref;
                element_init_G1(value, pairing_ref);
                initialized = true;
            }
            element_set(value, Mutable(other.value));
            return *this;
        }

        // 移动构造通过复制后释放对端，保持接口简单安全
        CipherG1(CipherG1&& other) noexcept : pairing_ref(other.pairing_ref), initialized(other.initialized) {
            if (initialized) {
                element_init_G1(value, pairing_ref);
                element_set(value, Mutable(other.value));
                other.release();
            }
        }

        // 移动赋值需要先清理自身，再接管资源
        CipherG1& operator=(CipherG1&& other) noexcept {
            if (this != &other) {
                release();
                pairing_ref = other.pairing_ref;
                initialized = other.initialized;
                if (initialized) {
                    element_init_G1(value, pairing_ref);
                    element_set(value, Mutable(other.value));
                    other.release();
                }
            }
            return *this;
        }

        // release 统一做资源释放，避免析构和赋值逻辑重复
        void release() {
            if (initialized) {
                element_clear(value);
                pairing_ref = nullptr;
                initialized = false;
            }
        }

        ~CipherG1() { release(); }
    };

    /**
     * @brief G2 群密文结构
     *
     * 与 CipherG1 相同，只是底层初始化在 G2。
     */
    struct CipherG2 {
        // pairing_ref 同样指向外部 pairing_t，生命周期由 BGN 管理
        pairing_ptr pairing_ref;
        // value 是落在 G2 的 element_t，按需 lazy-init
        element_t value;
        // 标记是否已完成 element_init_G2，控制是否需要清理
        bool initialized;

        // 默认构造保持未初始化，方便在容器中占位
        CipherG2() : pairing_ref(nullptr), initialized(false) {}

        // 构造时立即初始化为单位元，便于后续累乘
        explicit CipherG2(pairing_ptr pairing) : pairing_ref(pairing), initialized(true) {
            element_init_G2(value, pairing_ref);
            element_set1(value);
        }

        // 拷贝构造与 G1 版本一致，深拷贝底层 element
        CipherG2(const CipherG2& other) : pairing_ref(other.pairing_ref), initialized(other.initialized) {
            if (initialized) {
                element_init_G2(value, pairing_ref);
                element_set(value, Mutable(other.value));
            }
        }

        // 拷贝赋值处理未初始化的目标与空源的情况
        CipherG2& operator=(const CipherG2& other) {
            if (this == &other) {
                return *this;
            }
            if (!other.initialized) {
                release();
                pairing_ref = nullptr;
                return *this;
            }
            if (!initialized) {
                pairing_ref = other.pairing_ref;
                element_init_G2(value, pairing_ref);
                initialized = true;
            }
            element_set(value, Mutable(other.value));
            return *this;
        }

        // 移动构造复制后立即释放源，减少共享状态
        CipherG2(CipherG2&& other) noexcept : pairing_ref(other.pairing_ref), initialized(other.initialized) {
            if (initialized) {
                element_init_G2(value, pairing_ref);
                element_set(value, Mutable(other.value));
                other.release();
            }
        }

        // 移动赋值先释放自身，再接管资源
        CipherG2& operator=(CipherG2&& other) noexcept {
            if (this != &other) {
                release();
                pairing_ref = other.pairing_ref;
                initialized = other.initialized;
                if (initialized) {
                    element_init_G2(value, pairing_ref);
                    element_set(value, Mutable(other.value));
                    other.release();
                }
            }
            return *this;
        }

        // 统一释放逻辑，避免重复代码
        void release() {
            if (initialized) {
                element_clear(value);
                pairing_ref = nullptr;
                initialized = false;
            }
        }

        ~CipherG2() { release(); }
    };

    /**
     * @brief 构造函数：初始化配对参数与生成元
     *
     * 步骤：
     * 1. 随机生成素数 p、q；
     * 2. 用 Type A1 生成阶为 pq 的配对；
     * 3. 初始化 g、h、g^q 等所有元素；
     * 4. 记录明文空间大小。
     */
    BGN() {
        mpz_init(p_);
        mpz_init(q_);
        mpz_init(n_);

        GenerateRandomPrime(p_, kPrivatePrimeBits);

        do {
            GenerateRandomPrime(q_, kRandomPrimeBits);
        } while (mpz_cmp(p_, q_) == 0);  // 极小概率相等，重新生成，避免出现 N = p^2。

        GenerateCompositeParameter();
        InitialiseGenerators();
    }

    // 析构时释放所有 PBC/GMP 的资源。
    ~BGN() {
        element_clear(g1_);
        element_clear(g2_);
        element_clear(h1_);
        element_clear(h2_);
        element_clear(g1_p_);
        element_clear(g2_p_);
        element_clear(gt_generator_p_);
        pairing_clear(pairing_);

        mpz_clear(p_);
        mpz_clear(q_);
        mpz_clear(n_);
    }

    // 返回公钥相关元素，仅供展示。
    std::string get_public_key_str() {
        return "g1:" + ElementToString(g1_) +
               ", h1:" + ElementToString(h1_) +
               ", g2:" + ElementToString(g2_) +
               ", h2:" + ElementToString(h2_);
    }

    // 私钥即为 p，用字符串形式输出。
    std::string get_private_key_str() const {
        char* p_str = mpz_get_str(nullptr, 10, p_);
        std::string result(p_str ? p_str : "");
        if (p_str) {
            free(p_str);
        }
        return result;
    }

    // 返回动态生成的 p、q 的实际比特长度，便于在演示中确认安全参数。
    int private_prime_bits() const { return mpz_sizeinbase(p_, 2); }
    int random_prime_bits() const { return mpz_sizeinbase(q_, 2); }

    /**
     * @brief 加密到 G1
     *
     * c = g1^m * h1^r，其中 h1 的阶为 p。
     */
    CipherG1 encrypt_g1(long long m) {
        // TODO(student):
        // 1. 调用 NormalizePlaintext 将 m 规约到明文空间；
        // 2. 在 Z_r 中随机采样r，并计算 h1^r；
        // 3. 将明文映射为 mpz_t，求出 g1^m；
        // 4. 将 g1^m 与 h1^r 相乘写入 CipherG1::value；
        // 5. 正确释放所有临时 element/mpz 资源并返回密文。

        // 1. 规约m
        auto norm_m = NormalizePlaintext(m);

        // 2. Gen r in Zn
        element_t r;
        // 规约到Zn
        element_init_Zr(r, mutable_pairing());
        element_random(r); // 随机采样r

        // 3. caculate h1^r
        element_t h1_r;
        element_init_G1(h1_r, mutable_pairing());
        mpz_t r_mpz;
        mpz_init(r_mpz);
        element_to_mpz(r_mpz, r);
        element_pow_mpz(h1_r, h1_, r_mpz);

        // 3. norm_m 转 mpz
        mpz_t m_mpz;
        mpz_init_set_ui(m_mpz, norm_m);

        // 4. 求 g1^m
        element_t g1_m;
        element_init_G1(g1_m, mutable_pairing());
        element_pow_mpz(g1_m, g1_, m_mpz);

        // 5. caculate g1^m * h1^r
        element_t ciphertext;
        element_init_G1(ciphertext, mutable_pairing());
        element_mul(ciphertext, g1_m, h1_r);

        // free
        element_clear(r);
        element_clear(h1_r);
        mpz_clear(r_mpz);
        mpz_clear(m_mpz);
        element_clear(g1_m);    

        // return
        CipherG1 ct(mutable_pairing());
        element_set(ct.value, ciphertext);
        element_clear(ciphertext);

        return ct;

        throw std::logic_error("encrypt_g1 is unimplemented; complete it according to the TODO hints.");
    }

    /**
     * @brief 加密到 G2
     *
     * 与 encrypt_g1 相同，只是位于 G2，用于后续乘法演示。
     */
    CipherG2 encrypt_g2(long long m) {
        // TODO(student):
        // 1. 复用 G1 加密的思路：NormalizePlaintext 后采样随机 r；
        // 2. 在 G2 群中分别计算 h2^r 与 g2^m；
        // 3. 将两部分相乘写入 CipherG2::value；
        // 4. 注意释放临时 element/mpz，保持与 encrypt_g1 对称。

        auto norm_m = NormalizePlaintext(m);

        element_t r;
        element_init_Zr(r, mutable_pairing());
        element_random(r);

        element_t h2_r;
        element_init_G2(h2_r, mutable_pairing());
        mpz_t r_mpz;
        mpz_init(r_mpz);
        element_to_mpz(r_mpz, r);
        element_pow_mpz(h2_r, h2_, r_mpz);
        mpz_t m_mpz;
        mpz_init_set_ui(m_mpz, norm_m);

        element_t g2_m;
        element_init_G2(g2_m, mutable_pairing());
        element_pow_mpz(g2_m, g2_, m_mpz);

        element_t ciphertext;
        element_init_G2(ciphertext, mutable_pairing());
        element_mul(ciphertext, g2_m, h2_r);

        element_clear(r);
        element_clear(h2_r);
        mpz_clear(r_mpz);
        mpz_clear(m_mpz);
        element_clear(g2_m);

        CipherG2 ct(mutable_pairing());
        element_set(ct.value, ciphertext);
        element_clear(ciphertext);

        return ct;

        throw std::logic_error("encrypt_g2 is unimplemented; complete it according to the TODO hints.");
    }

    /**
     * @brief 解密 G1 密文
     *
     * 计算 c^p = (g1^m)^p = (g1^p)^m，之后在阶为 q 的子群里做离散对数。
     */
    long long decrypt_g1(const CipherG1& ct) {
        // TODO(student):
        // 1. 初始化临时 G1 元素，将密文 value 取 p 次幂消去随机化项；
        // 2. 调用 BabyStepGiantStep，在 g1_p_ 生成的阶 q 子群中恢复明文；
        // 3. 清理临时元素并返回离散对数的结果。

        // init temp_g1
        element_t temp_g1;

        // set Ciphertext.value 2 temp_g1
        element_init_G1(temp_g1, mutable_pairing());
        element_set(temp_g1, Mutable(ct.value));

        // calculate ct^p
        element_t g_p_m;
        element_init_G1(g_p_m, mutable_pairing());
        element_pow_mpz(g_p_m, temp_g1, p_);

        // call BabyStepGiantStep
        long long m = BabyStepGiantStep(g_p_m, g1_p_, kMaxPlaintextValue);
        
        // free
        element_clear(temp_g1);
        element_clear(g_p_m);

        return m;
        throw std::logic_error("decrypt_g1 is unimplemented; complete it according to the TODO hints.");
    }

    /**
     * @brief 解密 G2 密文
     *
     * 与 decrypt_g1 相同，只是使用 g2^p。
     */
    long long decrypt_g2(const CipherG2& ct) {
        // TODO(student):
        // 1. 初始化临时 G2 元素并计算密文 value 的 p 次幂；
        // 2. 使用 BabyStepGiantStep 结合 g2_p_ 找到明文值；
        // 3. 释放临时资源后返回恢复出的整数。

        // init temp_g1=2
        element_t temp_g2;

        // set Ciphertext.value 2 temp_g2
        element_init_G2(temp_g2, mutable_pairing());
        element_set(temp_g2, Mutable(ct.value));

        // calculate ct^p
        element_t g_p_m;
        element_init_G2(g_p_m, mutable_pairing());
        element_pow_mpz(g_p_m, temp_g2, p_);

        // call BabyStepGiantStep
        long long m = BabyStepGiantStep(g_p_m, g2_p_, kMaxPlaintextValue);
        
        // free
        element_clear(temp_g2);
        element_clear(g_p_m);

        return m;

        throw std::logic_error("decrypt_g2 is unimplemented; complete it according to the TODO hints.");
    }

    /**
     * @brief G1 同态加法
     *
     * 利用群运算直接相乘：c1*c2 = g^{m1+m2} * h^{r1+r2}。
     */
    CipherG1 add_g1(const CipherG1& ct1, const CipherG1& ct2) const {
        // TODO(student):
        // 1. 初始化返回值 CipherG1 result(mutable_pairing())；
        // 2. 使用 element_mul 将两个密文的 value 依次相乘；
        // 3. 返回累乘后的 result，体现明文加法的同态性。
        CipherG1 result(mutable_pairing());
        element_mul(result.value, Mutable(ct1.value), Mutable(ct2.value));
        return result;
        throw std::logic_error("add_g1 is unimplemented; complete it according to the TODO hints.");
    }

    /**
     * @brief G2 同态加法
     *
     * 与 G1 相同的逻辑。
     */
    CipherG2 add_g2(const CipherG2& ct1, const CipherG2& ct2) const {
        // TODO(student):
        // 1. 初始化 CipherG2 result(mutable_pairing())；
        // 2. 在 G2 群中调用 element_mul 聚合两个密文；
        // 3. 返回结果，验证与 add_g1 一致的同态加法性质。
        CipherG2 result(mutable_pairing());
        element_mul(result.value, Mutable(ct1.value), Mutable(ct2.value));
        return result;
        throw std::logic_error("add_g2 is unimplemented; complete it according to the TODO hints.");
    }

    /**
     * @brief G1/G2 一次乘法
     *
     * 利用双线性性质：e(g1^{m1}h1^{r1}, g2^{m2}h2^{r2})
     * = e(g1, g2)^{m1 m2} * e(g1, h2)^{m1 r2} * e(h1, g2)^{r1 m2} * e(h1,h2)^{r1 r2}
     * 其中含有 p 因子的部分在后续取 p 次幂时会被消去，只留下 e(g1,g2)^{m1 m2}。
     */
    void multiply_g1_g2(const CipherG1& ct1, const CipherG2& ct2, element_t result) const {
        // TODO(student):
        // 1. 在 GT 群中初始化临时元素，通过 pairing_apply 计算密文的双线性映射；
        // 2. 将配对结果复制到输出参数 result；
        // 3. 释放临时资源，确保无内存泄漏。
        element_t temp_gt;
        element_init_GT(temp_gt, mutable_pairing());
        // pairing_apply(temp_gt, Mutable(ct1.value), Mutable(ct2.value), mutable_pairing());
        element_pairing(temp_gt, Mutable(ct1.value), Mutable(ct2.value));
        element_set(result, temp_gt);
        element_clear(temp_gt);
        return;
        throw std::logic_error("multiply_g1_g2 is unimplemented; complete it according to the TODO hints.");
    }

    /**
     * @brief 解密乘法结果
     *
     * 对 GT 元素取 p 次幂，得到 (e(g1,g2)^p)^{m1 m2}，再做离散对数求乘积。
     */
    long long decrypt_product(element_t value) {
        // TODO(student):
        // 1. 在 GT 群里初始化临时元素并计算 value 的 p 次幂，通过 p 次幂消去随机化项；
        // 2. 使用 BabyStepGiantStep 与 gt_generator_p_ 求解乘积的离散对数；
        // 3. 回收临时变量并返回最终的乘法明文。
        element_t temp_gt;
        element_init_GT(temp_gt, mutable_pairing());
        element_pow_mpz(temp_gt, value, p_);
        long long m = BabyStepGiantStep(temp_gt, gt_generator_p_, kDiscreteLogUpperBound);
        element_clear(temp_gt);
        return m;
        throw std::logic_error("decrypt_product is unimplemented; complete it according to the TODO hints.");
    }

    // 暴露底层 pairing 指针，供演示脚本初始化临时 element_t
    pairing_ptr pairing() { return pairing_; }
};

int main() {
    // 演示脚本：生成系统、随机挑选明文并验证同态性质。
    std::cout << "=== BGN同态加密算法演示 (复合阶群) ===" << std::endl;

    BGN bgn;

    std::cout << "公钥: " << bgn.get_public_key_str().substr(0, 120) << "..." << std::endl;
    std::cout << "私钥 (p): " << bgn.get_private_key_str() << std::endl;
    std::cout << "p 比特长度: " << bgn.private_prime_bits()
              << ", q 比特长度: " << bgn.random_prime_bits() << std::endl;
    std::cout << "明文取值范围约束: [0, " << kMaxPlaintextValue << "]" << std::endl;

    std::random_device rd;
    std::mt19937 gen(rd());
    // 演示只挑选有限范围的明文，确保离散对数恢复可行。
    std::uniform_int_distribution<unsigned long> dist(0, kMaxPlaintextValue);

    const unsigned long m1 = dist(gen);  // 第一个明文
    const unsigned long m2 = dist(gen);  // 第二个明文

    std::cout << "\n=== G1群加法同态演示 ===" << std::endl;
    std::cout << "加密 m1 = " << m1 << " 到 G1" << std::endl;
    std::cout << "加密 m2 = " << m2 << " 到 G1" << std::endl;

    auto c1 = bgn.encrypt_g1(m1);
    auto c2 = bgn.encrypt_g1(m2);

    // 单独解密，用于确认基本的加/解密正确性。
    const long long dec_m1 = bgn.decrypt_g1(c1);
    const long long dec_m2 = bgn.decrypt_g1(c2);
    std::cout << "单独解密 m1 -> " << dec_m1 << std::endl;
    std::cout << "单独解密 m2 -> " << dec_m2 << std::endl;

    auto sum_g1 = bgn.add_g1(c1, c2);
    const long long decrypted_sum_g1 = bgn.decrypt_g1(sum_g1);
    const unsigned long expected_sum =
        (static_cast<unsigned long>(m1) + static_cast<unsigned long>(m2));
    // BGN 在模 q 上加法，这里范围较小，可直接相加得到期望结果

    std::cout << "解密和 = " << decrypted_sum_g1 << std::endl;
    std::cout << "明文加法 m1 + m2 = " << expected_sum << std::endl;
    const bool sum_correct = decrypted_sum_g1 >= 0 &&
        static_cast<unsigned long>(decrypted_sum_g1) == expected_sum;
    // decrypted_sum_g1 返回 -1 表示离散对数失败，这里也一并检查
    std::cout << "验证结果: " << (sum_correct ? "正确" : "错误")
              << std::endl;

    std::cout << "\n=== G2群加法同态演示 ===" << std::endl;
    auto c1_g2 = bgn.encrypt_g2(m1);
    auto c2_g2 = bgn.encrypt_g2(m2);

    const long long decrypted_sum_g2 = bgn.decrypt_g2(bgn.add_g2(c1_g2, c2_g2));
    std::cout << "解密和 = " << decrypted_sum_g2 << std::endl;
    const bool sum_g2_correct = decrypted_sum_g2 >= 0 &&
        static_cast<unsigned long>(decrypted_sum_g2) == expected_sum;
    // 比较 G2 的解密结果，验证同样保持加法同态
    std::cout << "验证结果: " << (sum_g2_correct ? "正确" : "错误")
              << std::endl;

    std::cout << "\n=== G1 与 G2 乘法同态演示 ===" << std::endl;
    element_t multiplication_result;
    element_init_GT(multiplication_result, bgn.pairing());
    bgn.multiply_g1_g2(c1, c2_g2, multiplication_result);

    const long long decrypted_product = bgn.decrypt_product(multiplication_result);
    const unsigned long expected_product =
        (static_cast<unsigned long long>(m1) * static_cast<unsigned long long>(m2));
    // 明文乘积不回绕（范围较小），可直接在整型中计算

    std::cout << "解密乘积 = " << decrypted_product << std::endl;
    std::cout << "明文乘积 m1 * m2 = " << expected_product << std::endl;
    const bool product_correct = decrypted_product >= 0 &&
        static_cast<unsigned long>(decrypted_product) == expected_product;
    // 验证一次乘法的同态性：只允许一次原因是离散对数基于 g^p 的阶为 q
    std::cout << "验证结果: " << (product_correct ? "正确" : "错误")
              << std::endl;

    element_clear(multiplication_result);

    std::cout << "\nBGN同态加密演示完成!" << std::endl;
    return 0;
}
