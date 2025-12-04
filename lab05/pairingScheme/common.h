/**
 * 公共工具头文件
 * 提供所有密码学方案共享的工具函数和类
 * 包括:双线性配对管理、哈希函数、序列化、密钥派生等
 */

#pragma once

#include <pbc/pbc.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <array>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace common {

// 安全参数常量(比特)
// 最小值用于内部验证，默认值供外部使用
constexpr int kMinimumRbits = 160;   // 基域最小大小（安全下限）
constexpr int kMinimumQbits = 512;   // 椭圆曲线阶数最小大小（安全下限）
constexpr int kDefaultRbits = 256;   // 默认基域大小（推荐值）
constexpr int kDefaultQbits = 1536;  // 默认椭圆曲线阶数大小（推荐值）

class ZrElement;
class G1Element;
class GTElement;

/**
 * 双线性配对上下文类
 * 管理PBC库的配对参数和配对对象的生命周期
 * 使用Type A曲线(对称配对)
 */
class PairingContext {
   public:
    /**
     * 构造函数
     * @param rbits 基域大小(比特)
     * @param qbits 椭圆曲线阶数大小(比特)
     * @throws std::invalid_argument 如果参数低于最小安全阈值
     */
    PairingContext(int rbits, int qbits);
    
    // 禁止拷贝
    PairingContext(const PairingContext&) = delete;
    PairingContext& operator=(const PairingContext&) = delete;
    
    /**
     * 析构函数
     * 清理配对参数和配对对象
     */
    ~PairingContext();

    /**
     * 获取配对对象
     * @return 配对对象引用
     */
    pairing_t& pairing();
    pairing_t& pairing() const;

   private:
    pbc_param_t param_;    // PBC参数
    pairing_t pairing_;    // 配对对象
};

/**
 * XOR操作 - 用于流加密
 * @param data 数据
 * @param key 密钥流
 * @return data XOR key
 * @throws std::invalid_argument 如果密钥流长度小于数据长度
 */
std::vector<uint8_t> xorWithKeystream(const std::vector<uint8_t>& data,
                                      const std::vector<uint8_t>& key);

/**
 * 从共享密钥派生密钥流
 * 使用SHA256的计数器模式KDF
 * @param secret 共享密钥(GT群元素)
 * @param length 需要的密钥流长度
 * @return 密钥流
 */
std::vector<uint8_t> sharedSecretToKeystream(const GTElement& secret, size_t length);

/**
 * 将字符串哈希到G1群
 * 使用SHA256哈希后映射到G1
 * @param pairing 配对对象
 * @param input 输入字符串
 * @param out 输出G1元素(已初始化)
 */
void hashStringToG1(pairing_t pairing, const std::string& input, G1Element& out);

/**
 * 将字符串哈希到Zr群
 * 使用SHA256哈希后映射到Zr
 * @param pairing 配对对象
 * @param input 输入字符串
 * @param out 输出Zr元素(已初始化)
 */
void hashStringToZr(pairing_t pairing, const std::string& input, ZrElement& out);

/**
 * 序列化群元素为字节数组
 * @param element 群元素
 * @return 字节数组
 */
std::vector<uint8_t> serializeElement(const ZrElement& element);
std::vector<uint8_t> serializeElement(const G1Element& element);
std::vector<uint8_t> serializeElement(const GTElement& element);

/**
 * 将字节数组转换为十六进制字符串
 * @param data 字节数组
 * @return 十六进制字符串
 */
std::string toHex(const std::vector<uint8_t>& data);

/**
 * Zr元素的RAII封装类
 * 用于自动管理Zr群中元素的生命周期
 */
class ZrElement {
   public:
    explicit ZrElement(pairing_t pairing);
    ZrElement(const ZrElement&) = delete;
    ZrElement& operator=(const ZrElement&) = delete;
    ZrElement(ZrElement&& other) noexcept;
    ZrElement& operator=(ZrElement&& other) noexcept;
    ~ZrElement();
    void randomize();
    void invert();
    void setInvert(const ZrElement& src);
    void setFromHash(const void* data, size_t len);
    void setOne();
    void setZero();
    void setNegate(const ZrElement& src);
    void setSub(const ZrElement& a, const ZrElement& b);
    void setSi(long value);
    void setDiv(const ZrElement& numerator, const ZrElement& denominator);
    bool isZero() const;
    void set(const ZrElement& src);
    bool equals(const ZrElement& other) const;
    void setAdd(const ZrElement& a, const ZrElement& b);
    void setMul(const ZrElement& a, const ZrElement& b);
    void fromBytes(const uint8_t* buffer);
    void fromBytes(const std::vector<uint8_t>& buffer);
    element_t& get();
    element_t& get() const;

   private:
    pairing_ptr pairing_;
    element_t value_;
};

/**
 * G1元素的RAII封装类
 * 用于自动管理G1群中元素的生命周期
 */
class G1Element {
   public:
    explicit G1Element(pairing_t pairing);
    G1Element(const G1Element&) = delete;
    G1Element& operator=(const G1Element&) = delete;
    G1Element(G1Element&& other) noexcept;
    G1Element& operator=(G1Element&& other) noexcept;
    ~G1Element();
    void randomize();
    void setFromHash(const void* data, size_t len);
    void setPowZn(const G1Element& base, const ZrElement& exponent);
    void setPowZn(const G1Element& base, element_t exponent);
    void setPowZn(element_t base, const ZrElement& exponent);
    void setPowZn(element_t base, element_t exponent);
    void setMul(const G1Element& a, const G1Element& b);
    void fromBytes(const uint8_t* buffer);
    void fromBytes(const std::vector<uint8_t>& buffer);
    element_t& get();
    element_t& get() const;

   private:
    pairing_ptr pairing_;
    element_t value_;
};

/**
 * GT元素的RAII封装类
 * 用于自动管理GT群中元素的生命周期
 */
class GTElement {
   public:
    explicit GTElement(pairing_t pairing);
    GTElement(const GTElement&) = delete;
    GTElement& operator=(const GTElement&) = delete;
    GTElement(GTElement&& other) noexcept;
    GTElement& operator=(GTElement&& other) noexcept;
    ~GTElement();
    void randomize();
    void setPowZn(const GTElement& base, const ZrElement& exponent);
    void setPowZn(const GTElement& base, element_t exponent);
    void setPowZn(element_t base, const ZrElement& exponent);
    void setPowZn(element_t base, element_t exponent);
    void setMul(const GTElement& a, const GTElement& b);
    void set(const GTElement& src);
    void setOne();
    void setPairing(const G1Element& a, const G1Element& b, pairing_t pairing);
    void invert();
    bool equals(const GTElement& other) const;
    void fromBytes(const uint8_t* buffer);
    void fromBytes(const std::vector<uint8_t>& buffer);
    element_t& get();
    element_t& get() const;

   private:
    pairing_ptr pairing_;
    element_t value_;
};

/**
 * 计算拉格朗日插值系数 (针对整数索引)
 * λ_target = Π_{j∈S,j≠target} (-j)/(target-j)
 * @param pairing 配对对象
 * @param indexes 索引集合 S
 * @param target 目标索引 target
 * @param out 输出结果
 */
void lagrangeCoefficient(pairing_t pairing, 
                        const std::vector<int>& indexes, 
                        int target, 
                        ZrElement& out);

/**
 * 使用Horner方法计算多项式值 (针对整数点)
 * p(x) = a_0 + a_1*x + ... + a_n*x^n
 * @param pairing 配对对象
 * @param coefficients 多项式系数 (a_0, ..., a_n)
 * @param point 求值点 x (整数)
 * @param out 输出结果
 */
void evaluatePolynomial(pairing_t pairing,
                       const std::vector<std::unique_ptr<ZrElement>>& coefficients,
                       int point,
                       ZrElement& out);
void evaluatePolynomial(pairing_t pairing,
                       const std::vector<ZrElement>& coefficients,
                       const ZrElement& point,
                       ZrElement& out);
void lagrangeCoefficient(pairing_t pairing,
                        const std::vector<ZrElement>& scalars,
                        size_t index,
                        ZrElement& out);

}  // namespace common
