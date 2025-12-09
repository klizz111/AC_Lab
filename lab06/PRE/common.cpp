/**
 * 公共工具实现文件
 * 实现所有密码学方案共享的工具函数
 */

#include "common.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace common {

/**
 * PairingContext构造函数
 * 初始化Type A配对参数
 */
PairingContext::PairingContext(int rbits, int qbits) {
    // 检查安全参数
    if (rbits < kMinimumRbits || qbits < kMinimumQbits) {
        throw std::invalid_argument("security parameters below recommended threshold");
    }
    // 生成Type A曲线参数
    pbc_param_init_a_gen(param_, rbits, qbits);
    // 初始化配对
    pairing_init_pbc_param(pairing_, param_);
}

/**
 * PairingContext析构函数
 * 清理配对和参数
 */
PairingContext::~PairingContext() {
    pairing_clear(pairing_);
    pbc_param_clear(param_);
}

pairing_t& PairingContext::pairing() { return pairing_; }

pairing_t& PairingContext::pairing() const { return const_cast<pairing_t&>(pairing_); }

/**
 * XOR操作实现
 * 用于对称加密/解密
 */
std::vector<uint8_t> xorWithKeystream(const std::vector<uint8_t>& data,
                                      const std::vector<uint8_t>& key) {
    if (key.size() < data.size()) {
        throw std::invalid_argument("keystream shorter than data");
    }
    std::vector<uint8_t> result(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        result[i] = data[i] ^ key[i];
    }
    return result;
}

/**
 * 密钥派生函数(KDF)
 * 使用SHA256的计数器模式
 * KDF(secret, length) = SHA256(secret||0) || SHA256(secret||1) || ...
 */
std::vector<uint8_t> sharedSecretToKeystream(const GTElement& secret, size_t length) {
    std::vector<uint8_t> secret_bytes(element_length_in_bytes(secret.get()));
    element_to_bytes(secret_bytes.data(), secret.get());

    std::vector<uint8_t> keystream(length);
    size_t produced = 0;
    uint32_t counter = 0;
    std::array<uint8_t, SHA256_DIGEST_LENGTH> digest{};

    while (produced < length) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) {
            throw std::runtime_error("EVP_MD_CTX_new failed");
        }
        EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(ctx, secret_bytes.data(), secret_bytes.size());

        uint8_t counter_bytes[4] = {static_cast<uint8_t>((counter >> 24) & 0xFF),
                                    static_cast<uint8_t>((counter >> 16) & 0xFF),
                                    static_cast<uint8_t>((counter >> 8) & 0xFF),
                                    static_cast<uint8_t>(counter & 0xFF)};
        EVP_DigestUpdate(ctx, counter_bytes, sizeof(counter_bytes));
        EVP_DigestFinal_ex(ctx, digest.data(), nullptr);
        EVP_MD_CTX_free(ctx);

        size_t to_copy = std::min(static_cast<size_t>(digest.size()), length - produced);
        std::copy_n(digest.begin(), to_copy, keystream.begin() + produced);
        produced += to_copy;
        ++counter;
    }

    return keystream;
}

/**
 * 哈希到G1群
 * H: {0,1}* -> G1
 */
void hashStringToG1(pairing_t pairing, const std::string& input, G1Element& out) {
    // 计算SHA256哈希
    std::array<uint8_t, SHA256_DIGEST_LENGTH> digest{};
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, input.data(), input.size());
    EVP_DigestFinal_ex(ctx, digest.data(), nullptr);
    EVP_MD_CTX_free(ctx);
    
    // 从哈希值映射到G1
    out.setFromHash(digest.data(), digest.size());
}

/**
 * 哈希到Zr群
 * H: {0,1}* -> Zr
 */
void hashStringToZr(pairing_t pairing, const std::string& input, ZrElement& out) {
    // 计算SHA256哈希
    std::array<uint8_t, SHA256_DIGEST_LENGTH> digest{};
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, input.data(), input.size());
    EVP_DigestFinal_ex(ctx, digest.data(), nullptr);
    EVP_MD_CTX_free(ctx);
    
    // 从哈希值映射到Zr
    out.setFromHash(digest.data(), digest.size());
}

/**
 * 序列化群元素
 * 将群元素转换为字节数组以便存储或传输
 */
std::vector<uint8_t> serializeElement(const ZrElement& element) {
    const int len = element_length_in_bytes(element.get());
    std::vector<uint8_t> buffer(len);
    element_to_bytes(buffer.data(), element.get());
    return buffer;
}

std::vector<uint8_t> serializeElement(const G1Element& element) {
    const int len = element_length_in_bytes(element.get());
    std::vector<uint8_t> buffer(len);
    element_to_bytes(buffer.data(), element.get());
    return buffer;
}

std::vector<uint8_t> serializeElement(const GTElement& element) {
    const int len = element_length_in_bytes(element.get());
    std::vector<uint8_t> buffer(len);
    element_to_bytes(buffer.data(), element.get());
    return buffer;
}

/**
 * 字节数组转十六进制字符串
 * 用于调试和显示
 */
std::string toHex(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t b : data) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

// ZrElement实现
ZrElement::ZrElement(pairing_t pairing) : pairing_(pairing) {
    element_init_Zr(value_, pairing_);
}

ZrElement::ZrElement(ZrElement&& other) noexcept : pairing_(other.pairing_) {
    element_init_Zr(value_, pairing_);
    element_set(value_, other.value_);
}

ZrElement& ZrElement::operator=(ZrElement&& other) noexcept {
    if (this != &other) {
        element_clear(value_);
        pairing_ = other.pairing_;
        element_init_Zr(value_, pairing_);
        element_set(value_, other.value_);
    }
    return *this;
}

ZrElement::~ZrElement() {
    element_clear(value_);
}

void ZrElement::randomize() {
    element_random(value_);
}

void ZrElement::invert() {
    element_invert(value_, value_);
}

void ZrElement::setInvert(const ZrElement& src) {
    element_invert(value_, src.get());
}

void ZrElement::setFromHash(const void* data, size_t len) {
    element_from_hash(value_, const_cast<void*>(data), static_cast<int>(len));
}

void ZrElement::setOne() {
    element_set1(value_);
}

void ZrElement::setZero() {
    element_set0(value_);
}

void ZrElement::setNegate(const ZrElement& src) {
    element_neg(value_, src.get());
}

void ZrElement::setSub(const ZrElement& a, const ZrElement& b) {
    element_sub(value_, a.get(), b.get());
}

void ZrElement::setSi(long value) {
    element_set_si(value_, value);
}

void ZrElement::setDiv(const ZrElement& numerator, const ZrElement& denominator) {
    element_div(value_, numerator.get(), denominator.get());
}

bool ZrElement::isZero() const {
    return element_is0(const_cast<element_t&>(value_)) != 0;
}

void ZrElement::set(const ZrElement& src) {
    element_set(value_, src.get());
}

bool ZrElement::equals(const ZrElement& other) const {
    return element_cmp(const_cast<element_t&>(value_), const_cast<element_t&>(other.value_)) == 0;
}

void ZrElement::setAdd(const ZrElement& a, const ZrElement& b) {
    element_add(value_, a.get(), b.get());
}

void ZrElement::setMul(const ZrElement& a, const ZrElement& b) {
    element_mul(value_, a.get(), b.get());
}

void ZrElement::fromBytes(const uint8_t* buffer) {
    element_from_bytes(value_, const_cast<uint8_t*>(buffer));
}

void ZrElement::fromBytes(const std::vector<uint8_t>& buffer) {
    if (buffer.empty()) {
        throw std::invalid_argument("buffer for ZrElement::fromBytes is empty");
    }
    fromBytes(buffer.data());
}

element_t& ZrElement::get() {
    return value_;
}

element_t& ZrElement::get() const {
    return const_cast<element_t&>(value_);
}

// G1Element实现
G1Element::G1Element(pairing_t pairing) : pairing_(pairing) {
    element_init_G1(value_, pairing_);
}

G1Element::G1Element(G1Element&& other) noexcept : pairing_(other.pairing_) {
    element_init_G1(value_, pairing_);
    element_set(value_, other.value_);
}

G1Element& G1Element::operator=(G1Element&& other) noexcept {
    if (this != &other) {
        element_clear(value_);
        pairing_ = other.pairing_;
        element_init_G1(value_, pairing_);
        element_set(value_, other.value_);
    }
    return *this;
}

G1Element::~G1Element() {
    element_clear(value_);
}

void G1Element::randomize() {
    element_random(value_);
}

void G1Element::setFromHash(const void* data, size_t len) {
    element_from_hash(value_, const_cast<void*>(data), static_cast<int>(len));
}

void G1Element::setPowZn(const G1Element& base, const ZrElement& exponent) {
    element_pow_zn(value_, base.get(), exponent.get());
}

void G1Element::setPowZn(const G1Element& base, element_t exponent) {
    element_pow_zn(value_, base.get(), exponent);
}

void G1Element::setPowZn(element_t base, const ZrElement& exponent) {
    element_pow_zn(value_, base, exponent.get());
}

void G1Element::setPowZn(element_t base, element_t exponent) {
    element_pow_zn(value_, base, exponent);
}

void G1Element::setMul(const G1Element& a, const G1Element& b) {
    element_mul(value_, a.get(), b.get());
}

void G1Element::fromBytes(const uint8_t* buffer) {
    element_from_bytes(value_, const_cast<uint8_t*>(buffer));
}

void G1Element::fromBytes(const std::vector<uint8_t>& buffer) {
    if (buffer.empty()) {
        throw std::invalid_argument("buffer for G1Element::fromBytes is empty");
    }
    fromBytes(buffer.data());
}

element_t& G1Element::get() {
    return value_;
}

element_t& G1Element::get() const {
    return const_cast<element_t&>(value_);
}

// GTElement实现
GTElement::GTElement(pairing_t pairing) : pairing_(pairing) {
    element_init_GT(value_, pairing_);
}

GTElement::GTElement(GTElement&& other) noexcept : pairing_(other.pairing_) {
    element_init_GT(value_, pairing_);
    element_set(value_, other.value_);
}

GTElement& GTElement::operator=(GTElement&& other) noexcept {
    if (this != &other) {
        element_clear(value_);
        pairing_ = other.pairing_;
        element_init_GT(value_, pairing_);
        element_set(value_, other.value_);
    }
    return *this;
}

GTElement::~GTElement() {
    element_clear(value_);
}

void GTElement::randomize() {
    element_random(value_);
}

void GTElement::setPowZn(const GTElement& base, const ZrElement& exponent) {
    element_pow_zn(value_, base.get(), exponent.get());
}

void GTElement::setPowZn(const GTElement& base, element_t exponent) {
    element_pow_zn(value_, base.get(), exponent);
}

void GTElement::setPowZn(element_t base, const ZrElement& exponent) {
    element_pow_zn(value_, base, exponent.get());
}

void GTElement::setPowZn(element_t base, element_t exponent) {
    element_pow_zn(value_, base, exponent);
}

void GTElement::setMul(const GTElement& a, const GTElement& b) {
    element_mul(value_, a.get(), b.get());
}

void GTElement::set(const GTElement& src) {
    element_set(value_, src.get());
}

void GTElement::setOne() {
    element_set1(value_);
}

void GTElement::setPairing(const G1Element& a, const G1Element& b, pairing_t pairing) {
    pairing_apply(value_, a.get(), b.get(), pairing);
}

void GTElement::invert() {
    element_invert(value_, value_);
}

void GTElement::fromBytes(const uint8_t* buffer) {
    element_from_bytes(value_, const_cast<uint8_t*>(buffer));
}

void GTElement::fromBytes(const std::vector<uint8_t>& buffer) {
    if (buffer.empty()) {
        throw std::invalid_argument("buffer for GTElement::fromBytes is empty");
    }
    fromBytes(buffer.data());
}

bool GTElement::equals(const GTElement& other) const {
    return element_cmp(const_cast<element_t&>(value_), const_cast<element_t&>(other.value_)) == 0;
}

element_t& GTElement::get() {
    return value_;
}

element_t& GTElement::get() const {
    return const_cast<element_t&>(value_);
}

void lagrangeCoefficient(pairing_t pairing, 
                        const std::vector<int>& indexes, 
                        int target, 
                        ZrElement& out) {
    out.setOne();
    ZrElement numerator(pairing);
    ZrElement denominator(pairing);
    ZrElement temp(pairing);

    for (int index : indexes) {
        if (index == target) continue;

        // numerator = -index
        temp.setSi(index);
        numerator.setNegate(temp);

        // denominator = target - index
        denominator.setSi(target - index);

        // out *= numerator / denominator
        temp.setDiv(numerator, denominator);
        out.setMul(out, temp);
    }
}

void evaluatePolynomial(pairing_t pairing,
                       const std::vector<std::unique_ptr<ZrElement>>& coefficients,
                       int point,
                       ZrElement& out) {
    out.setZero();
    ZrElement x(pairing);
    x.setSi(point);

    ZrElement power(pairing);
    power.setOne();

    ZrElement term(pairing);

    for (const auto& coeff : coefficients) {
        // out += coeff * x^i
        term.setMul(*coeff, power);
        out.setAdd(out, term);
        power.setMul(power, x);
    }
}

void evaluatePolynomial(pairing_t pairing,
                       const std::vector<ZrElement>& coefficients,
                       const ZrElement& point,
                       ZrElement& out) {
    out.setZero();
    ZrElement power(pairing);
    power.setOne();
    ZrElement term(pairing);
    for (const auto& coeff : coefficients) {
        term.setMul(coeff, power);
        out.setAdd(out, term);
        power.setMul(power, point);
    }
}

void lagrangeCoefficient(pairing_t pairing,
                        const std::vector<ZrElement>& scalars,
                        size_t index,
                        ZrElement& out) {
    out.setOne();
    ZrElement temp_num(pairing);
    ZrElement temp_den(pairing);
    ZrElement inv_den(pairing);
    for (size_t j = 0; j < scalars.size(); ++j) {
        if (j == index) continue;
        temp_num.setNegate(scalars[j]);
        out.setMul(out, temp_num);

        temp_den.setSub(scalars[index], scalars[j]);
        inv_den.setInvert(temp_den);
        out.setMul(out, inv_den);
    }
}

}  // namespace common
