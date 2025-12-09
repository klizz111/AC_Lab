#include "utils.h"

#include <openssl/crypto.h>

// 生成空 BIGNUM。
Big BNUtils::make() {
    Big bn(BN_new());
    if (!bn) throw std::runtime_error("BN_new failed");
    return bn;
}

// 十六进制字符串转 BIGNUM。
Big BNUtils::from_hex(const std::string& hex) {
    BIGNUM* raw = nullptr;
    if (!BN_hex2bn(&raw, hex.c_str())) throw std::runtime_error("BN_hex2bn failed");
    return Big(raw);
}

// 64 位整数转 BIGNUM。
Big BNUtils::from_uint(uint64_t value) {
    Big bn = make();
    if (!BN_set_word(bn.get(), value)) throw std::runtime_error("BN_set_word failed");
    return bn;
}

// 拷贝 BIGNUM。
Big BNUtils::dup(const BIGNUM* src) {
    Big bn(BN_dup(src));
    if (!bn) throw std::runtime_error("BN_dup failed");
    return bn;
}

Big BNUtils::dup(const Big& src) { return dup(src.get()); }

// BIGNUM 转十六进制字符串。
std::string BNUtils::to_hex(const BIGNUM* bn) {
    char* hex = BN_bn2hex(bn);
    if (!hex) throw std::runtime_error("BN_bn2hex failed");
    std::string out(hex);
    OPENSSL_free(hex);
    return out;
}

std::string BNUtils::to_hex(const Big& bn) { return to_hex(bn.get()); }

// 模乘。
Big BNUtils::mod_mul(const BIGNUM* a, const BIGNUM* b, const BIGNUM* mod, BN_CTX* ctx) {
    Big r = make();
    if (!BN_mod_mul(r.get(), a, b, mod, ctx)) throw std::runtime_error("BN_mod_mul failed");
    return r;
}

Big BNUtils::mod_mul(const Big& a, const Big& b, const Big& mod, BN_CTX* ctx) {
    return mod_mul(a.get(), b.get(), mod.get(), ctx);
}

Big BNUtils::mod_mul(const BIGNUM* a, const Big& b, const Big& mod, BN_CTX* ctx) {
    return mod_mul(a, b.get(), mod.get(), ctx);
}

Big BNUtils::mod_mul(const Big& a, const Big& b, const Big& mod, Ctx& ctx) {
    return mod_mul(a, b, mod, ctx.get());
}

Big BNUtils::mod_mul(const BIGNUM* a, const Big& b, const Big& mod, Ctx& ctx) {
    return mod_mul(a, b, mod, ctx.get());
}

Big BNUtils::mod_mul(const Big& a, const Big& b, const Big& mod) {
    Ctx ctx(BN_CTX_new());
    if (!ctx) throw std::runtime_error("BN_CTX_new failed");
    return mod_mul(a, b, mod, ctx.get());
}

Big BNUtils::mod_mul(const BIGNUM* a, const Big& b, const Big& mod) {
    Ctx ctx(BN_CTX_new());
    if (!ctx) throw std::runtime_error("BN_CTX_new failed");
    return mod_mul(a, b, mod, ctx.get());
}

// 模幂。
Big BNUtils::mod_exp(const BIGNUM* base, const BIGNUM* exp, const BIGNUM* mod, BN_CTX* ctx) {
    Big r = make();
    if (!BN_mod_exp(r.get(), base, exp, mod, ctx)) throw std::runtime_error("BN_mod_exp failed");
    return r;
}

Big BNUtils::mod_exp(const Big& base, const Big& exp, const Big& mod, BN_CTX* ctx) {
    return mod_exp(base.get(), exp.get(), mod.get(), ctx);
}

Big BNUtils::mod_exp(const Big& base, const Big& exp, const Big& mod, Ctx& ctx) {
    return mod_exp(base, exp, mod, ctx.get());
}

Big BNUtils::mod_exp(const Big& base, const Big& exp, const Big& mod) {
    Ctx ctx(BN_CTX_new());
    if (!ctx) throw std::runtime_error("BN_CTX_new failed");
    return mod_exp(base, exp, mod, ctx.get());
}

// 模逆。
Big BNUtils::mod_inv(const BIGNUM* a, const BIGNUM* mod, BN_CTX* ctx) {
    Big r(make());
    if (!BN_mod_inverse(r.get(), a, mod, ctx)) throw std::runtime_error("BN_mod_inverse failed");
    return r;
}

Big BNUtils::mod_inv(const Big& a, const Big& mod, BN_CTX* ctx) {
    return mod_inv(a.get(), mod.get(), ctx);
}

Big BNUtils::mod_inv(const Big& a, const Big& mod, Ctx& ctx) {
    return mod_inv(a, mod, ctx.get());
}

Big BNUtils::mod_inv(const Big& a, const Big& mod) {
    Ctx ctx(BN_CTX_new());
    if (!ctx) throw std::runtime_error("BN_CTX_new failed");
    return mod_inv(a, mod, ctx.get());
}

Big BNUtils::mod(const Big& a, const Big& mod, BN_CTX* ctx) {
    Big out = make();
    if (!BN_mod(out.get(), a.get(), mod.get(), ctx)) throw std::runtime_error("BN_mod failed");
    return out;
}

Big BNUtils::mod(const Big& a, const Big& mod, Ctx& ctx) { return BNUtils::mod(a, mod, ctx.get()); }

Big BNUtils::mod(const Big& a, const Big& mod) {
    Ctx ctx(BN_CTX_new());
    if (!ctx) throw std::runtime_error("BN_CTX_new failed");
    return BNUtils::mod(a, mod, ctx.get());
}

// 生成区间 (0, upper_exclusive) 内随机数。
Big BNUtils::random_range(const BIGNUM* upper_exclusive) {
    Big r = make();
    do {
        if (!BN_priv_rand_range(r.get(), upper_exclusive))
            throw std::runtime_error("BN_priv_rand_range failed");
    } while (BN_is_zero(r.get()));
    return r;
}

Big BNUtils::random_range(const Big& upper_exclusive) {
    return random_range(upper_exclusive.get());
}

// 字节数组转 BIGNUM。
Big BNUtils::from_bytes(const std::vector<uint8_t>& data) {
    if (data.empty()) throw std::runtime_error("Plaintext is empty");
    Big bn = make();
    if (!BN_bin2bn(data.data(), static_cast<int>(data.size()), bn.get()))
        throw std::runtime_error("BN_bin2bn failed");
    return bn;
}

// BIGNUM 定长导出到字节数组。
std::vector<uint8_t> BNUtils::to_bytes(const BIGNUM* bn, size_t out_len) {
    std::vector<uint8_t> buf(out_len);
    if (BN_bn2binpad(bn, buf.data(), static_cast<int>(out_len)) < 0)
        throw std::runtime_error("BN_bn2binpad failed");
    return buf;
}

std::vector<uint8_t> BNUtils::to_bytes(const Big& bn, size_t out_len) {
    return to_bytes(bn.get(), out_len);
}

void BNUtils::add_word(Big& a, unsigned long w) {
    if (!BN_add_word(a.get(), w)) throw std::runtime_error("BN_add_word failed");
}

void BNUtils::sub_word(Big& a, unsigned long w) {
    if (!BN_sub_word(a.get(), w)) throw std::runtime_error("BN_sub_word failed");
}

void BNUtils::rshift1(Big& a) {
    if (!BN_rshift1(a.get(), a.get())) throw std::runtime_error("BN_rshift1 failed");
}

Big BNUtils::mul(const Big& a, const Big& b, BN_CTX* ctx) {
    Big out = make();
    if (!BN_mul(out.get(), a.get(), b.get(), ctx)) throw std::runtime_error("BN_mul failed");
    return out;
}

Big BNUtils::mul(const Big& a, const Big& b, Ctx& ctx) { return mul(a, b, ctx.get()); }

Big BNUtils::mul(const Big& a, const Big& b) {
    Ctx ctx(BN_CTX_new());
    if (!ctx) throw std::runtime_error("BN_CTX_new failed");
    return mul(a, b, ctx.get());
}

Big BNUtils::div(const Big& numerator, const Big& denominator, BN_CTX* ctx) {
    Big out = make();
    if (!BN_div(out.get(), nullptr, numerator.get(), denominator.get(), ctx))
        throw std::runtime_error("BN_div failed");
    return out;
}

Big BNUtils::div(const Big& numerator, const Big& denominator, Ctx& ctx) {
    return div(numerator, denominator, ctx.get());
}

Big BNUtils::div(const Big& numerator, const Big& denominator) {
    Ctx ctx(BN_CTX_new());
    if (!ctx) throw std::runtime_error("BN_CTX_new failed");
    return div(numerator, denominator, ctx.get());
}

Big BNUtils::mod_sub(const Big& a, const Big& b, const Big& mod, BN_CTX* ctx) {
    Big out = make();
    if (!BN_mod_sub(out.get(), a.get(), b.get(), mod.get(), ctx))
        throw std::runtime_error("BN_mod_sub failed");
    return out;
}

Big BNUtils::mod_sub(const Big& a, const Big& b, const Big& mod, Ctx& ctx) {
    return mod_sub(a, b, mod, ctx.get());
}

Big BNUtils::mod_sub(const Big& a, const Big& b, const Big& mod) {
    Ctx ctx(BN_CTX_new());
    if (!ctx) throw std::runtime_error("BN_CTX_new failed");
    return mod_sub(a, b, mod, ctx.get());
}

int BNUtils::cmp(const Big& a, const Big& b) { return BN_cmp(a.get(), b.get()); }
int BNUtils::cmp(const BIGNUM* a, const BIGNUM* b) { return BN_cmp(a, b); }
int BNUtils::cmp(const Big& a, const BIGNUM* b) { return BN_cmp(a.get(), b); }
int BNUtils::cmp(const BIGNUM* a, const Big& b) { return BN_cmp(a, b.get()); }

Big BNUtils::gcd(const Big& a, const Big& b, BN_CTX* ctx) {
    Big out = make();
    if (!BN_gcd(out.get(), a.get(), b.get(), ctx)) throw std::runtime_error("BN_gcd failed");
    return out;
}

Big BNUtils::gcd(const Big& a, const Big& b, Ctx& ctx) {
    return gcd(a, b, ctx.get());
}

Big BNUtils::gcd(const Big& a, const Big& b) {
    Ctx ctx(BN_CTX_new());
    if (!ctx) throw std::runtime_error("BN_CTX_new failed");
    return gcd(a, b, ctx.get());
}

bool BNUtils::is_one(const Big& a) { return BN_is_one(a.get()); }

bool BNUtils::is_zero(const Big& a) { return BN_is_zero(a.get()); }

void BNUtils::generate_prime(Big& out, int bits, bool safe) {
    if (!BN_generate_prime_ex(out.get(), bits, safe ? 1 : 0, nullptr, nullptr, nullptr))
        throw std::runtime_error("BN_generate_prime_ex failed");
}
