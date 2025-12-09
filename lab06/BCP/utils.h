#pragma once

#include <openssl/bn.h>
#include <openssl/rand.h>

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

// BN/CTX 智能指针删除器，避免手动释放。
struct BNDeleter { void operator()(BIGNUM* bn) const { BN_free(bn); } };
struct CtxDeleter { void operator()(BN_CTX* ctx) const { BN_CTX_free(ctx); } };

using Big = std::unique_ptr<BIGNUM, BNDeleter>;
using Ctx = std::unique_ptr<BN_CTX, CtxDeleter>;

// BNUtils: 聚合与方案无关的 BIGNUM 常用操作。
class BNUtils {
  public:
    static Big make();
    static Ctx cmake();
    static Big from_hex(const std::string& hex);
    static Big from_uint(uint64_t value);
    static Big dup(const BIGNUM* src);
    static Big dup(const Big& src);
    static std::string to_hex(const BIGNUM* bn);
    static std::string to_hex(const Big& bn);
    static Big mod_mul(const BIGNUM* a, const BIGNUM* b, const BIGNUM* mod, BN_CTX* ctx);
    static Big mod_mul(const Big& a, const Big& b, const Big& mod, BN_CTX* ctx);
    static Big mod_mul(const BIGNUM* a, const Big& b, const Big& mod, BN_CTX* ctx);
    static Big mod_mul(const Big& a, const Big& b, const Big& mod, Ctx& ctx);
    static Big mod_mul(const BIGNUM* a, const Big& b, const Big& mod, Ctx& ctx);
    static Big mod_mul(const Big& a, const Big& b, const Big& mod);
    static Big mod_mul(const BIGNUM* a, const Big& b, const Big& mod);
    static Big mod_exp(const BIGNUM* base, const BIGNUM* exp, const BIGNUM* mod, BN_CTX* ctx);
    static Big mod_exp(const Big& base, const Big& exp, const Big& mod, BN_CTX* ctx);
    static Big mod_exp(const Big& base, const Big& exp, const Big& mod, Ctx& ctx);
    static Big mod_exp(const Big& base, const Big& exp, const Big& mod);
    static Big mod_inv(const BIGNUM* a, const BIGNUM* mod, BN_CTX* ctx);
    static Big mod_inv(const Big& a, const Big& mod, BN_CTX* ctx);
    static Big mod_inv(const Big& a, const Big& mod, Ctx& ctx);
    static Big mod_inv(const Big& a, const Big& mod);
    static Big mod(const Big& a, const Big& mod, BN_CTX* ctx);
    static Big mod(const Big& a, const Big& mod, Ctx& ctx);
    static Big mod(const Big& a, const Big& mod);
    static Big random_range(const BIGNUM* upper_exclusive);
    static Big random_range(const Big& upper_exclusive);
    static Big from_bytes(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> to_bytes(const BIGNUM* bn, size_t out_len);
    static std::vector<uint8_t> to_bytes(const Big& bn, size_t out_len);
    static void add_word(Big& a, unsigned long w);
    static void sub_word(Big& a, unsigned long w);
    static void rshift1(Big& a);
    static Big mul(const Big& a, const Big& b, BN_CTX* ctx);
    static Big mul(const Big& a, const Big& b, Ctx& ctx);
    static Big mul(const Big& a, const Big& b);
    static Big div(const Big& numerator, const Big& denominator, BN_CTX* ctx);
    static Big div(const Big& numerator, const Big& denominator, Ctx& ctx);
    static Big div(const Big& numerator, const Big& denominator);
    static Big mod_sub(const Big& a, const Big& b, const Big& mod, BN_CTX* ctx);
    static Big mod_sub(const Big& a, const Big& b, const Big& mod, Ctx& ctx);
    static Big mod_sub(const Big& a, const Big& b, const Big& mod);
    static int cmp(const Big& a, const Big& b);
    static int cmp(const BIGNUM* a, const BIGNUM* b);
    static int cmp(const Big& a, const BIGNUM* b);
    static int cmp(const BIGNUM* a, const Big& b);
    static Big gcd(const Big& a, const Big& b, BN_CTX* ctx);
    static Big gcd(const Big& a, const Big& b, Ctx& ctx);
    static Big gcd(const Big& a, const Big& b);
    static bool is_one(const Big& a);
    static bool is_zero(const Big& a);
    static void generate_prime(Big& out, int bits, bool safe = true);
};
