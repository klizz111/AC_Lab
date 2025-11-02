#ifndef ELGAMAL_HPP
#define ELGAMAL_HPP
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/bn.h> 
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <random>
#include "utils.hpp"

using namespace std;
std::default_random_engine generator(static_cast<unsigned>(time(0)));
std::uniform_int_distribution<int> distribution(1, 1<<16);    

class ElGamalCiphertext {
private:
    BIGNUM *p;
    BIGNUM *g;
    BIGNUM *y;
public:
    BIGNUM *c1;
    BIGNUM *c2;
    ElGamalCiphertext() {
        p = BN_new();
        g = BN_new();
        y = BN_new();
        c1 = BN_new();
        c2 = BN_new();
    }

    ElGamalCiphertext(BIGNUM *p, BIGNUM *g, BIGNUM *y, BIGNUM *c1, BIGNUM *c2) {
        this->p = BN_new();
        this->g = BN_new();
        this->y = BN_new();
        this->c1 = BN_new();
        this->c2 = BN_new();
        BN_copy(this->p, p);
        BN_copy(this->g, g);
        BN_copy(this->y, y);
        BN_copy(this->c1, c1);
        BN_copy(this->c2, c2);
    }

    string to_string() const {
        stringstream ss;
        ss << "(" << BN_bn2hex(c1) << ", " << BN_bn2hex(c2) << ")";
        return ss.str();
    }

    ElGamalCiphertext operator*(const ElGamalCiphertext &other) const {
        if (BN_cmp(this->p, other.p) != 0 || BN_cmp(this->g, other.g) != 0 || BN_cmp(this->y, other.y) != 0) {
            throw std::invalid_argument("Cannot multiply ciphertexts with different parameters.");
        }
        ElGamalCiphertext result;
        BN_CTX *ctx = BN_CTX_new();
        BN_mod_mul(result.c1, this->c1, other.c1, this->p, ctx);
        BN_mod_mul(result.c2, this->c2, other.c2, this->p, ctx);
        BN_copy(result.p, this->p);
        BN_copy(result.g, this->g);
        BN_copy(result.y, this->y);
        BN_CTX_free(ctx);
        return result;
    }
};

class ElGamal {
private:
    BIGNUM *p;
    BIGNUM *g;
    BIGNUM *x;
    BIGNUM *y;
public:
    ElGamal() { p = BN_new(); g = BN_new(); x = BN_new(); y = BN_new(); }
    void generate_secure_key_parameters();
    string get_public_key();
    string get_private_key();
    vector<std::pair<int, BIGNUM*>> split_secret_key(int threshold, int total_shares);
    ElGamalCiphertext encrypt(int message);
    int decrypt(const ElGamalCiphertext &ciphertext);
    int distributed_decrypt(ElGamalCiphertext &dist_ciphertext, const vector<std::pair<int, BIGNUM*>> &shares);
};

void ElGamal::generate_secure_key_parameters() {
    // 1. 生成素数 p = 2q + 1
    BIGNUM *q = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create BN_CTX");
    }

    BIGNUM *candidate_p = BN_new();
    BIGNUM *two = BN_new();
    BN_set_word(two, 2);

    while (true) {
        // 生成 (bits-1) 位的素数 q
        if (!BN_generate_prime_ex(q, 1023, 0, NULL, NULL, NULL)) {
            throw std::runtime_error("Failed to generate prime q");
        }

        // 计算 p = 2q + 1
        BN_mul(candidate_p, q, two, ctx); // candidate_p = 2 * q
        BN_add(candidate_p, candidate_p, BN_value_one()); // candidate_p = 2 * q + 1

        // 检查 p 是否为素数
        if (BN_check_prime(candidate_p, ctx, NULL)) {
            break;
        }
    }

    // 将结果赋值给 p
    BN_copy(p, candidate_p);

    // 2. 选取生成元 g
    BIGNUM *h = BN_new();
    BIGNUM *exp = BN_new();
    BN_set_word(exp, 2);

    while (true) {
        // 生成随机数 h ∈ [2, p-1]
        BN_rand_range(h, p);
        if (BN_cmp(h, BN_value_one()) <= 0) continue;

        // g = h^2 mod p
        BN_mod_exp(g, h, exp, p, ctx);
        if (BN_cmp(g, BN_value_one()) != 0) break;
    }

    // 3. 生成私钥 x ∈ [1, q-1]
    BIGNUM *q_minus_1 = BN_new();
    BN_sub(q_minus_1, q, BN_value_one());
    BN_rand_range(x, q_minus_1);
    BN_add(x, x, BN_value_one()); // 确保 x ∈ [1, q-1]

    // 4. 计算公钥 y = g^x mod p
    BN_mod_exp(y, g, x, p, ctx);

    // 清理内存
    BN_free(candidate_p);
    BN_free(two);
    BN_free(h);
    BN_free(exp);
    BN_free(q_minus_1);
    BN_CTX_free(ctx);
}

string ElGamal::get_public_key() {
    stringstream ss;
    ss << "p: " << BN_bn2hex(p) << "\n";
    ss << "g: " << BN_bn2hex(g) << "\n";
    ss << "y: " << BN_bn2hex(y);
    return ss.str();
}

string ElGamal::get_private_key() {
    stringstream ss;
    ss << "x: " << BN_bn2hex(x);
    /// return ss.str().substr(0,50) + "..."; 
    return ss.str();
}

inline vector<std::pair<int, BIGNUM *>> ElGamal::split_secret_key(int threshold, int total_shares)
{
    // 1. 生成系数
    auto [priv, coeffs] = generate_secret_and_coeffs(p, x, threshold);

    // 2. 生成份额
    auto shares = generate_shares(p, coeffs, total_shares);

    // 返回
    return shares;
    return vector<std::pair<int, BIGNUM *>>();
}

ElGamalCiphertext ElGamal::encrypt(int message)
{
    BIGNUM *m = BN_new();
    BN_set_word(m, message);

    BIGNUM *k = BN_new();
    BIGNUM *p_minus_2 = BN_new();
    BN_sub(p_minus_2, p, BN_value_one());
    BN_sub(p_minus_2, p_minus_2, BN_value_one()); // p-2
    BN_rand_range(k, p_minus_2); // k ∈ [1, p-2]
    BN_add(k, k, BN_value_one());

    // c1 = g^k mod p
    BIGNUM *c1 = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    BN_mod_exp(c1, g, k, p, ctx);

    // c2 = m * y^k mod p
    BIGNUM *y_k = BN_new();
    BN_mod_exp(y_k, y, k, p, ctx);
    BIGNUM *c2 = BN_new();
    BN_mod_mul(c2, m, y_k, p, ctx);

    return ElGamalCiphertext(p, g, y, c1, c2);
}

int ElGamal::decrypt(const ElGamalCiphertext &ciphertext)
{
    BIGNUM *s = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    BN_mod_exp(s, ciphertext.c1, x, p, ctx); // s = c1^x mod p
    BIGNUM *s_inv = BN_new();
    BN_mod_inverse(s_inv, s, p, ctx); // s_inv = s^(-1) mod p
    BIGNUM *m = BN_new();
    BN_mod_mul(m, ciphertext.c2, s_inv, p, ctx); // m = c2 * s_inv mod p
    int result = BN_get_word(m);

    return result;
}

inline int ElGamal::distributed_decrypt(ElGamalCiphertext &dist_ciphertext, const vector<std::pair<int, BIGNUM *>> &shares)
{
    // 重构x
    BIGNUM *re_x = BN_new();
    re_x = reconstruct_secret(p, shares);

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *s = BN_new();
    // 尝试解密
    try {
        BN_mod_exp(s, dist_ciphertext.c1, re_x, p, ctx); // s = c1^x mod p
        BIGNUM *s_inv = BN_new();
        BN_mod_inverse(s_inv, s, p, ctx); // s_inv = s^(-1) mod p
        BIGNUM *m = BN_new();
        BN_mod_mul(m, dist_ciphertext.c2, s_inv, p, ctx); // m = c2 * s_inv mod p
        int result = BN_get_word(m);
        return result;
    } catch (const std::exception &e) {
        std::cerr << "Error during distributed decryption: " << e.what() << "at " << __FILE__ << ":" << __LINE__ << "\n";
    }
    return -1;
}

int generate_random_message() {
    return distribution(generator);
}

#endif // ELGAMAL_HPP

