#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/bn.h> 
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <random>

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
    ElGamalCiphertext encrypt(int message);
    int decrypt(const ElGamalCiphertext &ciphertext);
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

int generate_random_message() {
    return distribution(generator);
}

int main()
{
    std::cout << "=== ElGamal加密算法演示 ===" << std::endl;

    // 创建ElGamal实例
    ElGamal elgamal;

    // 生成安全密钥参数
    std::cout << "生成安全1024位密钥参数..." << std::endl;
    elgamal.generate_secure_key_parameters();

    // 显示密钥对
    std::cout << "公钥 (1024位素数 p): " << elgamal.get_public_key() << std::endl;
    std::cout << "私钥 (x值 - 为安全起见部分显示): ";
    std::string private_key = elgamal.get_private_key();
    // 只显示前50个字符以保护私钥安全
    if (private_key.length() > 50)
    {
        std::cout << private_key.substr(0, 50) << "...[为安全起见已截断]" << std::endl;
    }
    else
    {
        std::cout << private_key << std::endl;
    }

    // 加密演示
    std::cout << "\n=== 加密解密演示 ===" << std::endl;
    int message = generate_random_message();  
    std::cout << "原始消息: " << message << std::endl;

    ElGamalCiphertext ciphertext = elgamal.encrypt(message);
    std::cout << "密文: ";
    std::string cipher_str = ciphertext.to_string();
    std::cout << cipher_str << std::endl;

    int decrypted = elgamal.decrypt(ciphertext);
    std::cout << "解密结果: " << decrypted << std::endl;
    std::cout << "加解密验证: " << (message == decrypted ? "成功" : "失败") << std::endl;

    // 演示同态乘法
    std::cout << "\n=== ElGamal同态乘法演示 ===" << std::endl;

    // 加密几个消息
    int m1 = generate_random_message(), m2 = generate_random_message(), m3 = generate_random_message();
    std::cout << "加密消息 m1 = " << m1 << std::endl;
    std::cout << "加密消息 m2 = " << m2 << std::endl;
    std::cout << "加密消息 m3 = " << m3 << std::endl;

    ElGamalCiphertext c1 = elgamal.encrypt(m1);
    ElGamalCiphertext c2 = elgamal.encrypt(m2);
    ElGamalCiphertext c3 = elgamal.encrypt(m3);

    std::cout << "密文 c1 = " << c1.to_string() << std::endl;
    std::cout << "密文 c2 = " << c2.to_string() << std::endl;
    std::cout << "密文 c3 = " << c3.to_string() << std::endl;

    // 执行同态乘法
    ElGamalCiphertext result = c1 * c2;
    std::cout << "同态乘法结果 c1*c2 = " << result.to_string() << std::endl;

    // 解密结果
    int decrypted_result = elgamal.decrypt(result);
    std::cout << "解密结果 = " << decrypted_result << std::endl;
    std::cout << "明文乘积 m1*m2 = " << (m1 * m2) << std::endl;
    std::cout << "验证结果 " << (decrypted_result == m1 * m2 ? "正确" : "错误") << std::endl;

    // 验证同态乘法性质
    ElGamalCiphertext result2 = c3 * result;
    std::cout << "同态乘法结果 c3*(c1*c2) = " << result2.to_string() << std::endl;

    int decrypted_result2 = elgamal.decrypt(result2);
    std::cout << "解密结果 = " << decrypted_result2 << std::endl;
    std::cout << "明文乘积 m3*(m1*m2) = " << (m3 * (m1 * m2)) << std::endl;
    std::cout << "验证结果 " << (decrypted_result2 == m3 * (m1 * m2) ? "正确" : "错误") << std::endl;

    return 0;
}