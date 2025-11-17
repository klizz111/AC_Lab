#include "schnorr_signature.h"
#include <iostream>
#include <cstring>
#include <string>
#include <stdexcept>

EC_POINT* reconstructPoint(const EC_GROUP* group, const BIGNUM* x, BN_CTX* ctx) {
    if (!group || !x || !ctx) {
        throw std::invalid_argument("Invalid input parameters");
    }

    BIGNUM *a = BN_new(), *b = BN_new(), *p = BN_new();
    BIGNUM *rhs = BN_new(), *y = BN_new();
    EC_POINT* point = nullptr;

    try {
        // Get param a, b, p
        if (!EC_GROUP_get_curve(group, p, a, b, ctx)) {
            throw std::runtime_error("Failed to get curve parameters");
        }

        // calc x³ + ax + b (mod p)
        BIGNUM *x3 = BN_new(), *ax = BN_new();
        BN_mod_sqr(x3, x, p, ctx);               // x²
        BN_mod_mul(x3, x3, x, p, ctx);          // x³
        BN_mod_mul(ax, a, x, p, ctx);           // ax
        BN_mod_add(rhs, x3, ax, p, ctx);        // x³ + ax
        BN_mod_add(rhs, rhs, b, p, ctx);        // x³ + ax + b

        // y² = x³ + ax + b (mod p)
        if (!BN_mod_sqrt(y, rhs, p, ctx)) {
            throw std::runtime_error("Failed to compute square root (no solution)");
        }

        // recover (x, y)
        point = EC_POINT_new(group);
        if (!EC_POINT_set_affine_coordinates(group, point, x, y, ctx)) {
            throw std::runtime_error("Failed to set point coordinates");
        }

        if (!EC_POINT_is_on_curve(group, point, ctx)) {
            throw std::runtime_error("Reconstructed point is not on the curve");
        }

        // free
        BN_free(a);
        BN_free(b);
        BN_free(p);
        BN_free(rhs);
        BN_free(x3);
        BN_free(ax);
        BN_free(y);

        return point;
    } catch (...) {
        BN_free(a);
        BN_free(b);
        BN_free(p);
        BN_free(rhs);
        BN_free(y);
        if (point) EC_POINT_free(point);
        throw;
    }
}

SchnorrSignature::SchnorrSignature() : m_group(nullptr), m_order(nullptr), 
                                       m_generator(nullptr), m_ctx(nullptr) {
    // 初始化secp256k1曲线的OpenSSL参数
    m_group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!m_group) {
        throw std::runtime_error("创建椭圆曲线群失败");
    }
    
    // 创建BIGNUM运算的上下文
    m_ctx = BN_CTX_new();
    if (!m_ctx) {
        EC_GROUP_free(m_group);
        throw std::runtime_error("创建BN_CTX失败");
    }
    
    // 获取曲线的阶（order）
    m_order = BN_new();
    if (!m_order || !EC_GROUP_get_order(m_group, m_order, m_ctx)) {
        BN_free(m_order);
        BN_CTX_free(m_ctx);
        EC_GROUP_free(m_group);
        throw std::runtime_error("获取曲线阶失败");
    }
    
    // 获取生成元点
    m_generator = EC_POINT_new(m_group);
    if (!m_generator || !EC_GROUP_get0_generator(m_group)) {
        EC_POINT_free(m_generator);
        BN_free(m_order);
        BN_CTX_free(m_ctx);
        EC_GROUP_free(m_group);
        throw std::runtime_error("获取生成元点失败");
    }
    
    // 复制生成元点
    if (!EC_POINT_copy(m_generator, EC_GROUP_get0_generator(m_group))) {
        EC_POINT_free(m_generator);
        BN_free(m_order);
        BN_CTX_free(m_ctx);
        EC_GROUP_free(m_group);
        throw std::runtime_error("复制生成元点失败");
    }
}

SchnorrSignature::~SchnorrSignature() {
    EC_POINT_free(m_generator);
    BN_free(m_order);
    BN_CTX_free(m_ctx);
    EC_GROUP_free(m_group);
}

bool SchnorrSignature::generateKeyPair(BIGNUM*& private_key, EC_POINT*& public_key) {
    /*
        TODO: 生成 Schnorr 密钥对。核心思路：随机挑选一个属于群阶范围的私钥，
        然后使用生成元 G 与私钥做标量乘得到公钥点。注意：
        - BN_rand_range 可能返回 0，需要重新取值或手动改成 1。
        - 失败路径要正确释放 BN/EC_POINT，并把指针置空。
        - 成功时返回 true，并把 private_key/public_key 交给调用者负责释放。
    */
    private_key = BN_new();
    public_key = EC_POINT_new(m_group);

    try {
        // Gen private key
        BN_rand_range(private_key, m_order);
        if (BN_is_zero(private_key)) {
            BN_one(private_key);
        }

        // Calc public key
        if (!EC_POINT_mul(m_group, public_key, private_key, nullptr, nullptr, m_ctx)) {
            throw std::runtime_error("Gen Public Key Failed");
        }

        BN_CTX_free(m_ctx);

        return true;
    } catch (...) {
        BN_free(private_key);
        EC_POINT_free(public_key);
        BN_CTX_free(m_ctx);
        private_key = nullptr;
        public_key = nullptr;
        return false;
    }
}

bool SchnorrSignature::sign(const std::string& message, const BIGNUM* private_key, 
                           BIGNUM*& r, BIGNUM*& s) {
    /*
        TODO: 实现 Schnorr 签名。流程概括：
        - 生成随机 nonce k（同样要确保不为 0），计算 R = k*G 并提取其 x 坐标作为 r。
        - 用 r、由私钥推导出来的公钥 P 以及消息拼接后哈希，得到挑战 e。
        - 计算 s = (k - e * private_key) mod order，保持结果为正。
        - r、s 由函数内部创建后返回。
        注意事项：所有 BN / EC_POINT / 动态缓冲区都要在失败时释放；sha256 输入
        的拼接顺序必须与 verify 中一致；返回 true 之前别忘了把 r、s 指针设为生成的值。
    */
    try
    {    
        m_ctx = BN_CTX_new();

        auto k = BN_new();
        BN_rand_range(k, m_order);
        if (BN_is_zero(k)) {
            BN_one(k);   
        }
        auto R = EC_POINT_new(m_group);
        EC_POINT_mul(m_group, R, k, m_generator, nullptr, m_ctx); // R = kG

        // set r = R.x
        r = BN_new();
        EC_POINT_get_affine_coordinates(m_group, R, r, nullptr, m_ctx);

        auto e = BN_new();
        auto P = EC_POINT_new(m_group);
        EC_POINT_mul(m_group, P, private_key, nullptr, nullptr, m_ctx);

        e = hashChallenge(R, P, message);

        s = BN_new();
        // s = (k - e * private_key) mod order
        auto e_priv = BN_new();
        BN_mod_mul(e_priv, e, private_key, m_order, m_ctx);
        BN_mod_sub(s, k, e_priv, m_order, m_ctx);

        // free
        BN_free(k);
        EC_POINT_free(R);
        BN_free(e);
        EC_POINT_free(P);
        BN_free(e_priv);

        return true;
    } catch (...)
    {
        std::cout << __LINE__ << " Sign Failed" << std::endl;
        r = nullptr;
        s = nullptr;
        BN_CTX_free(m_ctx);
        return false;
    }
}

bool SchnorrSignature::verify(const std::string& message, const BIGNUM* r, const BIGNUM* s, 
                             const EC_POINT* public_key) {
    /*
        TODO: 实现 Schnorr 验证。
        核心思路：检查 r/s 范围后，按照与 sign 完全相同的方式构造挑战 e，
        再计算 sG 与 eP，求和得到 R'，看其 x 坐标是否等于 r。
        注意 e 的哈希输入顺序和签名阶段必须一致，否则验证永远失败；
        中途申请的点与大数都要及时释放，避免内存泄漏。
    */

    try {
        // check range
        if (BN_is_negative(r) || BN_is_negative(s) ||
            BN_cmp(r, m_order) >= 0 || BN_cmp(s, m_order) >= 0) {
            std::cout << "r or s out of range" << std::endl;
            return false;
        }
        // recover R from r
        auto R = EC_POINT_new(m_group);
        R = reconstructPoint(m_group, r, m_ctx);

        // calc e
        auto e = BN_new();
        e = hashChallenge(R, public_key, message);
        // calc sG + eP
        auto sG = EC_POINT_new(m_group);
        EC_POINT_mul(m_group, sG, s, nullptr, nullptr, m_ctx);

        auto eP = EC_POINT_new(m_group);
        EC_POINT_mul(m_group, eP, nullptr, public_key, e, m_ctx);

        auto R_dot = EC_POINT_new(m_group);
        EC_POINT_add(m_group, R_dot, sG, eP, m_ctx);

        auto x_R_dot = BN_new();
        EC_POINT_get_affine_coordinates(m_group, R_dot, x_R_dot, nullptr, m_ctx);

        if (BN_cmp(r, x_R_dot) == 0) {
            // free
            BN_free(x_R_dot);
            EC_POINT_free(R);
            EC_POINT_free(sG);
            EC_POINT_free(eP);
            EC_POINT_free(R_dot);
            BN_free(e);

            return true;
        } else {
            return false;
        }

    } catch (...) {
        (void)r;
        (void)s;
        return false;
    }
}

BIGNUM* SchnorrSignature::sha256AsBn(const unsigned char* data, size_t data_len) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data, data_len, hash);
    
    // 将哈希转换为BIGNUM
    BIGNUM* result = BN_bin2bn(hash, SHA256_DIGEST_LENGTH, nullptr);
    return result;
}

BIGNUM* SchnorrSignature::hashChallenge(const EC_POINT* R, const EC_POINT* P, 
                                       const std::string& message) {
    // 将R和P序列化为字节
    size_t r_buf_len = EC_POINT_point2oct(m_group, R, POINT_CONVERSION_COMPRESSED, nullptr, 0, m_ctx);
    size_t p_buf_len = EC_POINT_point2oct(m_group, P, POINT_CONVERSION_COMPRESSED, nullptr, 0, m_ctx);
    
    if (r_buf_len == 0 || p_buf_len == 0) {
        return nullptr;
    }
    
    unsigned char* r_buf = new unsigned char[r_buf_len];
    unsigned char* p_buf = new unsigned char[p_buf_len];
    
    if (!r_buf || !p_buf) {
        delete[] r_buf;
        delete[] p_buf;
        return nullptr;
    }
    
    if (EC_POINT_point2oct(m_group, R, POINT_CONVERSION_COMPRESSED, r_buf, r_buf_len, m_ctx) != r_buf_len ||
        EC_POINT_point2oct(m_group, P, POINT_CONVERSION_COMPRESSED, p_buf, p_buf_len, m_ctx) != p_buf_len) {
        delete[] r_buf;
        delete[] p_buf;
        return nullptr;
    }
    
    // 连接 R || P || message
    size_t total_len = r_buf_len + p_buf_len + message.length();
    unsigned char* concat = new unsigned char[total_len];
    
    if (!concat) {
        delete[] r_buf;
        delete[] p_buf;
        return nullptr;
    }
    
    memcpy(concat, r_buf, r_buf_len);
    memcpy(concat + r_buf_len, p_buf, p_buf_len);
    memcpy(concat + r_buf_len + p_buf_len, message.c_str(), message.length());
    
    // 哈希连接的数据
    BIGNUM* challenge = sha256AsBn(concat, total_len);
    
    delete[] r_buf;
    delete[] p_buf;
    delete[] concat;
    
    return challenge;
}

std::string SchnorrSignature::bnToHex(const BIGNUM* bn) {
    if (!bn) return "";
    char* hex = BN_bn2hex(bn);
    if (!hex) return "";
    std::string result(hex);
    OPENSSL_free(hex);
    return result;
}

BIGNUM* SchnorrSignature::hexToBn(const std::string& hex) {
    BIGNUM* bn = nullptr;
    BN_hex2bn(&bn, hex.c_str());
    return bn;
}
