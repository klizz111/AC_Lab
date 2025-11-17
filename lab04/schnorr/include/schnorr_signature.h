#ifndef SCHNORR_SIGNATURE_H
#define SCHNORR_SIGNATURE_H

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <string>
#include <vector>
#include <memory>

/**
 * @brief 使用OpenSSL实现的Schnorr签名方案
 * 
 * 本实现使用椭圆曲线密码学，采用secp256k1曲线和SHA-256哈希函数。
 */
class SchnorrSignature {
public:
    /**
     * @brief 构造函数，初始化Schnorr签名方案
     * 使用secp256k1曲线进行密码学运算
     */
    SchnorrSignature();
    
    /**
     * @brief 析构函数，清理OpenSSL资源
     */
    ~SchnorrSignature();
    
    /**
     * @brief 生成新的密钥对（私钥和公钥）
     * @param private_key 输出参数，用于存储私钥
     * @param public_key 输出参数，用于存储公钥（曲线上的点）
     * @return 成功返回true，否则返回false
     */
    bool generateKeyPair(BIGNUM*& private_key, EC_POINT*& public_key);
    
    /**
     * @brief 使用私钥对消息进行签名
     * @param message 要签名的消息
     * @param private_key 用于签名的私钥
     * @param r 输出参数，签名的r分量
     * @param s 输出参数，签名的s分量
     * @return 成功返回true，否则返回false
     */
    bool sign(const std::string& message, const BIGNUM* private_key, 
              BIGNUM*& r, BIGNUM*& s);
    
    /**
     * @brief 验证消息的签名和公钥
     * @param message 被签名的消息
     * @param r 签名的r分量
     * @param s 签名的s分量
     * @param public_key 用于验证的公钥
     * @return 签名有效返回true，否则返回false
     */
    bool verify(const std::string& message, const BIGNUM* r, const BIGNUM* s, 
                const EC_POINT* public_key);
    
    /**
     * @brief 将BIGNUM转换为十六进制字符串表示
     * @param bn 要转换的BIGNUM
     * @return 十六进制字符串表示
     */
    static std::string bnToHex(const BIGNUM* bn);
    
    /**
     * @brief 将十六进制字符串转换为BIGNUM
     * @param hex 十六进制字符串
     * @return 从十六进制字符串创建的BIGNUM*
     */
    static BIGNUM* hexToBn(const std::string& hex);
    
private:
    EC_GROUP* m_group;        // 椭圆曲线群参数
    BIGNUM* m_order;          // 曲线的阶
    EC_POINT* m_generator;    // 曲线的生成元点
    BN_CTX* m_ctx;            // BIGNUM运算的上下文
    
    /**
     * @brief 获取输入数据的SHA-256哈希
     * @param data 要哈希的输入数据
     * @param data_len 输入数据的长度
     * @return SHA-256哈希作为BIGNUM
     */
    BIGNUM* sha256AsBn(const unsigned char* data, size_t data_len);
    
    /**
     * @brief Schnorr签名挑战的哈希函数
     * 生成 H(R || P || m)，其中R是随机点，P是公钥，m是消息
     */
    BIGNUM* hashChallenge(const EC_POINT* R, const EC_POINT* P, 
                         const std::string& message);
};

#endif // SCHNORR_SIGNATURE_H