#include <iostream>
#include <vector>
#include <utility>

#include <openssl/bn.h>      // 大数
#include <openssl/ec.h>      // 椭圆曲线
#include <openssl/obj_mac.h> // NID_secp256k1
#include <openssl/rand.h>    // 随机数

#include "utils.hpp"

using namespace std;

typedef pair<int, BIGNUM *> SHARE_BASE; // first: int(x), second: BIGNUM*(y)
typedef vector<SHARE_BASE> SHARES;
typedef vector<EC_POINT *> COMMITMENTS;
typedef pair<SHARES, COMMITMENTS> FELDMAN_SHARES_AND_COMMITMENTS;
/// @brief 产生份额和承诺
/// @param group
/// @param generator
/// @param prime
/// @param coeffs
/// @param n 份额数量
/// @return pair<pair<int, BIGNUM*>, vector<EC_POINT*>>
FELDMAN_SHARES_AND_COMMITMENTS generate_feldman_shares_and_commitments(
    EC_GROUP *group,
    EC_POINT *generator,
    BIGNUM *prime,
    const vector<BIGNUM *> &coeffs,
    int n)
{
    FELDMAN_SHARES_AND_COMMITMENTS result;
    SHARES &shares = result.first;
    COMMITMENTS &commitments = result.second;

    // 1. 生成份额
    for (int i = 1; i <= n; i++)
    {
        BIGNUM *x = BN_new();
        BN_set_word(x, i);                       // x = i
        BIGNUM *y = eval_poly(coeffs, x, prime); // f(i) mod prime
        shares.push_back({i, y});                // 添加份额 (i, f(i))
        BN_free(x);
    }

    // 2. 生成承诺
    for (size_t j = 0; j < coeffs.size(); j++)
    {
        EC_POINT *Cj = EC_POINT_new(group);
        EC_POINT_mul(group, Cj, nullptr, generator, coeffs[j], nullptr); // Cj = aj * G
        commitments.push_back(Cj);
    }

    return result;
}

/// @brief 
/// @param x 份额编号
/// @param y 私有秘密
/// @param commitments 承诺 
/// @param group
/// @param generator 
/// @param prime 
/// @return 
bool verify_share(
    int x,
    BIGNUM *y,
    const COMMITMENTS &commitments,
    EC_GROUP *group,
    EC_POINT *generator,
    BIGNUM *prime)
{
    // cout << "Call " << __FUNCTION__ << "\n";
    // 1. left = y * G
    EC_POINT *left = EC_POINT_new(group);
    EC_POINT_mul(group, left, nullptr, generator, y, nullptr); 
    // cout << "Call " << __LINE__ << "\n";

    // 2. right = sum( Cj * x^j )
    EC_POINT *right = EC_POINT_new(group);
    EC_POINT_set_to_infinity(group, right); // 初始化零元
    // cout << "Call " << __LINE__ << "\n";

    BIGNUM *x_bn = BN_new();
    BN_set_word(x_bn, x); // x 转换为 BIGNUM

    BIGNUM *x_pow = BN_new();
    BN_one(x_pow); // x^0 = 1

    BN_CTX *ctx = BN_CTX_new();

    for (size_t j = 0; j < commitments.size(); j++)
    {
        // cout << "Call " << __LINE__ << "\n";
        EC_POINT *term = EC_POINT_new(group);
        EC_POINT_mul(group, term, nullptr, commitments[j], x_pow, ctx); // term = Cj * x^j
        EC_POINT_add(group, right, right, term, ctx);                   // right += term

        // 更新 x_pow = x^(j+1)
        BN_mod_mul(x_pow, x_pow, x_bn, prime, ctx);

        EC_POINT_free(term);
    }

    // 3. left == right
    bool valid = (EC_POINT_cmp(group, left, right, ctx) == 0);

    // free
    EC_POINT_free(left);
    EC_POINT_free(right);
    BN_free(x_bn);
    BN_free(x_pow);
    BN_CTX_free(ctx);

    return valid;
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    { // 检查参数数量
        std::cerr << "用法:\n"
                  << "  feldman share <secret_hex|'rand'> <t> <n>\n"                                // 生成份额和承诺模式
                  << "  feldman verify <x> <y_hex> <commitment1> <commitment2> ... <coeff_count>\n" // 验证份额模式
                  << "  feldman reconstruct <share1> <share2> ...\n";                               // 重构秘密模式
        return 1;
    }

    // 使用椭圆曲线secp256k1
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!group)
    {
        std::cerr << "无法创建椭圆曲线群\n";
        return 1;
    }

    const EC_POINT *generator_const = EC_GROUP_get0_generator(group);
    if (!generator_const)
    {
        std::cerr << "无法获取生成元\n";
        EC_GROUP_free(group);
        return 1;
    }
    EC_POINT *generator = EC_POINT_new(group);
    if (!EC_POINT_copy(generator, generator_const))
    {
        std::cerr << "无法复制生成元\n";
        EC_GROUP_free(group);
        return 1;
    }

    // 使用椭圆曲线secp256k1的阶数（作为我们的质数域）
    BIGNUM *prime = BN_new();
    EC_GROUP_get_order(group, prime, nullptr);

    std::string mode = argv[1]; // 获取操作模式

    if (mode == "share")
    { // 生成份额和承诺模式
        if (argc < 5)
        {
            std::cerr << "share模式参数错误\n";
            return 1;
        }
        int t = std::stoi(argv[3]);                                            // 阈值：需要至少t个份额才能重构秘密
        int n = std::stoi(argv[4]);                                            // 总共生成n个份额
        auto [secret, coeffs] = generate_secret_and_coeffs(prime, argv[2], t); // 生成秘密和多项式系数
        std::cout << "原始秘密: " << bn_to_hex(secret) << "\n";                // 输出原始秘密值（十六进制）

        auto [shares, commitments] = generate_feldman_shares_and_commitments(group, generator, prime, coeffs, n);

        std::cout << "份额:\n";
        for (auto &s : shares)
        {                                                               // 输出每个份额
            std::cout << s.first << ":" << bn_to_hex(s.second) << "\n"; // 格式：序号:y值（十六进制）
        }

        std::cout << "承诺:\n";
        for (size_t i = 0; i < commitments.size(); i++)
        {
            char *commitment_str = EC_POINT_point2hex(group, commitments[i], POINT_CONVERSION_COMPRESSED, nullptr);
            std::cout << "C" << i << ":" << std::string(commitment_str) << "\n";
            OPENSSL_free(commitment_str);
        }

        BN_free(secret); // 释放秘密值
        for (auto c : coeffs)
            BN_free(c); // 释放多项式系数
        for (auto c : commitments)
            EC_POINT_free(c); // 释放承诺
    }
    else if (mode == "verify")
    { // 验证份额模式
        if (argc < 5)
        {
            std::cerr << "verify模式参数错误\n";
            return 1;
        }

        int x = std::stoi(argv[2]);     // x坐标
        BIGNUM *y = hex_to_bn(argv[3]); // y值（十六进制）

        // Parse commitments
        int coeff_count = std::stoi(argv[argc - 1]); // 最后一个参数是系数数量
        std::vector<EC_POINT *> commitments(coeff_count);
        for (int i = 0; i < coeff_count; i++)
        {
            EC_POINT *commitment = EC_POINT_new(group);
            BN_CTX *ctx = BN_CTX_new();
            if (!EC_POINT_hex2point(group, argv[4 + i], commitment, ctx))
            {
                std::cerr << "无法解析承诺 " << i << "\n";
                EC_POINT_free(commitment);
                BN_CTX_free(ctx);
                BN_free(y);
                EC_GROUP_free(group);
                BN_free(prime);
                return 1;
            }
            BN_CTX_free(ctx);
            commitments[i] = commitment;
        }

        bool valid = verify_share(x, y, commitments, group, generator, prime);
        std::cout << "份额验证: " << (valid ? "通过" : "失败") << "\n";

        BN_free(y);
        for (auto c : commitments)
            EC_POINT_free(c);
    }
    else if (mode == "reconstruct")
    { // 重构秘密模式
        if (argc < 3)
        {
            std::cerr << "reconstruct模式参数错误\n";
            return 1;
        }
        std::vector<std::pair<int, BIGNUM *>> shares; // 存储解析的份额
        for (int i = 2; i < argc; i++)
        {                           // 解析每个份额参数
            std::string s(argv[i]); // 获取份额参数，格式为 "x:yhex"
            auto pos = s.find(':'); // 查找分隔符 ':'
            if (pos == std::string::npos)
            {
                std::cerr << "份额格式错误\n";
                return 1;
            } // 检查格式
            int xi = std::stoi(s.substr(0, pos));      // 解析x坐标
            BIGNUM *yi = hex_to_bn(s.substr(pos + 1)); // 解析y坐标（十六进制）
            shares.push_back({xi, yi});                // 将份额添加到向量中
        }
        BIGNUM *secret = reconstruct_secret(prime, shares);       // 使用拉格朗日插值重构秘密
        std::cout << "重构的秘密: " << bn_to_hex(secret) << "\n"; // 输出重构的秘密值（十六进制）
        BN_free(secret);                                          // 释放重构的秘密值
        for (auto &s : shares)
            BN_free(s.second); // 释放份额的y值
    }
    else
    {
        std::cerr << "未知模式\n";
        return 1;
    } // 未知模式，输出错误信息

    EC_GROUP_free(group); // 释放椭圆曲线群
    BN_free(prime);       // 释放素数

    return 0;
}