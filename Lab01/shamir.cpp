#include <openssl/bn.h>   // OpenSSL大整数运算库
#include <openssl/rand.h> // OpenSSL随机数生成库
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <stdexcept>

// 将BIGNUM（大整数）转换为十六进制字符串
std::string bn_to_hex(const BIGNUM *n)
{
    char *s = BN_bn2hex(n); // 使用OpenSSL函数将大整数转换为十六进制字符串
    std::string r(s);
    OPENSSL_free(s); // 释放OpenSSL分配的内存
    return r;
}

// 将十六进制字符串转换为BIGNUM（大整数）
BIGNUM *hex_to_bn(const std::string &hex)
{
    BIGNUM *n = nullptr;
    BN_hex2bn(&n, hex.c_str()); // 使用OpenSSL函数将十六进制字符串转换为大整数
    return n;
}

// 生成模mod的随机数
BIGNUM *rand_mod(const BIGNUM *mod)
{
    int nbytes = (BN_num_bits(mod) + 7) / 8;           // 计算模数的字节数，向上取整
    std::vector<unsigned char> buf(nbytes);            // 创建随机字节缓冲区
    if (RAND_bytes(buf.data(), nbytes) != 1)           // 使用OpenSSL的随机数生成器
        throw std::runtime_error("RAND_bytes failed"); // 如果随机数生成失败，抛出异常
    BIGNUM *bn = BN_bin2bn(buf.data(), nbytes, nullptr);                 // 将字节数组转换为大整数
    BN_CTX *ctx = BN_CTX_new();                        // 创建BIGNUM计算上下文
    BIGNUM *res = BN_new();                            // 创建结果大整数
    BN_mod(res, bn, mod, ctx);               // 计算bn mod mod，即对模数取模
    BN_free(bn);                                       // 释放临时大整数
    BN_CTX_free(ctx);                                  // 释放计算上下文
    return res;                                        // 返回模mod的随机数
}

// 计算模逆元：找到a关于mod的乘法逆元
BIGNUM *modinv(const BIGNUM *a, const BIGNUM *mod)
{
    BN_CTX *ctx = BN_CTX_new();                                   // 创建计算上下文
    BIGNUM *inv = BN_mod_inverse(nullptr, a, mod, ctx); // 使用OpenSSL函数计算模逆元
    BN_CTX_free(ctx);                                             // 释放计算上下文
    if (!inv)
        throw std::runtime_error("没有逆元"); // 如果不存在逆元，抛出异常
    return inv;                               // 返回模逆元
}

// TODO: 学生需要实现此函数 - 在x点计算多项式的值
BIGNUM *eval_poly(const std::vector<BIGNUM *> &coeffs, const BIGNUM *x, const BIGNUM *mod)
{
    // 提示：
    // 计算 f(x) = coeffs[0] + coeffs[1]*x + coeffs[2]*x^2 + ...
    // 你的代码 在这里

    // std::cout << "Call " << __FUNCTION__ << "\n";
    auto res = BN_new(); // init
    BN_zero(res);

    auto len = coeffs.size();
    auto CTX = BN_CTX_new();

    // 霍纳法则
    for (int i = len - 1; i >= 0; --i) { // 高位到低位
        BN_mod_mul(res, res, x, mod, CTX); // res * x
        BN_mod_add(res, res, coeffs[i], mod, CTX); // res + coeffs[i]
    }

    BN_CTX_free(CTX);
    return res;
    // return nullptr; // 临时返回，学生需要替换
}

// TODO: 学生需要实现此函数 - 使用拉格朗日插值法重构秘密
BIGNUM *lagrange_reconstruct_at_zero(const std::vector<std::pair<BIGNUM *, BIGNUM *>> &points, const BIGNUM *mod)
{
    // 提示：
    // 1. 对于每个点i，计算拉格朗日基函数li(0) = product_{j!=i}(0-xj)/(xi-xj)
    // 2. 重构值 = sum(yi * li(0))
    // 3. 所有运算都要在模mod下进行
    // 你的代码在这里
    auto len = points.size();

    BIGNUM *result = BN_new();
    BN_zero(result);
    BN_CTX *ctx = BN_CTX_new();

    auto ZERO = BN_new();
    BN_zero(ZERO);

    for (int i = 0; i < len; ++i) {
        BIGNUM *li = BN_new();
        BN_one(li); // 初始化为1

        // x - x_j / x_i - x_j
        // len 个点计算 len - 1 个分式
        for (int j = 0; j < len; ++j) { // len
            if (j == i) continue; // len - 1

            // -x_j mod mod
            BIGNUM *_xj = BN_new();
            BN_mod_sub(_xj, ZERO, points[j].first, mod, ctx);

            // xi - xj mod mod
            BIGNUM *xi_m_xj = BN_new();
            BN_mod_sub(xi_m_xj, points[i].first, points[j].first, mod, ctx);

            //  1 / (xi - xj) mod mod
            BIGNUM *_xi_m_xj = modinv(xi_m_xj, mod);

            // -xj / xi-xj mod mod
            BIGNUM *final = BN_new();
            BN_mod_mul(final, _xj, _xi_m_xj, mod, ctx);

            // li *= final mod mod
            BN_mod_mul(li, li, final, mod, ctx);

            BN_free(_xj);
            BN_free(xi_m_xj);
            BN_free(_xi_m_xj);
            BN_free(final);
        }

        // yi * li mod mod
        BIGNUM *contrib = BN_new();
        BN_mod_mul(contrib, points[i].second, li, mod, ctx);

        // result += contrib mod mod
        BN_mod_add(result, result, contrib, mod, ctx);

        BN_free(li);
        BN_free(contrib);
    }
    
    return result;
    return nullptr; // 临时返回，学生需要替换
}

// 确定秘密和多项式系数
// 根据输入参数决定是随机生成秘密还是从十六进制字符串解析秘密，然后生成多项式的系数
std::pair<BIGNUM *, std::vector<BIGNUM *>> generate_secret_and_coeffs(BIGNUM *prime, const std::string &secret_arg, int t)
{
    // 如果参数是"rand"，则随机生成秘密；否则从十六进制字符串解析秘密
    BN_CTX *ctx = BN_CTX_new(); // 创建BIGNUM计算上下文
    BIGNUM *temp_secret = (secret_arg == "rand") ? rand_mod(prime) : hex_to_bn(secret_arg);
    BIGNUM *secret = BN_new();
    BN_mod(secret, temp_secret, prime, ctx);
    BN_free(temp_secret); // 释放临时秘密
    std::vector<BIGNUM *> coeffs;     // 存储多项式系数的向量
    coeffs.push_back(BN_dup(secret)); // 常数项是秘密值
    for (int i = 1; i < t; i++)
        coeffs.push_back(rand_mod(prime)); // 生成t-1个随机系数
    return {secret, coeffs};               // 返回秘密和系数向量的配对
}

// TODO: 学生需要实现此函数 - 根据系数生成份额
std::vector<std::pair<int, BIGNUM *>> generate_shares(BIGNUM *prime, const std::vector<BIGNUM *> &coeffs, int n)
{
    // 提示：
    // 1. 创建存储份额的向量，每个份额是(序号, y值)的配对
    // 2. 对于每个i从1到n，计算x=i, y=f(i)
    // 3. 使用eval_poly计算多项式值
    // 你的代码在这里
    // std::cout << "Call " << __FUNCTION__ << "\n";
    std::vector<std::pair<int, BIGNUM *>> shares;

    auto len = coeffs.size();
    try {

        for (int i = 1; i <= n; ++i) {
            auto x = BN_new();
            BN_set_word(x, i);

            auto y = eval_poly(coeffs, x, prime);
            shares.push_back({i, y});

            BN_free(x); 
        }
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << "\n";
    }

    return shares;

    return {}; // 临时返回，学生需要替换
}

// 重构秘密
// 使用拉格朗日插值法从给定的份额重构原始秘密
BIGNUM *reconstruct_secret(BIGNUM *prime, const std::vector<std::pair<int, BIGNUM *>> &shares)
{
    // 将整数x坐标转换为BIGNUM格式，以便用于拉格朗日插值
    std::vector<std::pair<BIGNUM *, BIGNUM *>> pts; // 存储点(x,y)的向量
    for (auto &p : shares)
    { // 遍历每个份额
        BIGNUM *xi = BN_new();
        BN_set_word(xi, p.first);              // 将整数x坐标转换为BIGNUM
        pts.push_back({xi, BN_dup(p.second)}); // 将点(x,y)添加到向量中
    }
    BIGNUM *secret = lagrange_reconstruct_at_zero(pts, prime); // 使用拉格朗日插值重构秘密
    // 释放临时点
    for (auto &pt : pts)
    {
        BN_free(pt.first);
        BN_free(pt.second);
    }
    return secret; // 返回重构的秘密
}

void print_usage()
{
    std::cerr << "用法:\n"
              << "  shamir share <secret_hex|'rand'> <t> <n>\n" // 生成份额模式
              << "  shamir reconstruct <share1> <share2> ...\n"; // 重构秘密模式
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    { // 检查参数数量
        print_usage();
        return 1;
    }

    // 使用椭圆曲线secp256k1的素数域
    const char *P_HEX = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
    BIGNUM *prime = hex_to_bn(P_HEX); // 将十六进制素数转换为BIGNUM

    std::string mode = argv[1]; // 获取操作模式
    if (mode == "share")
    { // 生成份额模式
        if (argc < 5)
        {
            std::cerr << "share模式参数错误\n";
            return 1;
        }
        int t = std::stoi(argv[3]);                                            // 阈值：需要至少t个份额才能重构秘密
        int n = std::stoi(argv[4]);                                            // 总共生成n个份额
        auto [secret, coeffs] = generate_secret_and_coeffs(prime, argv[2], t); // 生成秘密和多项式系数
        std::cout << bn_to_hex(secret) << "\n";                                // 输出原始秘密值（十六进制）
        auto shares = generate_shares(prime, coeffs, n);                       // 生成n个份额
        for (auto &s : shares)
        {                                                               // 输出每个份额
            std::cout << s.first << ":" << bn_to_hex(s.second) << "\n"; // 格式：序号:y值（十六进制）
            BN_free(s.second);                                          // 释放份额的y值
        }
        BN_free(secret); // 释放秘密值
        for (auto c : coeffs)
            BN_free(c); // 释放多项式系数
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
        BIGNUM *secret = reconstruct_secret(prime, shares); // 使用拉格朗日插值重构秘密
        std::cout << bn_to_hex(secret) << "\n";             // 输出重构的秘密值（十六进制）
        BN_free(secret);                                    // 释放重构的秘密值
        for (auto &s : shares)
            BN_free(s.second); // 释放份额的y值
    }
    else
    {
        std::cerr << "未知模式\n";
        return 1;
    } // 未知模式，输出错误信息

    BN_free(prime); // 释放素数
    return 0;
}
