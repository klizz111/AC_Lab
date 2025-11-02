#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <iostream>
#include <typeinfo>
#include <sstream>
#include <iomanip>
#include <vector>
#include <stdexcept>

// TODO: 学生需要实现此函数 - 将BIGNUM（大整数）转换为十六进制字符串
std::string bn_to_hex(const BIGNUM *n)
{
    // 提示：使用OpenSSL的BN_bn2hex函数将BIGNUM类型大整数转换为十六进制字符串(char*)，然后转换为std::string
    // 记住使用OPENSSL_free释放BN_bn2hex返回的内存
    // 你的代码在这里
    auto res = BN_bn2hex(n);
    std::string hex_str(res);
    OPENSSL_free(res);
    return hex_str; // 临时返回，学生需要替换
}

// TODO: 学生需要实现此函数 - 将椭圆曲线点（EC_POINT）转换为压缩格式的十六进制字符串
std::string point_to_hex(const EC_GROUP *group, const EC_POINT *P)
{
    // 创建BIGNUM上下文，用于椭圆曲线运算
    BN_CTX *ctx = BN_CTX_new();
    // 计算椭圆曲线点的压缩格式字节长度
    size_t len = EC_POINT_point2oct(group, P, POINT_CONVERSION_COMPRESSED, nullptr, 0, ctx);
    // 创建缓冲区存储压缩后的点数据
    std::vector<unsigned char> buf(len);
    // 将椭圆曲线点转换为压缩格式的字节数组
    EC_POINT_point2oct(group, P, POINT_CONVERSION_COMPRESSED, buf.data(), buf.size(), ctx);
    BN_CTX_free(ctx); // 释放上下文

    // 将 buf 字节数组转换为十六进制字符串
    // 你的代码在这里
    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setfill('0');
    for (unsigned char byte : buf) {
            oss << std::setw(2) << (int)(byte & 0xFF);
    }
    std::string hex = oss.str();
    return hex; // 临时返回，学生需要替换
}

// 将字符串哈希为模群阶的标量值
BIGNUM *hash_to_bn_mod_order(const std::string &s, const BIGNUM *order)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0; // SHA256哈希值为32字节，后面会被置为32

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();            // 创建哈希上下文
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr); // 初始化哈希计算
    EVP_DigestUpdate(ctx, s.data(), s.size());     // 更新哈希计算
    EVP_DigestFinal_ex(ctx, digest, &dlen);        // 完成哈希计算并得到结果
    EVP_MD_CTX_free(ctx);
    BIGNUM *bn = BN_new();        // 创建新的大整数
    BN_bin2bn(digest, dlen, bn);  // 将哈希结果（字节数组）转换为大整数
    BN_CTX *bctx = BN_CTX_new();  // 创建BIGNUM计算上下文
    BIGNUM *res = BN_new();       // 创建结果大整数
    BN_mod(res, bn, order, bctx); // 计算哈希值模群阶的值
    BN_free(bn);                  // 释放中间大整数
    BN_CTX_free(bctx);            // 释放BIGNUM上下文
    return res;                   // 返回模群阶的标量值
}

// TODO: 学生需要实现此函数 - 执行Pedersen承诺操作
// 输入：椭圆曲线群、消息m、随机数r、基点G、辅助点H、计算上下文
// 输出：承诺点C = m*G + r*H
EC_POINT *pedersen_commit(const EC_GROUP *group, const BIGNUM *m, const BIGNUM *r,
                          const EC_POINT *G, const EC_POINT *H, BN_CTX *ctx)
{
    // 提示：
    // 1. 创建点可使用EC_POINT_new(group)
    // 2. 计算常数与点的乘法可使用EC_POINT_mul(group, P, m, G, ctx)
    // 3. 计算点的加法可使用EC_POINT_add(group, P, Q, R, ctx)
    // 你的代码在这里
    auto mG = EC_POINT_new(group);
    auto rH = EC_POINT_new(group);
    EC_POINT_mul(group, mG, nullptr, G, m, ctx);
    EC_POINT_mul(group, rH, nullptr, H, r, ctx);
    auto C = EC_POINT_new(group);
    EC_POINT_add(group, C, mG, rH, ctx);
    EC_POINT_free(mG);
    EC_POINT_free(rH);  

    // return nullptr; // 临时返回，学生需要替换
    return C;
}

// TODO: 学生需要实现此函数 - 执行Pedersen验证操作
// 输入：椭圆曲线群、承诺点C、消息m、随机数r、基点G、辅助点H、计算上下文
// 输出：验证结果（true表示匹配，false表示不匹配）
bool pedersen_verify(const EC_GROUP *group, const EC_POINT *C, const BIGNUM *m, const BIGNUM *r,
                     const EC_POINT *G, const EC_POINT *H, BN_CTX *ctx)
{
    // 提示：
    // 1. 重新计算承诺值 C' = m*G + r*H
    // 2. 使用EC_POINT_cmp比较原始承诺点C和重新计算的承诺点C'
    // 3. 释放分配的内存
    // 你的代码在这里
    auto *mG = EC_POINT_new(group);
    auto *rH = EC_POINT_new(group);
    EC_POINT_mul(group, mG, nullptr, G, m, ctx);  
    EC_POINT_mul(group, rH, nullptr, H, r, ctx);  
    EC_POINT *C_ = EC_POINT_new(group);
    EC_POINT_add(group, C_, mG, rH, ctx);  // C' = mG + rH
    int cmp_result = EC_POINT_cmp(group, C, C_, ctx);  
    if (cmp_result < 0) {
        std::cout << "At" << __LINE__;
        throw std::runtime_error("EC_POINT_cmp failed");
    }

    EC_POINT_free(mG);
    EC_POINT_free(rH);
    EC_POINT_free(C_);
    return cmp_result == 0;
}

struct PedersenCommitResult
{
    BIGNUM *message;
    BIGNUM *randomness;
    EC_POINT *commitment;
};

// 确定承诺消息和随机数，并执行Pedersen承诺操作
// 输入：椭圆曲线群、基点G、辅助点H、计算上下文、消息字符串（可以是"rand"表示随机生成，或十六进制字符串）
// 输出：包含消息、随机数和承诺点的结构
struct PedersenCommitResult create_pedersen_commitment(const EC_GROUP *group, const EC_POINT *G, const EC_POINT *H,
                                                       BN_CTX *ctx, const BIGNUM *order, const std::string &msg_str)
{
    struct PedersenCommitResult result;

    // 1. 根据msg_str参数决定是随机生成消息还是解析十六进制字符串
    // 2. 生成随机数r
    // 3. 调用pedersen_commit函数计算承诺值

    // 消息m
    result.message = BN_new(); // 创建存储消息的大整数
    if (msg_str == "rand")
    {                                                                 // 如果参数是"rand"，则生成随机消息
        std::vector<unsigned char> tmp((BN_num_bits(order) + 7) / 8); // 计算群阶的字节数
        RAND_bytes(tmp.data(), (int)tmp.size());                      // 生成随机字节
        BN_bin2bn(tmp.data(), (int)tmp.size(), result.message);       // 将随机字节转换为大整数
        BN_mod(result.message, result.message, order, ctx);           // 将随机大整数模群阶
    }
    else
    {                                                       // 否则将参数作为十六进制消息值
        BN_hex2bn(&result.message, msg_str.c_str());        // 将十六进制字符串转换为大整数
        BN_mod(result.message, result.message, order, ctx); // 将消息大整数模群阶
    }

    // 生成随机数r
    // 可使用RAND_bytes生成随机字节，BN_bin2bn将随机字节转换为大整数，BN_mod将随机大整数模群阶
    // 你的代码在这里
    result.randomness = BN_new(); 
    std::vector<unsigned char> tmp((BN_num_bits(order) + 7) / 8); 
    RAND_bytes(tmp.data(), (int)tmp.size());
    BN_bin2bn(tmp.data(), (int)tmp.size(), result.randomness);
    BN_mod(result.randomness, result.randomness, order, ctx);
    // 使用现有的函数pedersen_commit计算承诺值 C = m*G + r*H
    // 你的代码在这里
    result.commitment = pedersen_commit(group, result.message, result.randomness, G, H, ctx);

    return result;
}

void print_usage()
{
    std::cout << "使用说明:\n"
              << "  pedersen setup-demo        # 显示椭圆曲线参数信息\n"
              << "  pedersen commit <m_hex|'rand'>  # 创建承诺，可以指定消息的十六进制值或使用随机值\n"
              << "  pedersen verify <C_hex> <m_hex> <r_hex>  # 验证承诺\n";
}

// TODO: 学生需要实现此函数 - 初始化Pedersen承诺参数
// 包括椭圆曲线群、群阶、基点G、辅助点H等
struct PedersenParams
{
    EC_GROUP *group;
    BIGNUM *order;
    const EC_POINT *G;
    EC_POINT *H;
    BN_CTX *ctx;
};

struct PedersenParams init_pedersen_params()
{
    struct PedersenParams params;

    // 椭圆曲线设置
    int nid = NID_X9_62_prime256v1;                 // 使用prime256v1（secp256r1）椭圆曲线
    params.group = EC_GROUP_new_by_curve_name(nid); // 创建椭圆曲线群
    if (!params.group)
    {
        std::cerr << "EC_GROUP_new failed\n";
        params.order = nullptr; // 可用于后续检查
        return params;
    }
    params.ctx = BN_CTX_new();                                  // 创建BIGNUM计算上下文（辅助计算）
    params.order = BN_new();                                    // 创建存储群阶的大整数
    EC_GROUP_get_order(params.group, params.order, params.ctx); // 获取椭圆曲线群的阶

    // 生成H = hash_to_point("Pedersen H generator v1") -> scalar*G
    // 使用哈希函数生成第二个生成元H
    BIGNUM *h_scalar = hash_to_bn_mod_order("Pedersen H generator v1", params.order); // 计算H的标量
    params.H = EC_POINT_new(params.group);                                            // 创建H点
    params.G = EC_GROUP_get0_generator(params.group);                                 // 获取椭圆曲线的基点G
    // 计算H = h_scalar * G，即标量乘法运算
    EC_POINT_mul(params.group, params.H, nullptr, params.G, h_scalar, params.ctx);

    // 释放临时变量
    BN_free(h_scalar);

    return params;
}

// 释放Pedersen参数占用的内存
void free_pedersen_params(struct PedersenParams &params)
{
    BN_free(params.order);
    EC_POINT_free(params.H);
    EC_GROUP_free(params.group);
    BN_CTX_free(params.ctx);
}

/* void __attribute__((constructor)) mian(){
    using namespace std;
    struct PedersenParams params = init_pedersen_params();
    EC_GROUP *group = params.group;
    const EC_POINT *G = params.G;
    // cout << typeid(G).name() << endl;
    // cout << point_to_hex(group, G) << endl;
} */


int main(int argc, char **argv)
{
    if (argc < 2)
    {
        print_usage();
        return 1;
    } // 如果参数不足，显示使用说明并退出
    std::string cmd = argv[1]; // 获取命令参数

    // 初始化Pedersen参数
    struct PedersenParams params = init_pedersen_params();
    if (!params.group)
    {
        std::cerr << "Failed to initialize Pedersen parameters\n";
        return 1;
    }

    // 从参数结构体中提取相关变量
    EC_GROUP *group = params.group;
    BIGNUM *order = params.order;
    const EC_POINT *G = params.G;
    EC_POINT *H = params.H;
    BN_CTX *ctx = params.ctx;

    if (cmd == "setup-demo")
    { // 如果是setup-demo命令
        std::cout << "椭圆曲线: prime256v1 (secp256r1)\n";
        std::cout << "群阶 (十六进制): " << bn_to_hex(order) << "\n";        // 输出群阶的十六进制值
        std::cout << "G (压缩十六进制): " << point_to_hex(group, G) << "\n"; // 输出基点G的压缩十六进制表示
        std::cout << "H (压缩十六进制): " << point_to_hex(group, H) << "\n"; // 输出H点的压缩十六进制表示
    }
    else if (cmd == "commit" && argc == 3)
    { // 如果是commit命令且参数数量正确
        // 使用承诺函数生成随机数并计算承诺值
        struct PedersenCommitResult result = create_pedersen_commitment(group, G, H, ctx, order, std::string(argv[2]));

        // 输出承诺点C的十六进制表示，消息m的十六进制表示，随机数r的十六进制表示
        std::cout << point_to_hex(group, result.commitment) << " "
                    << bn_to_hex(result.message) << " " << bn_to_hex(result.randomness) << std::endl;

        // 释放分配的内存
        BN_free(result.message);
        BN_free(result.randomness);
        EC_POINT_free(result.commitment);
    }
    else if (cmd == "verify" && argc == 5)
    {                                                               // 如果是verify命令且参数数量正确
        std::string Chex = argv[2], mhex = argv[3], rhex = argv[4]; // 获取承诺点、消息、随机数的十六进制字符串
        // 解析承诺点C
        size_t buflen = Chex.size() / 2;        // 计算十六进制字符串对应的字节数
        std::vector<unsigned char> buf(buflen); // 创建缓冲区
        // 将十六进制字符串转换为字节数组
        for (size_t i = 0; i < buflen; i++)
        {
            unsigned int v;
            std::istringstream iss(Chex.substr(2 * i, 2)); // 读取每两个十六进制字符
            iss >> std::hex >> v;                          // 将十六进制转换为整数
            buf[i] = (unsigned char)v;                     // 存储为字节
        }
        EC_POINT *C = EC_POINT_new(group); // 创建椭圆曲线点C
        // 将字节数组转换为椭圆曲线上的点
        if (EC_POINT_oct2point(group, C, buf.data(), buf.size(), ctx) != 1)
        {
            std::cerr << "无效的C点\n";
            return 1; // 如果转换失败，输出错误并退出
        }
        // 解析消息m和随机数r
        BIGNUM *m = BN_new();
        BN_hex2bn(&m, mhex.c_str());
        BN_mod(m, m, order, ctx); // 将m的十六进制字符串转换为大整数并模群阶
        BIGNUM *r = BN_new();
        BN_hex2bn(&r, rhex.c_str());
        BN_mod(r, r, order, ctx); // 将r的十六进制字符串转换为大整数并模群阶

        // 使用验证函数执行验证
        bool result = pedersen_verify(group, C, m, r, G, H, ctx);
        std::cout << (result ? "OK\n" : "FAIL\n");

        // 释放分配的内存
        BN_free(m);
        BN_free(r);
        EC_POINT_free(C);
    }
    else
    {
        print_usage(); // 如果命令不匹配，显示使用说明
        return 1;
    }

    // 释放所有分配的内存
    free_pedersen_params(params);
    return 0;
}