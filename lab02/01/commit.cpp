#include <openssl/rand.h>
#include <openssl/sha.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <cstdlib>  // 用于 rand()

/**
 * 将字节数组转换为十六进制字符串
 * @param buf 输入的字节数组
 * @return 对应的十六进制字符串
 */
std::string to_hex(const std::vector<unsigned char> &buf)
{
    std::ostringstream oss;
    for (unsigned char c : buf)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    return oss.str();
}

/**
 * 将十六进制字符串转换为字节数组
 * @param hex 输入的十六进制字符串
 * @return 对应的字节数组
 */
std::vector<unsigned char> hex_to_bytes(const std::string &hex)
{
    std::vector<unsigned char> buf(hex.size() / 2); // 每两个十六进制字符代表一个字节
    for (size_t i = 0; i < buf.size(); ++i)
        buf[i] = (unsigned char)std::stoul(hex.substr(2 * i, 2), nullptr, 16);
    return buf;
}

/**
 * 计算SHA256哈希值
 * @param data 输入的数据
 * @return SHA256哈希值
 */
std::vector<unsigned char> sha256(const std::vector<unsigned char> &data)
{
    std::vector<unsigned char> digest(SHA256_DIGEST_LENGTH); // 创建足够大的缓冲区存储SHA256哈希值
    SHA256(data.data(), data.size(), digest.data());         // 计算数据的SHA256哈希值
    return digest;
}

/**
 * 生成小范围的随机数作为nonce（随机数）- 用于实验目的
 * @return 4字节的随机数数组
 */
std::vector<unsigned char> generate_nonce_small()
{
    // 生成一个较小的随机数（0-65535）并转换为4字节
    srand(time(NULL));  // 初始化随机数种子，基于当前时间
    int small_nonce = rand() % 65536;  // 生成0-65535之间的随机数
    
    std::vector<unsigned char> nonce(4);
    nonce[0] = (small_nonce >> 24) & 0xFF;
    nonce[1] = (small_nonce >> 16) & 0xFF;
    nonce[2] = (small_nonce >> 8) & 0xFF;
    nonce[3] = small_nonce & 0xFF;
    
    return nonce;
}

/**
 * 计算承诺值 commit = SHA256(message || nonce)，其中||表示连接操作
 * @param message 消息字符串
 * @param nonce 随机数
 * @return 承诺值（SHA256哈希）
 */
std::vector<unsigned char> commit(const std::string &message, const std::vector<unsigned char> &nonce)
{
    std::vector<unsigned char> data(message.begin(), message.end()); // 将消息字符串转换为字节向量
    data.insert(data.end(), nonce.begin(), nonce.end());             // 将随机数连接到消息后面
    return sha256(data);                                             // 对连接后的数据进行SHA256哈希运算，并返回哈希值
}

/**
 * 创建承诺并以十六进制输出承诺值和随机数
 * @param message 输入的消息
 */
void create_commit(const std::string &message)
{
    std::vector<unsigned char> nonce = generate_nonce_small();  // 为实验生成小范围随机数
    std::vector<unsigned char> C = commit(message, nonce);      // 计算承诺值
    std::cout << to_hex(C) << " " << to_hex(nonce) << std::endl; // 以十六进制输出承诺值和随机数
}

void create_commit(const std::string &message, const std::vector<unsigned char> &nonce)
{
    std::vector<unsigned char> C = commit(message, nonce);      // 计算承诺值
    std::cout << to_hex(C) << " " << to_hex(nonce) << std::endl; // 以十六进制输出承诺值和随机数
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " create <message>    # Create commit\n";
        return 1;
    }
    
    std::string cmd = argv[1];
    
    if (cmd == "create") {
        if(argc == 4){
            std::cout << "create commit with nonce: " << argv[3] << std::endl;
            create_commit(argv[2], hex_to_bytes(argv[3]));
        }
        else{
            create_commit(argv[2]);
        }
    }
    else {
        std::cerr << "Unknown command: " << cmd << std::endl;
        return 1;
    }
    
    return 0;
}