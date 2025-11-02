#include <openssl/rand.h>
#include <openssl/sha.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

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
 * 验证承诺值是否与给定的消息和随机数匹配
 * @param commit_hex 承诺值的十六进制字符串
 * @param nonce_hex 随机数的十六进制字符串
 * @param message 消息
 * @return 验证是否成功
 */
bool verify(const std::string &commit_hex, const std::string &nonce_hex, const std::string &message)
{
    std::vector<unsigned char> C = hex_to_bytes(commit_hex);    // 将输入的十六进制承诺值转换为字节
    std::vector<unsigned char> nonce = hex_to_bytes(nonce_hex); // 将输入的十六进制随机数转换为字节
    std::vector<unsigned char> computed_commit = commit(message, nonce); // 重新计算承诺值
    return C == computed_commit;                                // 比较是否匹配
}

int main(int argc, char **argv)
{
    if (argc != 4)
    {
        std::cerr << "Usage: " << argv[0] << " <commit_hex> <nonce_hex> <message>  # Verify commit\n";
        return 1;
    }
    
    std::string commit_hex = argv[1];
    std::string nonce_hex = argv[2];
    std::string message = argv[3];
    
    bool result = verify(commit_hex, nonce_hex, message);
    
    if (result) {
        std::cout << "Success! Verify result is correct." << std::endl;
        std::cout << "commit_hex: " << commit_hex << std::endl;
        std::cout << "message: " << message << std::endl;
        std::cout << "nonce_hex: " << nonce_hex << std::endl;
    } else {
        std::cout << "Fail! Verify result is incorrect." << std::endl;
    }
    
    return 0;
}