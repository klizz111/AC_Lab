#include <openssl/rand.h>
#include <openssl/sha.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

// TODO: 学生需要实现此函数 - 将字节转换为十六进制字符串（作为工具函数）
std::string to_hex(const std::vector<unsigned char> &buf)
{
    // 提示：可使用std::ostringstream和std::hex, std::setw, std::setfill
    // 实现将字节向量转换为十六进制字符串
    // 例如：{0x1, 0x2, 0xAB} 应该转换为 "0102ab"
    // 你的代码在这里
    using namespace std; 
    {
        ostringstream oss;
        for (unsigned char byte : buf) {
            oss << hex << setw(2) << setfill('0') << (int)byte;
        }
        return oss.str();
    }
}

// TODO: 学生需要实现此函数 - 将十六进制字符串转换为字节（作为工具函数）
std::vector<unsigned char> hex_to_bytes(const std::string &hex)
{
    // 提示：hex字符串每两个字符代表一个字节
    // 例如："0102ab" 应该转换为 {0x1, 0x2, 0xAB}
    // 你的代码在这里
    using namespace std; 
    {
        vector<unsigned char> bytes;
        for (size_t i = 0; i < hex.length(); i += 2) {
            string byteString = hex.substr(i, 2);
            unsigned char byte = (unsigned char) strtol(byteString.c_str(), nullptr, 16);
            bytes.push_back(byte);
        }
        return bytes;
    }
}

// TODO: 学生需要实现此函数 - 对数据进行SHA256哈希
std::vector<unsigned char> sha256(const std::vector<unsigned char> &data)
{
    // 提示：使用OpenSSL的SHA256函数
    // SHA256_DIGEST_LENGTH是哈希输出的长度
    // 你的代码在这里
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data.data(),data.size(),hash);
    std::vector<unsigned char> result;
    result.insert(result.end(),hash,hash+SHA256_DIGEST_LENGTH);
    return result;
    // return {}; // 临时返回，学生需要替换
}

// TODO: 学生需要实现此函数 - 生成指定长度的安全随机数
/// @brief 产生随机数
/// @param len int_32 随机数长度
/// @return rand_bytes int_32 随机数
std::vector<unsigned char> generate_nonce(size_t len = 32)
{
    // 提示：使用OpenSSL的RAND_bytes函数生成随机数
    // 你的代码在这里
    std::vector<unsigned char> rand_bytes(len); 
    RAND_bytes(rand_bytes.data(), len);
    return rand_bytes;
}

// TODO: 学生需要实现此函数 - 计算承诺值，即SHA256(message || nonce)
/// @brief 
/// @param message ASCII明文字符串
/// @param nonce bytes随机数
/// @return 
std::vector<unsigned char> commit(const std::string &message, const std::vector<unsigned char> &nonce)
{
    // 提示：将消息和随机数连接起来，然后计算SHA256哈希
    // message需要先转换为字节向量
    // 你的代码在这里
    auto vec_message = std::vector<unsigned char>(message.begin(), message.end());
    vec_message.insert(vec_message.end(), nonce.begin(), nonce.end());
    auto res = sha256(vec_message);
    return res;
}

// TODO: 学生需要实现此函数 - 创建承诺并输出结果
/// @brief 哈西承诺
/// @param message ASCII明文字符串
/// @return 输出十六进制Commit和Nonce
void do_commit(const std::string &message)
{
    // 提示：
    // 1. 生成随机数
    // 2. 计算承诺值
    // 3. 打印出承诺值和随机数的十六进制表示，用空格分隔(调用to_hex函数)
    // 你的代码在这里
    auto rand_nonce = generate_nonce();
    auto hex_nonce = to_hex(rand_nonce);
    auto hash_commit = commit(message, rand_nonce);
    std::cout << to_hex(hash_commit) << " " << hex_nonce << std::endl;
}

// TODO: 学生需要实现此函数 - 验证承诺是否正确
bool verify(const std::string &commit_hex, const std::string &nonce_hex, const std::string &message)
{
    // 提示：将十六进制字符串转换为字节向量(hex_to_bytes函数) ，重新计算承诺值，并比较
    // 你的代码在这里
    auto hex_message = std::vector<unsigned char>(message.begin(), message.end());
    auto hex_commit = commit(message, hex_to_bytes(nonce_hex));
    if (to_hex(hex_commit) == commit_hex) {
        return true;
    } else {
        return false;
    }
}

int main(int argc, char **argv)
{
    if (argc < 3)
    {
        std::cerr << "使用说明:\n"
                  << argv[0] << " commit <message>          # 创建承诺      Output: <commit_hex> <nonce_hex>\n"
                  << argv[0] << " open-verify <commit_hex> <nonce_hex> <message>  # 验证承诺\n";
        return 1;
    }

    std::string cmd = argv[1]; // 获取命令参数（commit或open-verify）
    if (cmd == "commit")
    {
        do_commit(argv[2]);
    }
    else if (cmd == "open-verify" && argc == 5)
    {
        std::cout << (verify(argv[2], argv[3], argv[4]) ? "OK" : "FAIL") << std::endl;
    }
    else
    {
        std::cerr << "参数错误\n";
        return 1;
    }

    return 0;
}