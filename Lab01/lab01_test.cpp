#include <iostream>
#include <cstdlib>
#include <sstream>
#include <string>
#include <vector>
#include <cassert>
#include <random>
#include <algorithm>

#ifdef _WIN32
#define POPEN _popen
#define PCLOSE _pclose
#define EXE_NAME(x) (x ".exe")
#define PATH_SEP "\\"
#else
#define POPEN popen
#define PCLOSE pclose
#define EXE_NAME(x) x
#define PATH_SEP "/"
#endif

// 辅助函数：按空格分割字符串
std::vector<std::string> split(const std::string &s)
{
    std::vector<std::string> res; // 存储分割后的字符串向量
    std::istringstream iss(s);    // 创建字符串输入流
    std::string token;            // 临时存储每个token
    while (iss >> token)
        res.push_back(token); // 按空格分割并存储到向量中
    return res;               // 返回分割后的字符串向量
}

// 执行命令并获取输出
std::string run_cmd(const std::string &cmd)
{
    std::string data;                       // 存储命令输出的字符串
    FILE *stream = POPEN(cmd.c_str(), "r"); // 执行命令并打开管道读取输出
    if (!stream)
        throw std::runtime_error("popen failed"); // 如果打开管道失败，抛出异常
    char buffer[256];                             // 创建缓冲区存储输出数据
    while (fgets(buffer, sizeof(buffer), stream))
    {                   // 逐行读取命令输出
        data += buffer; // 将读取的数据追加到字符串中
    }
    PCLOSE(stream); // 关闭管道
    return data;    // 返回命令输出
}

// 测试哈希承诺方案
bool test_hash_commit()
{
    std::string msg = "HelloCrypto";
    std::string cmd = std::string(".") + PATH_SEP + EXE_NAME("hash_commit") +
                      " commit " + msg;

    std::string out = run_cmd(cmd);
    auto tokens = split(out);
    if (tokens.size() != 2)
    {
        std::cerr << "hash_commit output parse fail\n";
        return false;
    }
    std::string commit_hex = tokens[0];
    std::string nonce_hex = tokens[1];

    std::string verify_cmd = std::string(".") + PATH_SEP + EXE_NAME("hash_commit") +
                             " open-verify " + commit_hex + " " + nonce_hex + " " + msg;
    std::string verify_out = run_cmd(verify_cmd);
    return verify_out.find("OK") != std::string::npos;
}

bool test_pedersen()
{
    std::string cmd = std::string(".") + PATH_SEP + EXE_NAME("pedersen") + " commit rand";
    std::string out = run_cmd(cmd);
    auto tokens = split(out);
    if (tokens.size() != 3)
    {
        std::cerr << "pedersen output parse fail\n";
        return false;
    }
    std::string C_hex = tokens[0];
    std::string m_hex = tokens[1];
    std::string r_hex = tokens[2];

    std::string verify_cmd = std::string(".") + PATH_SEP + EXE_NAME("pedersen") +
                             " verify " + C_hex + " " + m_hex + " " + r_hex;
    std::string verify_out = run_cmd(verify_cmd);
    return verify_out.find("OK") != std::string::npos;
}

bool test_shamir()
{
    std::string cmd = std::string(".") + PATH_SEP + EXE_NAME("shamir") + " share rand 3 5";
    std::string out = run_cmd(cmd);
    std::istringstream iss(out);
    std::string secret_hex;
    std::getline(iss, secret_hex);

    std::vector<std::string> shares;
    std::string line;
    while (std::getline(iss, line))
        if (!line.empty())
            shares.push_back(line);
    if (shares.size() != 5)
    {
        std::cerr << "shamir share output parse fail\n";
        return false;
    }

    std::vector<int> indices(shares.size());
    for (int i = 0; i < shares.size(); ++i)
        indices[i] = i;
    std::shuffle(indices.begin(), indices.end(),
                 std::mt19937{std::random_device{}()});

    int t = 3;
    std::string rec_cmd = std::string(".") + PATH_SEP + EXE_NAME("shamir") + " reconstruct";
    for (int i = 0; i < t; ++i)
        rec_cmd += " " + shares[indices[i]];

    std::string rec_out = run_cmd(rec_cmd);
    std::istringstream iss2(rec_out);
    std::string rec_hex;
    std::getline(iss2, rec_hex);
    return secret_hex == rec_hex;
}

int main()
{
    bool h = test_hash_commit(); // 运行哈希承诺测试
    bool p = test_pedersen();    // 运行Pedersen承诺测试
    bool s = test_shamir();      // 运行Shamir秘密分享测试

    // 输出测试结果
    std::cout << "HashCommit test: " << (h ? "PASS" : "FAIL") << "\n"; // 输出哈希承诺测试结果
    std::cout << "Pedersen test: " << (p ? "PASS" : "FAIL") << "\n";   // 输出Pedersen承诺测试结果
    std::cout << "Shamir test: " << (s ? "PASS" : "FAIL") << "\n";     // 输出Shamir秘密分享测试结果

    if (h && p && s)
        return 0; // 如果所有测试都通过，返回0
    return 1;     // 如果有测试失败，返回1
}
