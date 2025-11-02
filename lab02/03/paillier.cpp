#include <iostream>
#include <cstdlib>
#include "paillier.h"

int main() {
    std::cout << "=== Paillier 同态加密演示 ===" << std::endl;
    
    std::cout << "创建Paillier实例..." << std::endl;
    Paillier paillier;
    
    std::cout << "生成密钥..." << std::endl;
    paillier.generate_keys();
    
    // 打印生成的参数
    std::cout << "\n密钥参数信息:" << std::endl;
    char *p_str = BN_bn2dec(paillier.get_p());
    char *q_str = BN_bn2dec(paillier.get_q());
    char *n_str = BN_bn2dec(paillier.get_n());
    
    std::cout << "质数 p = " << p_str << std::endl;
    std::cout << "质数 q = " << q_str << std::endl;
    std::cout << "模数 n = " << n_str << std::endl;
    
    // 释放字符串内存
    OPENSSL_free(p_str);
    OPENSSL_free(q_str);
    OPENSSL_free(n_str);
    
    std::cout << "\n密钥生成完成" << std::endl;
    
    // 加密演示
    srand(time(0));
    int m1 = rand() % 1000, m2 = rand() % 1000, m3 = rand() % 1000;
    std::cout << "加密消息: " << m1 << ", " << m2 << ", " << m3 << std::endl;
    PaillierCiphertext c1 = paillier.encrypt(m1);
    PaillierCiphertext c2 = paillier.encrypt(m2);
    PaillierCiphertext c3 = paillier.encrypt(m3);
        
    // 解密演示
    std::cout << "解密消息..." << std::endl;
    int d1 = paillier.decrypt(c1);
    int d2 = paillier.decrypt(c2);
    int d3 = paillier.decrypt(c3);
    
    std::cout << "解密结果: " << d1 << ", " << d2 << ", " << d3 << std::endl;
    
    // 同态加法演示
    std::cout << "执行同态加法..." << std::endl;
    PaillierCiphertext result = c1 + c2;

    std::cout << "同态加法结果 c1 + c2 = " << result.to_string() << std::endl;
    
    int decrypted_result = paillier.decrypt(result);
    std::cout << "解密结果 = " << decrypted_result << std::endl;
    std::cout << "明文相加 = " << (m1 + m2) << std::endl;
    std::cout << "验证结果 " << (decrypted_result == m1 + m2 ? "正确" : "错误") << std::endl;

    std::cout << "执行同态加法..." << std::endl;
    PaillierCiphertext result2 = result + c3;

    std::cout << "同态加法结果 c1 + c2 + c3 = " << result2.to_string() << std::endl;
    
    int decrypted_result2 = paillier.decrypt(result2);
    std::cout << "解密结果 = " << decrypted_result2 << std::endl;
    std::cout << "明文相加 = " << (m1 + m2 + m3) << std::endl;
    std::cout << "验证结果 " << (decrypted_result2 == m1 + m2 + m3 ? "正确" : "错误") << std::endl;

    // 同态数乘演示
    int a = rand() % 1000;
    std::cout << "执行同态数乘..." << std::endl;
    PaillierCiphertext result3 = result2 * a;

    std::cout << "同态数乘结果 (c1 + c2 + c3) * a = " << result3.to_string() << std::endl;
    
    int decrypted_result3 = paillier.decrypt(result3);
    std::cout << "解密结果 = " << decrypted_result3 << std::endl;
    std::cout << "明文数乘 = " << (m1 + m2 + m3) * a << std::endl;
    std::cout << "验证结果 " << (decrypted_result3 == (m1 + m2 + m3) * a ? "正确" : "错误") << std::endl;
    
    return 0;
}