#include <iostream>
#include <vector>
#include <utility>
#include <string>
#include <algorithm>

#include "elgamal.hpp"

int main()
{
    std::cout << "=== ElGamal加密算法演示 ===" << std::endl;

    std::srand(static_cast<unsigned>(std::time(nullptr)));

    // 创建ElGamal实例
    ElGamal elgamal;

    // 生成安全密钥参数
    std::cout << "生成安全1024位密钥参数..." << std::endl;
    elgamal.generate_secure_key_parameters();

    // 显示密钥对
    std::cout << "公钥 (1024位素数 p): " << elgamal.get_public_key() << std::endl;
    std::cout << "私钥 (x值 - 为安全起见部分显示): ";
    std::string private_key = elgamal.get_private_key();
    // 只显示前50个字符以保护私钥安全
    if (private_key.length() > 50)
    {
        std::cout << private_key.substr(0, 50) << "...[为安全起见已截断]" << std::endl;
    }
    else
    {
        std::cout << private_key << std::endl;
    }

    // 加密演示
    std::cout << "\n=== 加密解密演示 ===" << std::endl;
    int message = generate_random_message();  
    std::cout << "原始消息: " << message << std::endl;

    ElGamalCiphertext ciphertext = elgamal.encrypt(message);
    std::cout << "密文: ";
    std::string cipher_str = ciphertext.to_string();
    std::cout << cipher_str << std::endl;

    int decrypted = elgamal.decrypt(ciphertext);
    std::cout << "解密结果: " << decrypted << std::endl;
    std::cout << "加解密验证: " << (message == decrypted ? "成功" : "失败") << std::endl;

    // 演示分布式解密
    std::cout << "\n=== ElGamal分布式解密演示 ===" << std::endl;
    
    // 重新生成一个消息用于分布式解密演示
    int dist_message = generate_random_message();
    std::cout << "分布式解密演示消息: " << dist_message << std::endl;

    ElGamalCiphertext dist_ciphertext = elgamal.encrypt(dist_message);
    std::cout << "分布式解密密文: " << dist_ciphertext.to_string() << std::endl;

    // 使用Shamir秘密分享分割私钥
    // 随机生成阈值和总份额数，确保阈值合理（至少2，小于总份额）
    int total_shares = (rand() % 4) + 5;  // 随机生成5-8个总份额 (minimum 5 to allow threshold < total_shares while keeping threshold >= 2)
    int threshold = (rand() % (total_shares - 2)) + 2;  // 随机生成2到(total_shares-1)之间的阈值
    std::vector<std::pair<int, BIGNUM*>> shares = elgamal.split_secret_key(threshold, total_shares);
    std::cout << "生成了 " << total_shares << " 个份额，阈值为 " << threshold << std::endl;

    // 随机选择份额进行分布式解密 (只需要threshold个份额)
    std::vector<std::pair<int, BIGNUM*>> selected_shares;
    std::vector<int> available_indices;
    for (int i = 0; i < total_shares; i++) {
        available_indices.push_back(i);
    }
    
    // 随机打乱索引并选择前threshold个
    for (int i = 0; i < available_indices.size(); i++) {
        int j = rand() % available_indices.size();
        std::swap(available_indices[i], available_indices[j]);
    }
    
    for (int i = 0; i < threshold; i++) {
        int idx = available_indices[i];
        selected_shares.push_back(shares[idx]);
        std::cout << "选择份额 " << shares[idx].first << ": " << BN_bn2dec(shares[idx].second) << std::endl;
    }

    int distributed_decrypted = elgamal.distributed_decrypt(dist_ciphertext, selected_shares);
    std::cout << "分布式解密结果: " << distributed_decrypted << std::endl;
    std::cout << "分布式解密验证: " << (dist_message == distributed_decrypted ? "成功" : "失败") << std::endl;
    
    // 验证使用不同组合的份额也能得到相同结果
    std::cout << "\n验证不同份额组合的解密结果..." << std::endl;
    
    // 随机选择不同的份额组合（确保与之前的选择不完全相同）
    std::vector<int> available_indices2;
    for (int i = 0; i < total_shares; i++) {
        available_indices2.push_back(i);
    }
    
    // 随机打乱索引
    for (int i = 0; i < available_indices2.size(); i++) {
        int j = rand() % available_indices2.size();
        std::swap(available_indices2[i], available_indices2[j]);
    }
    
    // 确保选择的组合与第一次不完全相同
    bool same_combination = true;
    int attempts = 0;
    std::vector<int> temp_indices;
    
    while (same_combination && attempts < 10) {
        temp_indices = available_indices2;
        // 随机再次打乱
        for (int i = 0; i < temp_indices.size(); i++) {
            int j = rand() % temp_indices.size();
            std::swap(temp_indices[i], temp_indices[j]);
        }
        
        same_combination = true;
        // 检查前threshold个索引是否与selected_shares的索引相同
        std::vector<int> selected_indices;
        for (int i = 0; i < threshold; i++) {
            selected_indices.push_back(available_indices[i]);
        }
        
        std::vector<int> new_selected_indices;
        for (int i = 0; i < threshold; i++) {
            new_selected_indices.push_back(temp_indices[i]);
        }
        
        // 排序以比较是否为相同的组合
        std::sort(selected_indices.begin(), selected_indices.end());
        std::sort(new_selected_indices.begin(), new_selected_indices.end());
        
        if (selected_indices == new_selected_indices) {
            same_combination = true;
            attempts++;
        } else {
            same_combination = false;
        }
    }
    
    // 使用新选择的索引
    std::vector<std::pair<int, BIGNUM*>> different_shares;
    for (int i = 0; i < threshold; i++) {
        int idx = temp_indices[i];
        different_shares.push_back(shares[idx]);
    }
    
    int different_decrypted = elgamal.distributed_decrypt(dist_ciphertext, different_shares);
    std::cout << "使用不同份额组合的解密结果: " << different_decrypted << std::endl;
    std::cout << "不同份额组合解密验证: " << (dist_message == different_decrypted ? "成功" : "失败") << std::endl;
    
    // 清理所有份额内存 (shares and different_shares contain the same BIGNUM pointers)
    for (auto &share : shares) {
        BN_free(share.second);
    }
    
    // Note: We don't free different_shares second time as they point to same memory as shares

    return 0;
}