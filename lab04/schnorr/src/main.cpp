#include "schnorr_signature.h"
#include <iostream>
#include <memory>
#include <cassert>
#include <vector>

// 测试签名生成和验证
void testSignature() {
    std::cout << "测试签名生成和验证..." << std::endl;

    SchnorrSignature schnorr;
    BIGNUM* private_key = nullptr;
    EC_POINT* public_key = nullptr;

    // 生成密钥对
    bool keyResult = schnorr.generateKeyPair(private_key, public_key);
    assert(keyResult == true);

    // 对消息进行签名
    std::string message = "Test message for Schnorr signature";
    BIGNUM* r = nullptr;
    BIGNUM* s = nullptr;

    bool signResult = schnorr.sign(message, private_key, r, s);
    assert(signResult == true);
    assert(r != nullptr);
    assert(s != nullptr);

    // 验证签名
    bool verifyResult = schnorr.verify(message, r, s, public_key);
    assert(verifyResult == true);

    // 使用错误消息进行测试应该失败
    std::string wrongMessage = "Wrong test message";
    bool wrongVerifyResult = schnorr.verify(wrongMessage, r, s, public_key);
    assert(wrongVerifyResult == false);

    // 清理内存
    BN_free(private_key);
    EC_POINT_free(public_key);
    BN_free(r);
    BN_free(s);

    std::cout << "签名测试通过!" << std::endl;
}

int main() {
    try {
        std::cout << "运行Schnorr签名..." << std::endl;
        testSignature();
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "测试失败，异常: " << e.what() << std::endl;
        return 1;
    }
}