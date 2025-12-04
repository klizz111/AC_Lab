#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/bn.h>

#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

class RsaBlindSign
{
private:
    BIGNUM* n;
    BIGNUM* d;
public:
    BIGNUM* e;

    struct BlindMessage {
        std::string blinded_msg;
        std::string nonce;
    };

    template<typename T>
    std::string to_hex(const T& buf) {
        using namespace std;
        {
            ostringstream oss;
            for (unsigned char byte : buf) {
                oss << hex << setw(2) << setfill('0') << (int)byte;
            }
            return oss.str();
        }
    }

    std::string bn_to_hex(const BIGNUM* n) {
        auto res = BN_bn2hex(n);
        std::string hex_str(res);
        OPENSSL_free(res);
        return hex_str;
    }

    std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
        using namespace std;
        {
            vector<unsigned char> bytes;
            for (size_t i = 0; i < hex.length(); i += 2) {
                string byteString = hex.substr(i, 2);
                unsigned char byte = (unsigned char)strtol(byteString.c_str(), nullptr, 16);
                bytes.push_back(byte);
            }
            return bytes;
        }
    }
    
    std::vector<unsigned char> generate_nonce(size_t len = 64) {
        std::vector<unsigned char> rand_bytes(len);
        RAND_bytes(rand_bytes.data(), len);
        return rand_bytes;
    }

    std::vector<unsigned char> sha256(const std::vector<unsigned char>& data) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(data.data(), data.size(), hash);
        std::vector<unsigned char> result;
        result.insert(result.end(), hash, hash + SHA256_DIGEST_LENGTH);
        return result;
    }

    RsaBlindSign() {
        n = BN_new();
        d = BN_new();
        e = BN_new();
    }

    ~RsaBlindSign() {
        BN_free(n);
        BN_free(d);
        BN_free(e);
    }

    void keygen(int bits = 2048) {
        BIGNUM* p;
        BIGNUM* q;
        BIGNUM* phi;
        p = BN_new();
        q = BN_new();
        phi = BN_new();
        BN_CTX* ctx = BN_CTX_new();

        // 1. gen prime p,q
    fallback:
        BN_generate_prime_ex(p, bits / 2, 0, nullptr, nullptr, nullptr);
        BN_generate_prime_ex(q, bits / 2, 0, nullptr, nullptr, nullptr);

        // 2. calc n = p*q
        BN_mul(n, p, q, ctx);

        // 3. calc phi = (p-1)*(q-1)
        BIGNUM* p_1 = BN_new();
        BIGNUM* q_1 = BN_new();
        BN_sub(p_1, p, BN_value_one());
        BN_sub(q_1, q, BN_value_one());
        BN_mul(phi, p_1, q_1, ctx);

        // 4. set e = 65537 and check gcd(e, phi) == 1
        BN_set_word(e, 65537);
        BIGNUM* gcd = BN_new();
        BN_gcd(gcd, e, phi, ctx);
        if (!BN_is_one(gcd)) {
            goto fallback;
        }

        // 5. calc d = e^(-1) mod phi
        BN_mod_inverse(d, e, phi, ctx);
    }

    BlindMessage blind(const std::string& message) {
        BlindMessage blind_msg;
        // 1. hash message
        auto msg_hex = to_hex(message);
        auto hash_bytes = sha256(hex_to_bytes(msg_hex));
        auto hex_hash = to_hex(hash_bytes);
        // 2. convert to BN
        BIGNUM* hash_bn = BN_new();
        BN_hex2bn(&hash_bn, hex_hash.c_str());
        // 3. gen nonce r
        auto nonce_bytes = generate_nonce();
        auto hex_nonce = to_hex(nonce_bytes);
        blind_msg.nonce = hex_nonce;
        BIGNUM* r = BN_new();
        BN_hex2bn(&r, hex_nonce.c_str());
        // 4. calc r^e mod n
        BIGNUM* r_e = BN_new();
        BN_CTX* ctx = BN_CTX_new();
        BN_mod_exp(r_e, r, e, n, ctx);
        // 5. calc blinded_msg = (hash * r^e) mod n
        BIGNUM* blinded_bn = BN_new();
        BN_mod_mul(blinded_bn, hash_bn, r_e, n, ctx);
        blind_msg.blinded_msg = bn_to_hex(blinded_bn);
        // free
        BN_free(hash_bn);
        BN_free(r);
        BN_free(r_e);
        BN_free(blinded_bn);

        return blind_msg;
    }

    std::string sign(const std::string& blinded_msg) {
        BN_CTX* ctx = BN_CTX_new();
        // 1. convert to BN
        BIGNUM* blinded_bn = BN_new();
        BN_hex2bn(&blinded_bn, blinded_msg.c_str());
        // 2. calc s' = m'^d mod n
        BIGNUM* signed_bn = BN_new();
        BN_mod_exp(signed_bn, blinded_bn, d, n, ctx);
        // 3. return hex
        auto signed_hex = bn_to_hex(signed_bn);
        // free
        BN_free(blinded_bn);
        BN_free(signed_bn);
        BN_CTX_free(ctx);

        return signed_hex;
    }

    std::string unblind(std::string r, std::string s_b_m) {
        BN_CTX* ctx = BN_CTX_new();
        // 1. convert 2 bn
        BIGNUM* rr = BN_new();
        BIGNUM* s_b_m_bn = BN_new();
        BN_hex2bn(&rr, r.c_str());
        BN_hex2bn(&s_b_m_bn, s_b_m.c_str());
        // 2 cal s = s' * r^{-1} mod n
        BIGNUM* s = BN_new();
        BN_mod_inverse(rr, rr, n, ctx);
        BN_mod_mul(s, s_b_m_bn, rr, n, ctx);
        // 3. return hex
        auto s_hex = bn_to_hex(s);
        // free
        BN_free(rr);
        BN_free(s_b_m_bn);
        BN_free(s);
        BN_CTX_free(ctx);

        return s_hex;
    }

    bool verify(const std::string& message, const std::string& signature) {
        // 1. hash message
        auto msg_hex = to_hex(message);
        auto hash_bytes = sha256(hex_to_bytes(msg_hex));
        auto hex_hash = to_hex(hash_bytes);
        // 2. convert to BN
        BIGNUM* sign_bn = BN_new();
        BN_hex2bn(&sign_bn, signature.c_str());
        // 3. calc mm == s^e mod n
        BN_CTX* ctx = BN_CTX_new();
        BIGNUM* mm = BN_new();
        BN_mod_exp(mm, sign_bn, e, n, ctx);
        // 4. assert mm == m
        auto mm_hex = bn_to_hex(mm);
        // free
        BN_free(sign_bn);
        BN_free(mm);
        BN_CTX_free(ctx);
        std::cout << "Origin Hash: " << hex_hash << std::endl;
        std::transform(mm_hex.begin(),mm_hex.end(),mm_hex.begin(), [](unsigned char c){ return std::tolower(c); });
        std::cout << "Recovered Hash: " << mm_hex << std::endl;
        if (mm_hex == hex_hash) {
            return true;
        } else {
            return false;
        }
    }
};

int main() {
    using namespace std;
    RsaBlindSign signer;
    signer.keygen(2048);

    const string message = "Blind signatures are cool";
    cout << "Message: " << message << endl;
    auto br = signer.blind(message);
    cout << "===Blinding===" << endl << endl;
    cout << "Blinded Message: " << br.blinded_msg << endl;
    cout << "Nonce: " << br.nonce << endl;
    auto signed__ = signer.sign(br.blinded_msg);
    cout << "===Signing===" << endl << endl;
    cout << "Signed Blinded Message: " << signed__ << endl;
    auto unblid = signer.unblind(br.nonce, signed__);
    cout << "===Unblinding===" << endl << endl;
    cout << "Unblinded Signature: " << unblid << endl;
    cout << "===Verifying===" << endl << endl;
    if (signer.verify(message, unblid)) {
        cout << "Signature Verified!" << endl;
    } else {
        cout << "Signature Verification Failed!" << endl;
    }
}