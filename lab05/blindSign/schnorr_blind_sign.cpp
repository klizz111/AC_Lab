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

#define NNN(x) BIGNUM* x = BN_new(); 
#define NN BIGNUM*
#define N_ BN_new()
#define F_(x) BN_free(x)
#define BF(...) \
    do { \
        BIGNUM* bn_list[] = { __VA_ARGS__ }; \
        for (BIGNUM* bn : bn_list) { \
            BN_free(bn); \
        } \
    } while (0)
#define CC BN_CTX*
#define CCC(x) CC x = BN_CTX_new();
#define C_ BN_CTX_new()
#define CF_(x) BN_CTX_free(x)

template<typename T>
std::string to_hex(const T& buf) {
    using namespace std;
    {
        ostringstream oss;
        for (unsigned char byte : buf) {
            oss << hex << setw(2) << setfill('0') << uppercase << (int)byte;
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

class SchnorrBlindSign
{
private:
    BIGNUM* p;
    BIGNUM* q;
    BIGNUM* g;
    BIGNUM* k;
    BIGNUM* x;
public:
    BIGNUM* y;

    SchnorrBlindSign() {
        p = BN_new();
        q = BN_new();
        g = BN_new();
        y = BN_new();
        x = BN_new();
        k = BN_new();
    }

    ~SchnorrBlindSign() {
        BF(p, q, g, x, y);
    }

    void keygen(int bits = 256) {
        BN_CTX* ctx = BN_CTX_new();

        // 1. gen prime p
        BN_generate_prime_ex(p, bits, 1, nullptr, nullptr, nullptr);

        // 2. q = (p-1)/2
        BN_sub(q, p, BN_value_one());
        BN_rshift1(q, q);

        // 3. gen g = h^2
        BIGNUM* h = BN_new();
        BIGNUM* two = BN_new();
        BN_set_word(two, 2);
    fallback:
        BN_rand_range(h, p);
        BN_mod_exp(g, h, two, p, ctx);
        if (BN_is_one(g)) {
            goto fallback;
        }
        // 4. gen x 
        BN_rand_range(x, q);
        // 5. calc y = g^x mod p
        BN_mod_exp(y, g, x, p, ctx);
        // free
        BN_free(h);
        BN_free(two);
        BN_CTX_free(ctx);
    }

    std::string commit() {
        // 1. gen k
        BN_rand_range(k, q);
        // 2. calc R = g^k mod p
        BIGNUM* R = BN_new();
        BN_CTX* ctx = BN_CTX_new();
        BN_mod_exp(R, g, k, p, ctx);
        // 3. return hex
        auto R_hex = bn_to_hex(R);
        // free
        BN_free(R);
        BN_CTX_free(ctx);

        return R_hex;
    }

    struct BlindFactors
    {
        std::string alpha_hex;
        std::string beta_hex;
    };

    struct BlincMessage
    {
        BlindFactors bf;
        std::string e_hex;
        std::string ee_hex;
    };

    BlincMessage blind(const std::string& R_hex, const std::string& message) {
        // 1. gen alpha, beta
        BIGNUM* alpha = BN_new();
        BIGNUM* beta = BN_new();
        BN_rand_range(alpha, q);
        BN_rand_range(beta, q);
        BlindFactors bf;
        bf.alpha_hex = bn_to_hex(alpha);
        bf.beta_hex = bn_to_hex(beta);

        // 2. calc RR = R * g^alpha * y^beta mod p
        NN R = N_;
        NN RR = N_;
        NN g_alpha = N_;
        NN y_beta = N_;
        BN_hex2bn(&R, R_hex.c_str());
        CC ctx = C_;
        BN_mod_exp(g_alpha, g, alpha, p, ctx);
        BN_mod_exp(y_beta, y, beta, p, ctx);
        BN_mod_mul(RR, R, g_alpha, p, ctx);
        BN_mod_mul(RR, RR, y_beta, p, ctx);

        // 3. calc ee = H(m || RR)
        auto message_hex = to_hex(message);
        auto RR_hex = bn_to_hex(RR);
        auto concat = message_hex + RR_hex;
        auto hash_bytes = sha256(hex_to_bytes(concat));
        auto ee_hex = to_hex(hash_bytes);

        // 4. calc e = ee + beta mod q
        NNN(ee);
        NNN(e);
        BN_hex2bn(&ee, ee_hex.c_str());
        BN_mod(ee, ee, q, ctx);
        BN_mod_add(e, ee, beta, q, ctx);
        auto e_hex = bn_to_hex(e);

        BlincMessage bm;
        bm.bf = bf;
        bm.e_hex = e_hex;
        bm.ee_hex = ee_hex;


        // free
        BF(alpha, beta, R, RR, g_alpha, y_beta, ee, e);
        CF_(ctx);

        return bm;
    }

    std::string sign(const std::string& e_hex) {
        // 1, conv 2 bn
        NNN(e);
        BN_hex2bn(&e, e_hex.c_str());
        // 2. calc s = k + x * e mod q
        NNN(s);
        CCC(ctx);
        BN_mod_mul(s, x, e, q, ctx);
        BN_mod_add(s, s, k, q, ctx);
        // 3. return hex
        auto s_hex = bn_to_hex(s);
        // free
        BF(e, s);
        CF_(ctx);
        return s_hex;
    }

    struct Signature
    {
        std::string ee_hex;
        std::string ss_hex;
        std::string message;
    };

    Signature Unblind(BlincMessage& bm, std::string& s_hex, std::string& message) {
        // 1. unpack alpha
        auto alpha_hex = bm.bf.alpha_hex;
        // 2. conv 2 bn
        NNN(alpha);
        NNN(s);
        BN_hex2bn(&s, s_hex.c_str());
        BN_hex2bn(&alpha, alpha_hex.c_str());
        // 3. calc ss = s + alpha mod q
        NNN(ss);
        CCC(ctx);
        BN_mod_add(ss, s, alpha, q, ctx);
        // 4. return hex
        Signature sig;
        sig.ss_hex = bn_to_hex(ss);
        sig.ee_hex = bm.ee_hex;
        sig.message = message;
        // free
        BF(alpha, s, ss);
        CF_(ctx);
        return sig;
    }

    bool Verify(Signature& sign) {
        // 1. unpack ee, ss
        auto ee_hex = sign.ee_hex;
        auto ss_hex = sign.ss_hex;
        // 2. conv 2 bn
        NNN(ee);
        NNN(ss);
        BN_hex2bn(&ee, ee_hex.c_str());
        BN_hex2bn(&ss, ss_hex.c_str());
        // 3. calc y^-ee
        CCC(ctx);
        NNN(y_ee);
        BN_mod_exp(y_ee, y, ee, p, ctx);
        BN_mod_inverse(y_ee, y_ee, p, ctx);
        // 4. calc RRR = g^ss * y^{-ee} mod p
        NNN(g_ss);
        NNN(RRR);
        BN_mod_exp(g_ss, g, ss, p, ctx);
        BN_mod_mul(RRR, g_ss, y_ee, p, ctx);
        // 5. calc eee = H(m || RRR)
        auto message_hex = to_hex(sign.message);
        auto RRR_hex = bn_to_hex(RRR);
        auto concat = message_hex + RRR_hex;
        auto hash_bytes = sha256(hex_to_bytes(concat));
        auto eee_hex = to_hex(hash_bytes);
        // 6. assert eee == ee
        // free
        BF(ee, ss, g_ss, y_ee, RRR);
        CF_(ctx);
        std::cout << "Original ee: " << ee_hex << std::endl;
        std::cout << "Computed eee: " << eee_hex << std::endl;

        return ee_hex == eee_hex;
    }
};

int main() {
    using std::cout;
    std::string message = "The macro is N1c3(";

    SchnorrBlindSign schnorr;
    schnorr.keygen();
    cout << "System inited, start blind sign..." << std::endl;
    cout << "Message: " << message << std::endl;
    cout << "=== Step 1: Commit ===" << std::endl << std::endl;
    auto R_hex = schnorr.commit();
    cout << "Gen commitment R: " << R_hex << std::endl;
    cout << "=== Step 2: Blind ===" << std::endl << std::endl;
    auto bm = schnorr.blind(R_hex, message);
    cout << "alpha: " << bm.bf.alpha_hex << std::endl;
    cout << "beta: " << bm.bf.beta_hex << std::endl;
    cout << "e: " << bm.e_hex << std::endl;
    cout << "ee: " << bm.ee_hex << std::endl;
    cout << "=== Step 3: Sign ===" << std::endl << std::endl;
    auto s_hex = schnorr.sign(bm.e_hex);
    cout << "s: " << s_hex << std::endl;
    cout << "=== Step 4: Unblind ===" << std::endl << std::endl;
    auto sig = schnorr.Unblind(bm, s_hex, message);
    cout << "ss: " << sig.ss_hex << std::endl;
    cout << "ee: " << sig.ee_hex << std::endl;
    cout << "=== Step 5: Verify ===" << std::endl << std::endl;
    if (schnorr.Verify(sig)) {
        cout << "Signature verified!" << std::endl;
    } else {
        cout << "Signature verify failed!" << std::endl;
    }
}