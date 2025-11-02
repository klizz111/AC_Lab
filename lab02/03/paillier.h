#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/bn.h> 
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <random>

using namespace std;

class PaillierCiphertext{
public:
    BIGNUM *n;
    BIGNUM *g;
    BIGNUM *c; 
    PaillierCiphertext() {
        n = BN_new();
        g = BN_new();
        c = BN_new();
    }
    PaillierCiphertext(BIGNUM *n, BIGNUM *g, BIGNUM *c) {
        this->n = BN_new();
        this->g = BN_new();
        this->c = BN_new();
        BN_copy(this->n, n);
        BN_copy(this->g, g);
        BN_copy(this->c, c);
    }
    PaillierCiphertext operator+(const PaillierCiphertext &other) const {
        PaillierCiphertext result;
        BN_CTX *ctx = BN_CTX_new();
        auto n2 = BN_new();
        BN_mul(n2, n, n, ctx);
        BN_mod_mul(result.c, c, other.c, n2, ctx); // c1 * c2 mod n^2
        BN_copy(result.n, n);
        BN_copy(result.g, g);
        BN_free(n2);
        BN_CTX_free(ctx);
        return result;
    }
    PaillierCiphertext operator*(const int &k) const {
        PaillierCiphertext result;
        BN_CTX *ctx = BN_CTX_new();
        auto n2 = BN_new();
        BN_mul(n2, n, n, ctx);
        auto bk = BN_new();
        BN_set_word(bk, k);
        BN_mod_exp(result.c, c, bk, n2, ctx); // c^k mod n^2
        BN_copy(result.n, n);
        BN_copy(result.g, g);
        BN_free(n2);
        BN_CTX_free(ctx);
        return result;
    }
    string to_string() const {
        return BN_bn2hex(c);
    }
};
class Paillier {
public:
    Paillier();
    ~Paillier() {BN_free(p); BN_free(q); BN_free(n); BN_free(g); BN_free(lambda); BN_free(miu); BN_CTX_free(ctx);}

    void generate_keys(int bits=512);
    PaillierCiphertext encrypt(int m);
    int decrypt(const PaillierCiphertext &c);

    BIGNUM* get_p() const { return p; }
    BIGNUM* get_q() const { return q; }
    BIGNUM* get_n() const { return n; }
private:
    BIGNUM *p, *q, *n, *g, *lambda, *miu;
    BN_CTX *ctx;
    void lcm(BIGNUM *lamba, const BIGNUM *a, const BIGNUM *b);
};

Paillier::Paillier()
{
    p = BN_new();
    q = BN_new();
    n = BN_new();
    g = BN_new();
    lambda = BN_new();
    miu = BN_new();
    ctx = BN_CTX_new();
}

void Paillier::generate_keys(int bits)
{
    BN_generate_prime_ex(p, bits/2, 0, NULL, NULL, NULL); // p
    BN_generate_prime_ex(q, bits/2, 0, NULL, NULL, NULL); // q
    BN_mul(n, p, q, ctx); // n = p * q

    BIGNUM *pm1 = BN_dup(p);
    BIGNUM *qm1 = BN_dup(q);
    BN_sub_word(pm1, 1);
    BN_sub_word(qm1, 1);
    lcm(lambda, pm1, qm1); // lambda = lcm(p-1, q-1)
    BN_free(pm1);
    BN_free(qm1);

    auto n2 = BN_new();
    BN_mul(n2, n, n, ctx);
    // BN_rand_range(g, n2);
    auto n_add_1 = BN_dup(n);
    BN_add_word(n_add_1, 1);
    BN_copy(g, n_add_1); // g = n + 1

/*     auto tmp1 = BN_new();
    BN_mod_exp(tmp1, g, lambda, n2, ctx); 
    BN_sub_word(tmp1, 1);
    BN_div(tmp1, NULL, tmp1, n, ctx); 
    BN_mod_inverse(miu, tmp1, n, ctx); */
    BN_mod_inverse(miu, lambda, n, ctx); // miu = lambda^(-1) mod n
    
    BN_free(n2);
}

PaillierCiphertext Paillier::encrypt(int m)
{
    auto n2 = BN_new();
    BN_mul(n2, n, n, ctx);
    auto r = BN_new();
    BN_rand_range(r, n2);

    auto nm = BN_new();
    BN_mod_mul(nm, n, BN_value_one(), n2, ctx); 
    BN_mul_word(nm, m); // nm = n * m mod n^2
    BN_add_word(nm, 1); // nm = n * m + 1

    BN_mod_exp(r, r, n, n2, ctx); //r = r^n mod n^2
    
    auto c = BN_new();
    BN_mod_mul(c, nm, r, n2, ctx); // c = (n*m + 1) * r^n mod n^2

    BN_free(n2);
    BN_free(r);


    return PaillierCiphertext(this->n, this->g, c);
}

int Paillier::decrypt(const PaillierCiphertext &c)
{
    auto n2 = BN_new();
    BN_mul(n2, n, n, ctx);

    auto x = BN_new();
    BN_mod_exp(x, c.c, lambda, n2, ctx); // x = c^lambda mod n^2 
    auto lx = BN_new();
    BN_sub_word(x, 1);
    BN_div(lx, NULL, x, n, ctx); // lx = (x-1)/n
    auto m = BN_new();
    BN_mod_mul(m, lx, miu, n, ctx); // m = (lx * miu) mod n
    int result = BN_get_word(m);
    BN_free(n2);
    return result;
}

void Paillier::lcm(BIGNUM *lamba, const BIGNUM *a, const BIGNUM *b)
{
    auto gcd = BN_new();
    auto tmp = BN_new();
    auto CTX = BN_CTX_new();

    BN_gcd(gcd, a, b, CTX);
    BN_mul(tmp, a, b, CTX);
    BN_div(lamba, NULL, tmp, gcd, CTX);

    BN_free(gcd);
    BN_free(tmp);
    BN_CTX_free(CTX);
}
