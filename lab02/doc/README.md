# 高级密码第 02 次实验报告

## 实验环境

### 系统环境
```sh
Virtualization: wsl
Operating System: Ubuntu 24.04.2 LTS                      
Kernel: Linux 5.15.153.1-microsoft-standard-WSL2
Architecture: x86-64
```

### 环境依赖
```sh
g++ (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0
cmake version 3.28.3
GNU Make 4.3 为 x86_64-pc-linux-gnu 编译
OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)
```

## 一、 哈希爆破

### 程序编译
```sh
#bin/bash
# PATH=./01
mkdir -p build
(cd build; cmake ..; make)
# 编译后的程序在./bin目录下
ls ./bin # commit crack verify
```

### 程序运行
```sh
$ ./crack
Found! message: flag73, nonce: 00000029, commit: d62cc82e34b963db7ae121557d6fe4d3c0f7fc383ab309b352e750dffcd2c9d5
Cracking completed in 55 ms
[1]    16388 segmentation fault (core dumped)  ./crack
```
> 这里程序没有正常终止是因为找到结果后就直接`exit(0)`了，没有管其他的线程。
平均运行时间在 `10~80ms` 左右。

### 具体实现

1. 验证函数
```cpp
void _create_commit(const std::string &message, const vector<unsigned char> &nonce)
{
    std::vector<unsigned char> C = commit(message, nonce); 
    if (to_hex(C) == target) {
        auto end_time = chrono::high_resolution_clock::now(); 
        auto duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time).count();
        cout << "Found! message: " << message << ", nonce: " << to_hex(nonce) << ", commit: " << to_hex(C) << endl;
        cout << "Cracking completed in " << duration << " ms" << endl; 
        exit(0);
    }
}
```

2. 多线程爆破

这里将线程数通过文件开头的 `int thread_num = 10;` 设置为10。
爆破过程中把随机数以10为间隔分为10个batch，每个线程负责 $70000 \div 10 \times 100 = 700000$ 个 `_create_commit` 调用。

```cpp
    for (int i = 0; i < 100; i++) {
        message_list[i] = message_p1 + to_string(i);
    }
    vector<thread> threads;
    for (int i = 0; i < thread_num; i++) {
        threads.emplace_back([i]() {
            for (int nonce_int = nonce_min + i; nonce_int <= nonce_max; nonce_int += thread_num) {
                auto nonce = hex_to_bytes((stringstream() << hex << setw(8) << setfill('0') << nonce_int).str());
                for (const auto &message : message_list) {
                    _create_commit(message, nonce);
                }
            }
        });
    }
    for (auto &t : threads) {
        t.join();
    }
```

不过最后发现好像多线程是多余的，把线程数改为1反而更快(
```sh
$ ./crack
Found! message: flag73, nonce: 00000029, commit: d62cc82e34b963db7ae121557d6fe4d3c0f7fc383ab309b352e750dffcd2c9d5
Cracking completed in 4 ms
```

## 二、ElGamal同态

### 程序编译
```sh
#bin/bash
# PATH=./02
comple.sh
```

### 程序运行
```sh
$ ./elgamal
=== ElGamal加密算法演示 ===
生成安全1024位密钥参数...
公钥 (1024位素数 p): p: E99AAE38B52C9F06B0E417DE70D7D4735237ADA8F68F67E527903D02B9BA106B8829A74E5324588B32E5DCDE4C25AEA2E7E790FD91569978C52029FEA71C4E4355863A5A112E8CAD898EB0CD6C7990024E3A18B0122CF1A3126CA4C3834E78D1AC6B451252AC27E971720BD5B3F84CEA6FB07440D8BE8BD95E8992157E6C7EC7
g: 157D9054C36726005069F4AA804527B6BE13ED2C1A015E7516C432CD923084F5B3879632DB4C2BC4D642312757B997647CE605E45AE8CB7180DCE504B80549ECE794924145D0960D4170D56D3AA25C310E9747DEC522BF3475D549A37C6BB370A75ADF6FEBEC6224B1A8C638B3F4601372859682FB20D39E7E3F5E27140804CF
y: 2DF42288A12363069FB862219FBD495AE4ECE842FE14B298FF52148B0591F11071114E582C711E69922D2551FF07F33BE42E90B06A2AE636D1A4837A28F975AB9938F6C45080E0ADA6DAFFB142671F3284610E4C471D6BCC1D04D1CBBEC8A519D248AB718E2AC36B50727B97F1F1F321B6846366F4909346567E792B93EC199B
私钥 (x值 - 为安全起见部分显示): x: 1E5C89CE707E80E094C9EB3048CE6B958BFDC23CF50E61B...[为安全起见已截断]

=== 加密解密演示 ===
原始消息: 26306
密文: (CE023F282560F29F13BF40A793FAF16E34C93BB488D52599341745D4D1A2312FD7AE8B351CD358EFD30FEC9C946989022252DC2BD02D767157E0B8B483BC9BDBC898040899D390C6FCBA88AB2689A3F57C5AFAD68A6AAC3713A21256E3F26CA74170F22D7C41F5696FC0086B1850AB13D4E4BC3A7EA42DFDFDA7135A6C433AAB, 4145A3A2EEEB892A49640F51C5708F555EDBC1011F6E2D2F85E60DA2053C0907491DB6E18E75B3154AB100710E7B2C6C6137742B4E21673CDE5222F41F1DFB3EB05326E57BD73461D5E2126F151B9364E0DEEB4078DD0616B37E21D773EB495EDC5A5925B7F22DF7DDFA66870262812F1A8C7F7AB1552B45B4DD0294587BCD53)
解密结果: 26306
加解密验证: 成功

=== ElGamal同态乘法演示 ===
加密消息 m1 = 60956
加密消息 m2 = 52431
加密消息 m3 = 38481
密文 c1 = (9E5CC62DA4F3A3715080BAECA63B123A36A393CA176A79AA7502E31FE4F7018FC7346523DD6142B9E7EB379D821DF0DB53DCB911DDC4F4491DC9F8EF6297B6504E63159434953BECEBB91CD6D47C622C2EC2F044A8554D1E6608862E136D7BBC197633F896F5906F3C23559080606CA3C2035853E261AA81B017003C54D9621E, 0127158E19697481516FC276AC9F3599897AA7B6EFE8FA200B36764316EE70E34AE8BF3122C14BB8607265F96F61A90B1F2AF616DB4CBC1028BFC7E3FE65FF27963A2BE564687F225F3C592B14B20DCCB5A65E1308FC339B8FAA3CA8F2D0330CD8E6260A2D0EE0E3E52C82D5D2E4854FCD600EC3BD1C9FC0C622953C146F681C)
密文 c2 = (7E1F964580245352B23C4EA8155220075A91BC46F9CB7AB188C9DFBDEC4BE8FF24BCC9C75C5040F46EE12A2152CB24BB04505FCBEF8608471FBED8EB943241C773582DAA0E04A75E25B838F6D2FFE255AC81EFB9077B7DC2BA89103BEFB1734C032F9A136FDF4D9675D5C2A597DF66170B7AB863E3895598C212DD0FCE0F5E89, 89550E021EA964C8D559C464ACC406D89DCF05577F5F2A5C1E581709C21CE69FBDFD58776639989E65D707B60F51AD4583ADB040CEE13570A789D7BFCD91D19A4BA469BB28BABB06460B1C60ECCDC19342D630AD4F183CFA6590BBF8B9E9610289F056BA1367B7830790E6C60558A07C451C0F1D18B9A82CADCC9CE4BC722452)
密文 c3 = (36678909F791EC8FFE8ABDCD78120340B1DBF6553949C154C6313BBF6BA43B20B8DBACB4277EBCE65EB3AF6DF945838FC8B585A4D116FD691F303A8704ACFE01641531F18CE3276F6D93365B07ED7A1BC62B42707DD706EB48A06B476842DFD736DC0CDA06BF255AC90995ACB6E4C4D486A59A2CDD82EC43AED529BA6B9C30C0, A3A2CB6DF9EC3B9A3F8B0040F804D5D1D13A42CAF72C8865E615AB28AD5E6A86688791D01CA6D638EAE89F0E424B18E14BFCE64C462941CBB15677D15C77B2D749EE78D00C6D1B7E413419A4AEAB908097AF19F84E3CD19F7CE584DF2EE2A89347806ECDD3BB53AD749B02AE29554C8FCB5B3420F36DA7446DD5D721783E05BF)
同态乘法结果 c1*c2 = (B399B050E16C1B16EA2F93959686C4E7ABA85A07BEB4A226D5CFB8557958702F6DA9F9E62B9C843A1321709F9B13E40D7203CA82D02FC0FFA6E58BF99EF3C6EC947EE257C5E324A49587F0E9161DC2B7CF5BEEA90A55A21DF87F98EF03B6D5A2E44A9BEA8B26E32BB4E4305258E1A04EC05DFE27280502490143FD889BFB81B6, 7C04C06478E9D300193324C10CA3DFCFFD2149D5B7F72D97B6F4F547AE15718AD4BEEB74516F2D7C59A5B555ABF525C271778D8BF4943D74FC708B528A021FE104A1615DF120692B9B0A6CB9DC8E76F83EA527F95678C396D3890E35BE9097C45312842EAB203D46093065F375B323A0A0313199425170CB4F6EC63561F7E8EF)
解密结果 = -1098983260
明文乘积 m1*m2 = -1098983260
验证结果 正确
同态乘法结果 c3*(c1*c2) = (AB8B6FBECEF98AF95840AABA55C7D472FEEB3D386A330BE12287EC1BF5669603CBAF035814B2AEF74C46C16A8A11153F45778C027C9CA24C4321162D20F4B01C083BEDC2425AAAB19743AA72500EFF31AAB183993666540736BA26B530C88AED0D75064BC9F4C63B758CA751F6FAAA605733177E516633AFE29449FE36640984, 029F9EB51F9E2D83B39A47B10BB7B4597342E9081B0B2A7EEFD8045577158A34B9357AA5160DF21994FD3120EE8B735522625CFBB0CCC9DE119708B9FA3E84E001FB2A4CB323CD5E63619D4ADFDE859B699F97CF09F48F6FC8B3E92FABE536D3D4EC5F03EC06E4B098ECAE832C8629996AD2FDBA7553E3CAE343FBB806769979)
解密结果 = -1726831644
明文乘积 m3*(m1*m2) = -1726831644
验证结果 正确
```
### 具体实现

1. 群参数生成
这里主要使用的是  `openssl` 中的 `BN_generate_prime_ex` 生成质数
```cpp
void ElGamal::generate_secure_key_parameters() {
    // 1. 生成素数 p = 2q + 1
    BIGNUM *q = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create BN_CTX");
    }

    BIGNUM *candidate_p = BN_new();
    BIGNUM *two = BN_new();
    BN_set_word(two, 2);

    while (true) {
        // 生成 (bits-1) 位的素数 q
        if (!BN_generate_prime_ex(q, 1023, 0, NULL, NULL, NULL)) {
            throw std::runtime_error("Failed to generate prime q");
        }

        // 计算 p = 2q + 1
        BN_mul(candidate_p, q, two, ctx); // candidate_p = 2 * q
        BN_add(candidate_p, candidate_p, BN_value_one()); // candidate_p = 2 * q + 1

        // 检查 p 是否为素数
        if (BN_check_prime(candidate_p, ctx, NULL)) {
            break;
        }
    }

    // 将结果赋值给 p
    BN_copy(p, candidate_p);

    // 2. 选取生成元 g
    BIGNUM *h = BN_new();
    BIGNUM *exp = BN_new();
    BN_set_word(exp, 2);

    while (true) {
        // 生成随机数 h ∈ [2, p-1]
        BN_rand_range(h, p);
        if (BN_cmp(h, BN_value_one()) <= 0) continue;

        // g = h^2 mod p
        BN_mod_exp(g, h, exp, p, ctx);
        if (BN_cmp(g, BN_value_one()) != 0) break;
    }

    // 3. 生成私钥 x ∈ [1, q-1]
    BIGNUM *q_minus_1 = BN_new();
    BN_sub(q_minus_1, q, BN_value_one());
    BN_rand_range(x, q_minus_1);
    BN_add(x, x, BN_value_one()); // 确保 x ∈ [1, q-1]

    // 4. 计算公钥 y = g^x mod p
    BN_mod_exp(y, g, x, p, ctx);

    // 清理内存
    BN_free(candidate_p);
    BN_free(two);
    BN_free(h);
    BN_free(exp);
    BN_free(q_minus_1);
    BN_CTX_free(ctx);
}
```

2. 随机数生成
这里由于只要求生成int16，故使用了cpp的内置库`random`
```cpp
std::default_random_engine generator(static_cast<unsigned>(time(0)));
std::uniform_int_distribution<int> distribution(1, 1<<16);  
int generate_random_message() {
    return distribution(generator);
}
```

3. elgamal加密
```cpp
ElGamalCiphertext ElGamal::encrypt(int message)
{
    BIGNUM *m = BN_new();
    BN_set_word(m, message);

    BIGNUM *k = BN_new();
    BIGNUM *p_minus_2 = BN_new();
    BN_sub(p_minus_2, p, BN_value_one());
    BN_sub(p_minus_2, p_minus_2, BN_value_one()); // p-2
    BN_rand_range(k, p_minus_2); // k ∈ [1, p-2]
    BN_add(k, k, BN_value_one());

    // c1 = g^k mod p
    BIGNUM *c1 = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    BN_mod_exp(c1, g, k, p, ctx);

    // c2 = m * y^k mod p
    BIGNUM *y_k = BN_new();
    BN_mod_exp(y_k, y, k, p, ctx);
    BIGNUM *c2 = BN_new();
    BN_mod_mul(c2, m, y_k, p, ctx);

    return ElGamalCiphertext(p, g, y, c1, c2);
}
```

4. 密文同态乘
```cpp
ElGamalCiphertext operator*(const ElGamalCiphertext &other) const {
    if (BN_cmp(this->p, other.p) != 0 || BN_cmp(this->g, other.g) != 0 || BN_cmp(this->y, other.y) != 0) {
        throw std::invalid_argument("Cannot multiply ciphertexts with different parameters.");
    }
    ElGamalCiphertext result;
    BN_CTX *ctx = BN_CTX_new();
    BN_mod_mul(result.c1, this->c1, other.c1, this->p, ctx);
    BN_mod_mul(result.c2, this->c2, other.c2, this->p, ctx);
    BN_copy(result.p, this->p);
    BN_copy(result.g, this->g);
    BN_copy(result.y, this->y);
    BN_CTX_free(ctx);
    return result;
}
```

5. ElGamal解密
```cpp
int ElGamal::decrypt(const ElGamalCiphertext &ciphertext)
{
    BIGNUM *s = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    BN_mod_exp(s, ciphertext.c1, x, p, ctx); // s = c1^x mod p
    BIGNUM *s_inv = BN_new();
    BN_mod_inverse(s_inv, s, p, ctx); // s_inv = s^(-1) mod p
    BIGNUM *m = BN_new();
    BN_mod_mul(m, ciphertext.c2, s_inv, p, ctx); // m = c2 * s_inv mod p
    int result = BN_get_word(m);

    return result;
}
```

## 三、Paillier同态

### 程序编译
```sh
#bin/bash
# PATH=./03
comple.sh
```

### 程序运行
```sh
$ ./paillier
=== Paillier 同态加密演示 ===
创建Paillier实例...
生成密钥...

密钥参数信息:
质数 p = 89701845049120985604820749108622736471399677926133001874803654653108764534139
质数 q = 94930460114441734396746351012961500705929327615513382116284407797329418265611
模数 n = 8515437423627412485128612401199708951021993617238075246141148954168372209695644261339851307723098031910707744658669718540313328257661503343962057779193929

密钥生成完成
加密消息: 962, 222, 697
解密消息...
解密结果: 962, 222, 697
执行同态加法...
同态加法结果 c1 + c2 = 41E35A5638425EA3B42797650439E2FBDCE1489F620DCCCE0C7388F6A493B21AE6FA0FFBEB7D66118885D4BA0D46722CC8C0B34037F93F14EDFCFDC1C0C583C3D905DC7AF671D76F8187C1EAC32AAC67944D4546D7BEDC470D01114207FF788662B3941DFB43ED0FFBC207864C056B9D898879569D57964F5667D747C588DCCB
解密结果 = 1184
明文相加 = 1184
验证结果 正确
执行同态加法...
同态加法结果 c1 + c2 + c3 = 5FCBD4D64CA36DD04860067711666294690443E5CC180E0B682E32C02B4A7092CCB480A26A37AF1E392D89F52042C1431404FC04168486BC6C871386C996AA8179D7059BDDE48571F393CA86881987C5F4C4B3AEF57F1220BCB3188FFBF2AD42F4E99190092D1CA02D0FAF19F02333C0A5AB0DF6F449E93D47E7F3FA142F63F2
解密结果 = 1881
明文相加 = 1881
验证结果 正确
执行同态数乘...
同态数乘结果 (c1 + c2 + c3) * a = 3FBAC55F6F14F99E5B63A3328888209CE4181EC708324E9750C5323423CA8185B7EACEDA6EF52765703ECFDB0ED0DC33959A1E789AD95453A5E9D310EE878A0B7F0CC1207AE2986F47F192D6659504D9A50279C1C373454F7C8311602B16099C320A52968BB0256A70341885E35FB37108614D3DB8B30F0FC59458A7FB6A375B
解密结果 = 972477
明文数乘 = 972477
验证结果 正确
```

### 具体实现

1. 密钥生成
这里直接用了课上讲的优化过后的版本，取 $g = n + 1$。
```cpp
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
```

2. 加密
这里由于使用优化后的`g`，故加密从 $c = g^m * r^n mod n^2$ 简化为 $c = (1 + m*n) * r^n mod n^2$
```cpp
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
```

3. 同态加
```cpp
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
```

4. 同态数乘
```cpp
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
```

5. 解密
```cpp
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
```