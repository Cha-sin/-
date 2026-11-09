// 加密层自测（需要 libsodium）。
#include <algorithm>
#include <cstdio>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

#include "../src/zh_crypto.hpp"

using namespace zhc;
static int fails = 0;
#define CHECK(c, msg) do { if (!(c)) { std::printf("FAIL: %s\n", msg); fails++; } } while (0)

static std::string make_codebook(unsigned seed, int n = 1024) {
    // 取若干个互不相同的汉字（U+4E00 起，打乱）
    std::vector<uint32_t> cps;
    for (uint32_t c = 0x4E00; c < 0x4E00 + 3000; c++) cps.push_back(c);
    std::mt19937 rng(seed);
    std::shuffle(cps.begin(), cps.end(), rng);
    std::string s;
    for (int i = 0; i < n; i++) {
        uint32_t c = cps[i];
        s += static_cast<char>(0xE0 | (c >> 12));
        s += static_cast<char>(0x80 | ((c >> 6) & 0x3F));
        s += static_cast<char>(0x80 | (c & 0x3F));
    }
    return s;
}

int main() {
    std::string cb = make_codebook(1), cb2 = make_codebook(2);
    std::string key = "3141592653589793", key2 = "3141592653589794";
    std::string msg = "Hello, 世界！明天 10:30 开会。";

    std::string poem = encrypt(msg, key, cb);
    std::printf("%s\n", poem.c_str());

    auto ok = decrypt(poem, key, cb);
    CHECK(ok.authentic && ok.text == msg, "correct key round trip");

    auto bad1 = decrypt(poem, key2, cb);
    CHECK(!bad1.authentic && bad1.text != msg, "wrong numeric key gives wrong output");
    auto bad2 = decrypt(poem, key, cb2);
    CHECK(!bad2.authentic && bad2.text != msg, "wrong codebook gives wrong output");
    std::printf("错误数字密钥：%s\n错误密码表：%s\n", bad1.text.c_str(), bad2.text.c_str());

    std::string zh = "阿辽沙，别害怕，火车在上面停下了，他一笑天就亮了。";
    auto zr = decrypt(encrypt(zh, key, cb), key, cb);
    CHECK(zr.authentic && zr.text == zh, "pure Chinese round trip (GB18030)");
    auto er = decrypt(encrypt("", key, cb), key, cb);
    CHECK(er.authentic && er.text.empty(), "empty message round trip");
    // 短密码表（256 字），并且允许有重复的字
    std::string cb256 = make_codebook(3, 256);
    std::string dup = cb256.substr(0, 246 * 3) + cb256.substr(0, 10 * 3);   // 后 10 个字重复前 10 个字
    auto info = codebook_info(dup);
    CHECK(info.length == 256 && info.distinct == 246, "codebook_info counts duplicates");
    auto dr = decrypt(encrypt(msg, key, dup), key, dup);
    CHECK(dr.authentic && dr.text == msg, "256-char codebook with duplicates round trip");
    std::string rev;   // 同样的字、顺序反过来，应当解不开
    for (int i = 255; i >= 0; i--) rev += dup.substr(i * 3, 3);
    auto rr = decrypt(encrypt(msg, key, dup), key, rev);
    CHECK(!rr.authentic && rr.text != msg, "same characters in a different order is a different codebook");
    bool threw = false;
    try { encrypt(msg, key, make_codebook(4, 63)); } catch (const std::invalid_argument&) { threw = true; }
    CHECK(threw, "codebook shorter than 64 is rejected");
    CHECK(encrypt(msg, key, cb) != poem, "random nonce -> different ciphertext each time");
    std::printf(fails ? "失败 %d 项\n" : "全部通过\n", fails);
    return fails ? 1 : 0;
}
