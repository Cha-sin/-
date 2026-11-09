// 诗句编码器自测（不依赖 libsodium）。
#include <cstdio>
#include <random>
#include <stdexcept>

#include "../src/lexicon.hpp"
#include "../src/poem_codec.hpp"

using namespace zhc;

static int fails = 0;
#define CHECK(c, msg) do { if (!(c)) { std::printf("FAIL: %s\n", msg); fails++; } } while (0)

int main() {
    lexicon();  // 触发词库校验
    std::mt19937 rng(12345);
    for (size_t n : {0, 1, 2, 5, 22, 23, 100, 126, 127, 128, 129, 1000, 16383, 16384, 20000, 65535}) {
        std::vector<uint8_t> d(n);
        for (auto& b : d) b = rng() & 0xFF;
        std::string poem = poem_encode(d);
        CHECK(poem_decode(poem) == d, "round trip");
        // 打乱标点/换行后仍可解码
        std::string alt;
        for (char c : poem) alt += (c == '\n') ? ' ' : c;
        CHECK(poem_decode(alt) == d, "round trip with reformatted whitespace");
    }
    // 篡改检测：换掉一个词，要么报错，要么结果不同，绝不能静默得到原数据
    std::vector<uint8_t> d(40);
    for (auto& b : d) b = rng() & 0xFF;
    std::string poem = poem_encode(d);
    std::string bad = poem;
    bad.replace(0, 6, "孤雁");  // 破坏开头
    bool ok = true;
    try { ok = (poem_decode(bad) == d); } catch (const std::exception&) { ok = false; }
    CHECK(!ok, "tamper detected");
    // 长度统计
    std::vector<uint8_t> blob(28 + 9);  // 约等于 3 个汉字的密文
    std::string p2 = poem_encode(blob);
    std::printf("37 字节 -> %zu 字节 UTF-8（%zu 个汉字）\n", p2.size(), p2.size() / 3);
    std::vector<uint8_t> sample(40);
    for (auto& b : sample) b = rng() & 0xFF;
    std::printf("---- 示例 ----\n%s", poem_encode(sample).c_str());
    std::printf(fails ? "失败 %d 项\n" : "全部通过\n", fails);
    return fails ? 1 : 0;
}
