#pragma once
// 最小 UTF-8 工具：按码点切分字符串。
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace zhc {

// 把 UTF-8 字符串切成单个码点（每个元素是该码点的 UTF-8 字节串）。
inline std::vector<std::string> utf8_chars(const std::string& s) {
    std::vector<std::string> out;
    size_t i = 0;
    while (i < s.size()) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        size_t n = c < 0x80 ? 1 : (c >> 5) == 0x6 ? 2 : (c >> 4) == 0xE ? 3 : (c >> 3) == 0x1E ? 4 : 0;
        if (n == 0 || i + n > s.size()) throw std::invalid_argument("输入不是有效的 UTF-8");
        for (size_t k = 1; k < n; k++)
            if ((static_cast<unsigned char>(s[i + k]) >> 6) != 0x2) throw std::invalid_argument("输入不是有效的 UTF-8");
        out.emplace_back(s.substr(i, n));
        i += n;
    }
    return out;
}

// 是否为常用汉字区 U+4E00..U+9FFF 的单个字。
inline bool is_cjk(const std::string& ch) {
    if (ch.size() != 3) return false;
    uint32_t cp = ((static_cast<unsigned char>(ch[0]) & 0x0F) << 12) |
                  ((static_cast<unsigned char>(ch[1]) & 0x3F) << 6) |
                  (static_cast<unsigned char>(ch[2]) & 0x3F);
    return cp >= 0x4E00 && cp <= 0x9FFF;
}

}  // namespace zhc
