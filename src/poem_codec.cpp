#include "poem_codec.hpp"

#include <random>
#include <stdexcept>

#include "lexicon.hpp"
#include "utf8.hpp"

namespace zhc {
namespace {

// 按位读取；数据读完后补随机位（让最后一首诗的剩余槽位不重复、不暴露结尾）。
class BitReader {
public:
    explicit BitReader(const std::vector<uint8_t>& d) : d_(d), total_(d.size() * 8), rng_(std::random_device{}()) {}
    bool exhausted() const { return pos_ >= total_; }
    uint32_t read(int n) {
        uint32_t v = 0;
        for (int i = 0; i < n; i++) {
            uint32_t bit = pos_ < total_ ? (d_[pos_ >> 3] >> (7 - (pos_ & 7))) & 1u : (rng_() & 1u);
            pos_++;
            v = (v << 1) | bit;
        }
        return v;
    }

private:
    const std::vector<uint8_t>& d_;
    size_t total_;
    size_t pos_ = 0;
    std::mt19937 rng_;
};

class BitWriter {
public:
    void write(uint32_t v, int n) {
        for (int i = n - 1; i >= 0; i--) bits_.push_back((v >> i) & 1u);
    }
    const std::vector<uint8_t>& bits() const { return bits_; }

private:
    std::vector<uint8_t> bits_;
};

using Chars = std::vector<std::string>;

std::string join(const Chars& l, size_t from, size_t n) {
    std::string w;
    for (size_t i = 0; i < n; i++) w += l[from + i];
    return w;
}

// 返回词所属的主题/韵部编号。
int group_of(const Lexicon::Rev& rev, const std::string& word, const char* what) {
    auto it = rev.find(word);
    if (it == rev.end()) throw std::runtime_error(std::string("无法识别的词（") + what + "）：" + word);
    return it->second.first;
}

// 返回词在池内的下标，并检查它属于期望的主题/韵部。
int lookup(const Lexicon::Rev& rev, const std::string& word, int group, const char* what) {
    auto it = rev.find(word);
    if (it == rev.end()) throw std::runtime_error(std::string("无法识别的词（") + what + "）：" + word);
    if (it->second.first != group)
        throw std::runtime_error(std::string("词与本首诗的主题/韵部不符（") + what + "）：" + word);
    return it->second.second;
}

// 主题内唯一的词：直接返回池内下标。
int index_of(const Lexicon::Idx& idx, const std::string& word, const char* what) {
    auto it = idx.find(word);
    if (it == idx.end()) throw std::runtime_error(std::string("词不在本首诗主题的词库里（") + what + "）：" + word);
    return it->second;
}

}  // namespace

std::string poem_encode(const std::vector<uint8_t>& data) {
    if (data.size() > 65535) throw std::length_error("数据过长（上限 65535 字节）");
    // 位流 = 变长长度（小于 128 字节只占 1 字节，小于 16384 占 2 字节，其余 3 字节）+ 数据
    std::vector<uint8_t> stream;
    stream.reserve(data.size() + 3);
    size_t len = data.size();
    do {
        uint8_t b = len & 0x7F;
        len >>= 7;
        if (len) b |= 0x80;
        stream.push_back(b);
    } while (len);
    stream.insert(stream.end(), data.begin(), data.end());

    const Lexicon& L = lexicon();
    BitReader br(stream);
    std::string out;
    bool first = true;
    while (!br.exhausted()) {
        // 诗头 7 位：五言/七言 1 位、主题 3 位、韵部 3 位
        bool seven = br.read(1) != 0;
        int theme = static_cast<int>(br.read(3));
        int rhyme = static_cast<int>(br.read(3));
        const ThemePools& T = L.themes[theme];
        if (!first) out += "\n";
        first = false;
        for (int line = 0; line < 4; line++) {
            bool rhyme_line = (line & 1) != 0;
            if (seven) out += T.c2[br.read(kBitsC2)];
            out += T.a2[br.read(kBitsA2)];
            out += T.v1[br.read(kBitsV1)];
            if (rhyme_line)
                out += L.r2[rhyme][br.read(kBitsR2)];
            else
                out += T.b2[br.read(kBitsB2)];
            out += rhyme_line ? "。" : "，";
            if (rhyme_line) out += "\n";
        }
    }
    return out;
}

std::vector<uint8_t> poem_decode(const std::string& text) {
    // 以非汉字字符断句
    std::vector<Chars> lines;
    Chars cur;
    for (const auto& ch : utf8_chars(text)) {
        if (is_cjk(ch)) {
            cur.push_back(ch);
        } else if (!cur.empty()) {
            lines.push_back(cur);
            cur.clear();
        }
    }
    if (!cur.empty()) lines.push_back(cur);
    if (lines.empty() || lines.size() % 4 != 0) throw std::runtime_error("密文格式不对：句数不是 4 的倍数");

    const Lexicon& L = lexicon();
    BitWriter bw;
    for (size_t p = 0; p < lines.size(); p += 4) {
        size_t len = lines[p].size();
        if (len != 5 && len != 7) throw std::runtime_error("密文格式不对：每句应为五言或七言");
        for (size_t k = 1; k < 4; k++)
            if (lines[p + k].size() != len) throw std::runtime_error("密文格式不对：同一首诗的句长不一致");
        bool seven = (len == 7);

        // 主题取自第 1 句句首的词，韵部取自第 2 句句尾的词；其余词必须与之一致
        int theme = group_of(seven ? L.c2_rev : L.a2_rev, join(lines[p], 0, 2), "主题");
        int rhyme = group_of(L.r2_rev, join(lines[p + 1], len - 2, 2), "韵脚");

        bw.write(seven ? 1 : 0, 1);
        bw.write(theme, 3);
        bw.write(rhyme, 3);
        for (size_t k = 0; k < 4; k++) {
            const Chars& l = lines[p + k];
            bool rhyme_line = (k & 1) != 0;
            size_t pos = 0;
            if (seven) {
                bw.write(lookup(L.c2_rev, join(l, pos, 2), theme, "状语"), kBitsC2);
                pos += 2;
            }
            bw.write(lookup(L.a2_rev, join(l, pos, 2), theme, "意象"), kBitsA2);
            pos += 2;
            bw.write(index_of(L.v1_idx[theme], join(l, pos, 1), "动词"), kBitsV1);
            pos += 1;
            if (rhyme_line)
                bw.write(lookup(L.r2_rev, join(l, pos, 2), rhyme, "韵脚"), kBitsR2);
            else
                bw.write(index_of(L.b2_idx[theme], join(l, pos, 2), "处所"), kBitsB2);
        }
    }

    const auto& bits = bw.bits();
    // 读变长长度
    size_t n = 0, pos = 0;
    int shift = 0;
    for (int k = 0;; k++) {
        if (k >= 3) throw std::runtime_error("密文被损坏（长度字段不对）");
        if (bits.size() < pos + 8) throw std::runtime_error("密文过短");
        uint8_t b = 0;
        for (int j = 0; j < 8; j++) b = static_cast<uint8_t>((b << 1) | bits[pos + j]);
        pos += 8;
        n |= static_cast<size_t>(b & 0x7F) << shift;
        shift += 7;
        if (!(b & 0x80)) break;
    }
    if (bits.size() < pos + n * 8) throw std::runtime_error("密文被截断或损坏");
    std::vector<uint8_t> out(n);
    for (size_t i = 0; i < n; i++) {
        uint8_t b = 0;
        for (int j = 0; j < 8; j++) b = static_cast<uint8_t>((b << 1) | bits[pos + i * 8 + j]);
        out[i] = b;
    }
    return out;
}

}  // namespace zhc
