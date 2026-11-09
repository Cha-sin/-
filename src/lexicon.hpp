#pragma once
// 内置古风词库。结构见 lexicon.cpp 顶部说明。
#include <array>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace zhc {

constexpr int kThemes = 8;  // 秋景 月夜 山水 送别 春景 冬雪 田园 边塞
constexpr int kRhymes = 8;  // 八个韵部

// 各词池大小，以及选一个词携带的位数（大小 = 2^位数）
constexpr int kPoolC2 = 64, kBitsC2 = 6;    // 状语/时地框架，2 字——仅七言使用
constexpr int kPoolA2 = 128, kBitsA2 = 7;   // 主语意象，2 字
constexpr int kPoolV1 = 64, kBitsV1 = 6;    // 动词，1 字
constexpr int kPoolB2 = 128, kBitsB2 = 7;   // 宾语/处所，2 字——用于不押韵的句子
constexpr int kPoolR2 = 64, kBitsR2 = 6;    // 押韵句句尾，2 字，每个韵部一池

struct ThemePools {
    std::vector<std::string> c2, a2, v1, b2;
};

struct Lexicon {
    std::array<ThemePools, kThemes> themes;
    std::array<std::vector<std::string>, kRhymes> r2;
    // 全库唯一的词：词 -> (主题或韵部编号, 池内下标)，用来识别一首诗的主题和韵部
    using Rev = std::unordered_map<std::string, std::pair<int, int>>;
    Rev c2_rev, a2_rev, r2_rev;
    // 主题内唯一的词：词 -> 池内下标
    using Idx = std::unordered_map<std::string, int>;
    std::array<Idx, kThemes> v1_idx, b2_idx;
};

// 首次调用时构建并校验词库，失败抛 std::logic_error。
const Lexicon& lexicon();

}  // namespace zhc
