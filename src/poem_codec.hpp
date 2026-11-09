#pragma once
// 状态式中文编码器：任意字节 <-> 古风诗句。不涉及密钥，算法公开。
#include <cstdint>
#include <string>
#include <vector>

namespace zhc {

// 把字节（最多 65535 字节）编成若干首四句诗。超长抛 std::length_error。
std::string poem_encode(const std::vector<uint8_t>& data);

// 把诗句还原成字节。格式不对或词不在词库里抛 std::runtime_error。
// 标点、换行不影响解码，但必须保留断句（每句之间要有非汉字字符分隔）。
std::vector<uint8_t> poem_decode(const std::string& text);

}  // namespace zhc
