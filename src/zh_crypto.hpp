#pragma once
// 加密层：数字密钥 + 密码表 -> 256 位密钥 -> ChaCha20 加密 + 校验标签 -> 古风诗句。
#include <string>

namespace zhc {

struct DecryptResult {
    std::string text;    // 解密结果（密钥或密码表不对时是"错误结果"，无效字节显示为随机汉字）
    bool authentic;      // Poly1305 标签是否通过（密钥/密码表正确且密文未被篡改）
};

struct CodebookInfo {
    size_t length;    // 密码表字数（空白字符不算）
    size_t distinct;  // 其中互不相同的字数
};

// 密码表应为 64 到 1024 个字，允许重复。返回字数和不重复字数。
// 字数不在范围内抛 std::invalid_argument。
CodebookInfo codebook_info(const std::string& codebook);

// 加密：返回古风诗句密文。明文最多 65535-28 字节。
std::string encrypt(const std::string& plaintext, const std::string& numeric_key, const std::string& codebook);

// 解密：数字密钥或密码表不对时不报错，照常返回（错误的）结果，authentic=false。
// 只有密文本身格式不对（不是本程序生成的诗句）才抛 std::runtime_error。
DecryptResult decrypt(const std::string& poem, const std::string& numeric_key, const std::string& codebook);

}  // namespace zhc
