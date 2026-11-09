// 命令行：zhcipher enc|dec [-k 数字密钥] [-c 密码表文件] [-i 输入文件] [-o 输出文件] [--verify]
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>

#include "zh_crypto.hpp"

static void usage() {
    std::cerr <<
        "用法：\n"
        "  zhcipher enc [选项]    加密，输出古风密文\n"
        "  zhcipher dec [选项]    解密\n"
        "选项：\n"
        "  -k, --key <数字>        数字密钥（省略则交互输入，避免留在 shell 历史里）\n"
        "  -c, --codebook <文件>   密码表（64～1024 字，可以有重复；UTF-8 文本文件；省略则交互输入）\n"
        "  -i, --in <文件>         输入文件（省略则读标准输入，Ctrl-D 结束）\n"
        "  -o, --out <文件>        输出文件（省略则写标准输出）\n"
        "      --verify            解密时在 stderr 报告校验是否通过\n"
        "交互输入顺序：数字密钥 -> 密码表 -> 原文/密文\n";
}

static std::string read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("无法读取文件：" + path);
    return std::string(std::istreambuf_iterator<char>(f), {});
}

int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 2; }
    std::string mode = argv[1];
    if (mode != "enc" && mode != "dec") { usage(); return 2; }

    std::string key, codebook_path, in_path, out_path;
    bool verify = false;
    for (int i = 2; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&]() -> std::string {
            if (i + 1 >= argc) throw std::invalid_argument("选项缺少参数：" + a);
            return argv[++i];
        };
        try {
            if (a == "-k" || a == "--key") key = next();
            else if (a == "-c" || a == "--codebook") codebook_path = next();
            else if (a == "-i" || a == "--in") in_path = next();
            else if (a == "-o" || a == "--out") out_path = next();
            else if (a == "--verify") verify = true;
            else { usage(); return 2; }
        } catch (const std::exception& e) {
            std::cerr << "错误：" << e.what() << "\n";
            return 2;
        }
    }

    try {
        if (key.empty()) {
            std::cerr << "数字密钥：";
            std::getline(std::cin, key);
        }
        if (key.size() < 16) std::cerr << "提示：数字密钥少于 16 位，容易被穷举。\n";

        std::string codebook;
        if (!codebook_path.empty()) {
            codebook = read_file(codebook_path);
        } else {
            std::cerr << "密码表：";
            std::getline(std::cin, codebook);
        }
        auto info = zhc::codebook_info(codebook);
        if (info.distinct < 64)
            std::cerr << "提示：密码表里不重复的字只有 " << info.distinct << " 个，保护作用很弱。\n";

        std::string input;
        if (!in_path.empty()) {
            input = read_file(in_path);
        } else {
            std::cerr << (mode == "enc" ? "原文（结束请按 Ctrl-D）：\n" : "密文（结束请按 Ctrl-D）：\n");
            input.assign(std::istreambuf_iterator<char>(std::cin), {});
            if (mode == "enc") {  // 去掉终端输入末尾那一个换行
                if (!input.empty() && input.back() == '\n') input.pop_back();
                if (!input.empty() && input.back() == '\r') input.pop_back();
            }
        }

        std::string output;
        if (mode == "enc") {
            output = zhc::encrypt(input, key, codebook);
        } else {
            auto r = zhc::decrypt(input, key, codebook);
            output = r.text;
            if (verify) std::cerr << (r.authentic ? "校验通过\n" : "校验未通过：数字密钥或密码表不对，或密文被改动\n");
        }

        if (out_path.empty()) {
            std::cout << output;
            if (mode == "dec") std::cout << "\n";
        } else {
            std::ofstream(out_path, std::ios::binary) << output;
        }
    } catch (const std::exception& e) {
        std::cerr << "错误：" << e.what() << "\n";
        return 1;
    }
    return 0;
}
