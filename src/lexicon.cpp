// 词库数据与校验（组合式词库）。
//
// 一句诗由若干"槽位"拼成，每个槽位从一个固定大小的词池里选一个词，池大小是 2 的幂，
// 选中某个词就恰好携带若干位数据：
//   五言：A2 + V1 + (B2 | R2)          例：寒鸦 栖 古山
//   七言：C2 + A2 + V1 + (B2 | R2)     例：秋深 寒鸦 栖 古山
// 每首诗四句，第 2、4 句末尾用 R2（同一韵部），第 1、3 句末尾用 B2。
//
// 池的大小与携带位数：C2 64（6 位）、A2 128（7 位）、V1 64（6 位）、B2 128（7 位）、R2 64（6 位）。
// 双字词池用"修饰字 × 名词字"组合生成，所以词库很大、容易检查：
//   A2 = 16 个修饰字 × 8 个名词字；B2 = 16 × 8；C2 = 8 个前缀 × 8 个后缀；R2 = 8 个修饰字 × 8 个韵脚字。
// 解码时靠"主题"和"韵部"识别词池，因此：
//   A2 的名词字、C2 的前缀字在各主题之间不能重复；R2 的韵脚字在各韵部之间不能重复。
// 这些约束在程序启动时自动检查，不满足会抛 std::logic_error。
#include "lexicon.hpp"

#include <stdexcept>

#include "utf8.hpp"

namespace zhc {
namespace {

// 动词：所有主题共用的 48 个基础动词 + 每个主题自己的 16 个
const char* kBaseVerbs = "照映满落飞过入横卧栖啼鸣浮沉凝临倚对依绕环连接抱锁吞吐涌奔泻穿通拥隐藏渡望忆思随归送别离惜愁叹盼";

struct RawTheme {
    const char *c2_prefix, *c2_suffix, *a2_mod, *a2_noun, *b2_mod, *b2_noun, *verb_extra;
};

const RawTheme kRaw[kThemes] = {
    {// 秋景
     "秋霜寒露菊枫蝉雁", "深来晚尽初半夜晓",
     "寒孤残衰落黄红老暮疏瘦枯冷凉败晚", "鸦雁叶荷蝉桐菊柳",
     "古荒空寒孤远深幽旧残断长野小高疏", "原径塘林渡村桥楼",
     "舞压暗老凋瘦染萧衰凉瑟肃霜黄枯冷"},
    {// 月夜
     "夜更宵月灯星烛漏", "深静半阑明凉久长",
     "清孤明皓素疏微寒淡朗残半新冷秋玉", "月星灯烛萤蛩露影",
     "高空深幽小长西东南北玉碧画绮疏孤", "楼窗阁廊院阶帘檐",
     "悬挂洒移升笼窥斜铺流垂洗浸泊澄皎"},
    {// 山水
     "山江溪湖峡峰涧岩", "中上畔前后头底边",
     "青绿碧白远孤苍幽清飞轻乱野高翠古", "山水泉瀑云松鹤鹭",
     "青碧深幽高远孤苍乱浅寒古飞险大云", "崖涧潭滩洲湾峰谷",
     "耸峙蜿蜒泛漾流飘溅挂倒卷荡翻折劈"},
    {// 送别
     "渡亭驿关津堤路岸", "口头外旁畔边前上",
     "孤远故旧离别游羁相归乡异浮白清长", "客人梦泪愁书笛琴",
     "长远孤旧离别空古客归断尽西南北天", "路亭渡桥舟帆岸关",
     "折赠饯怨泣惊嗟怅悲哀念候迎辞叙留"},
    {// 春景
     "春晴花莺燕柳桃杏", "深来晚初好暖浓盛",
     "红紫新嫩芳绿轻暖垂碧飞娇野细晴小", "花莺燕蝶芽草杏桃",
     "新绿嫩暖小轻高长远深幽古芳碧细疏", "枝园径堤院溪陌楼",
     "醒绽笑染抽拂迎唤戏逐翻簇缀点偎袭"},
    {// 冬雪
     "冬雪冰梅腊岁朔炉", "深来晚尽初寒夜晓",
     "白寒飞冷暖老孤疏瑞残初暮碎深轻晴", "雪梅冰炉雀竹枝酒",
     "雪冰寒孤空冷荒深远古瑶玉暮小长北", "原岭村窗径巷寺桥",
     "覆封积飘凋冻裹披缠扫敲听守傲歇压"},
    {// 田园
     "日午晨田村桑麦农", "中间头边里下后外",
     "老小耕牧野炊青黄村田晚柴桑茅竹稚", "牛童犬鸡烟稻麦蛙",
     "田菜稻麦桑瓜豆柴茅村农山溪野竹草", "埂畦舍篱陇塘场家",
     "耕种锄采钓酌弈吟读煮烹牧酿樵栽眠"},
    {// 边塞
     "塞边沙阵营戍城陇", "上外前中头下畔北",
     "胡铁金孤长战寒大羌军古残虎白烽朔", "笳骑旗戈甲弓马鼓",
     "孤古荒大长远雪玉阳燕祁阴辽陇朔胡", "关城营台漠山川原",
     "戍征战驰射卷吹扬烧燃嘶冲破屯卫劈"},
};

// 八个韵部：修饰字（共用）× 韵脚字（互不相同）
// 韵母：an / ang / u / ai / i / ou / eng·ong / a 系
const char* kRhymeMods = "空古孤远深幽旧清";
const char* kRhymeEnds[kRhymes] = {
    "山天烟川田船泉帆",
    "江霜光乡窗阳堂塘",
    "路树渡暮雾露谷户",
    "台苔海埃怀槐钗斋",
    "枝丝池溪西衣旗梯",
    "楼舟洲流秋鸥钩沟",
    "风钟松峰龙虹灯城",
    "花霞沙茶纱崖鸦家",
};

std::vector<std::string> product(const char* first, const char* second) {
    std::vector<std::string> a = utf8_chars(first), b = utf8_chars(second), out;
    for (const auto& x : a)
        for (const auto& y : b) out.push_back(x + y);
    return out;
}

void need(bool ok, const std::string& msg) {
    if (!ok) throw std::logic_error("词库错误：" + msg);
}

void check_size(const std::vector<std::string>& pool, size_t size, const char* name, int group) {
    need(pool.size() == size, std::string(name) + " 主题/韵部 " + std::to_string(group) + " 的池大小应为 " +
                                  std::to_string(size) + "，实际 " + std::to_string(pool.size()));
}

void index_global(const std::vector<std::string>& pool, int group, Lexicon::Rev& rev, const char* name) {
    for (size_t i = 0; i < pool.size(); i++)
        need(rev.emplace(pool[i], std::make_pair(group, static_cast<int>(i))).second,
             std::string(name) + " 全库内重复词：" + pool[i]);
}

void index_local(const std::vector<std::string>& pool, Lexicon::Idx& idx, const char* name) {
    for (size_t i = 0; i < pool.size(); i++)
        need(idx.emplace(pool[i], static_cast<int>(i)).second, std::string(name) + " 主题内重复词：" + pool[i]);
}

Lexicon build() {
    Lexicon L;
    for (int t = 0; t < kThemes; t++) {
        const RawTheme& R = kRaw[t];
        ThemePools& T = L.themes[t];
        T.c2 = product(R.c2_prefix, R.c2_suffix);
        T.a2 = product(R.a2_mod, R.a2_noun);
        T.b2 = product(R.b2_mod, R.b2_noun);
        for (const auto& v : utf8_chars(kBaseVerbs)) T.v1.push_back(v);
        for (const auto& v : utf8_chars(R.verb_extra)) T.v1.push_back(v);
        check_size(T.c2, kPoolC2, "C2", t);
        check_size(T.a2, kPoolA2, "A2", t);
        check_size(T.v1, kPoolV1, "V1", t);
        check_size(T.b2, kPoolB2, "B2", t);
        index_global(T.c2, t, L.c2_rev, "C2");
        index_global(T.a2, t, L.a2_rev, "A2");
        index_local(T.v1, L.v1_idx[t], "V1");
        index_local(T.b2, L.b2_idx[t], "B2");
    }
    for (int g = 0; g < kRhymes; g++) {
        L.r2[g] = product(kRhymeMods, kRhymeEnds[g]);
        check_size(L.r2[g], kPoolR2, "R2", g);
        index_global(L.r2[g], g, L.r2_rev, "R2");
    }
    return L;
}

}  // namespace

const Lexicon& lexicon() {
    static const Lexicon L = build();
    return L;
}

}  // namespace zhc
