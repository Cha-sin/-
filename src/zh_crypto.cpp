#include "zh_crypto.hpp"

#include <cerrno>
#include <iconv.h>
#include <sodium.h>

#include <algorithm>
#include <array>
#include <numeric>
#include <stdexcept>
#include <unordered_set>
#include <vector>

#include "poem_codec.hpp"
#include "utf8.hpp"

namespace zhc {
namespace {

constexpr size_t kCodebookMin = 64;     // 密码表最少字数（空白不算）
constexpr size_t kCodebookMax = 1024;   // 密码表最多字数；允许有重复的字
constexpr size_t kNonceBytes = 12;  // ChaCha20(IETF) 要求 12 字节 nonce
constexpr size_t kWireNonce = 6;    // 实际随机并写进密文的只有前 6 字节，后 6 字节固定为 0，让密文更短
constexpr size_t kTagBytes = 8;     // 校验标签 8 字节（64 位）

void init_sodium() {
    if (sodium_init() < 0) throw std::runtime_error("libsodium 初始化失败");
}

// 字符编码转换失败：记下出错位置（第几个字节）和系统错误码，方便排查。
struct ConvertError : std::runtime_error {
    size_t pos;
    int err;
    ConvertError(size_t p, int e) : std::runtime_error("字符编码转换失败"), pos(p), err(e) {}
};

// 字符编码转换（用系统自带的 iconv）。
std::string convert(const std::string& in, const char* to, const char* from) {
    iconv_t cd = iconv_open(to, from);
    if (cd == reinterpret_cast<iconv_t>(-1)) throw std::runtime_error("系统缺少字符编码转换支持（iconv）");
    std::string out(in.size() * 4 + 16, '\0');
    char* inp = const_cast<char*>(in.data());
    size_t inleft = in.size();
    char* outp = &out[0];
    size_t outleft = out.size();
    size_t r = iconv(cd, &inp, &inleft, &outp, &outleft);
    if (r != static_cast<size_t>(-1)) r = iconv(cd, nullptr, nullptr, &outp, &outleft);
    int e = errno;
    iconv_close(cd);
    if (r == static_cast<size_t>(-1)) throw ConvertError(in.size() - inleft, e);
    out.resize(out.size() - outleft);
    return out;
}

// 原文先从 UTF-8 转成 GB18030：汉字 2 字节（UTF-8 要 3 字节），英文数字仍是 1 字节，密文因此更短。
// 转回来再核对一遍，保证不会悄悄改掉原文。
std::string to_gb(const std::string& utf8) {
    std::string gb;
    try {
        gb = convert(utf8, "GB18030", "UTF-8");
    } catch (const ConvertError& e) {
        throw std::invalid_argument("原文不是有效的 UTF-8 文本，或含有无法编码的字符（出错位置：第 " +
                                    std::to_string(e.pos + 1) + " 个字节附近，错误码 " + std::to_string(e.err) + "）");
    }
    std::string back;
    try {
        back = convert(gb, "UTF-8", "GB18030");
    } catch (const ConvertError&) {
        throw std::invalid_argument("原文里有字符无法安全编码（转回来时失败）");
    }
    if (back != utf8) {
        size_t i = 0;
        while (i < back.size() && i < utf8.size() && back[i] == utf8[i]) i++;
        throw std::invalid_argument("原文里有字符无法安全编码（第 " + std::to_string(i + 1) + " 个字节附近转回来对不上）");
    }
    return gb;
}

// 由 256 位主密钥派生出两把子密钥：一把加密，一把做校验（BLAKE2b 带密钥，用法即标准的 MAC）。
struct SubKeys {
    std::array<uint8_t, 32> enc, mac;
};
SubKeys split_key(const std::array<uint8_t, 32>& k) {
    static const unsigned char e[] = "zhc-v2-enc", m[] = "zhc-v2-mac";
    SubKeys s;
    crypto_generichash(s.enc.data(), s.enc.size(), e, sizeof e - 1, k.data(), k.size());
    crypto_generichash(s.mac.data(), s.mac.size(), m, sizeof m - 1, k.data(), k.size());
    return s;
}

// 标签 = BLAKE2b(密钥=mac 子密钥, 内容=随机数‖密文) 的前 8 字节
void make_tag(uint8_t out[kTagBytes], const SubKeys& s, const uint8_t* data, size_t n) {
    uint8_t full[32];
    crypto_generichash(full, sizeof full, data, n, s.mac.data(), s.mac.size());
    std::copy(full, full + kTagBytes, out);
    sodium_memzero(full, sizeof full);
}

std::vector<std::string> clean_codebook(const std::string& cb) {
    std::vector<std::string> out;
    for (auto& c : utf8_chars(cb)) {
        if (c == " " || c == "\n" || c == "\r" || c == "\t" || c == "\xE3\x80\x80") continue;
        out.push_back(c);
    }
    if (out.size() < kCodebookMin || out.size() > kCodebookMax)
        throw std::invalid_argument("密码表应为 " + std::to_string(kCodebookMin) + " 到 " + std::to_string(kCodebookMax) +
                                    " 个字（可以有重复的字），当前 " + std::to_string(out.size()) + " 个");
    return out;
}

void check_numeric(const std::string& k) {
    if (k.empty()) throw std::invalid_argument("数字密钥不能为空");
    for (char c : k)
        if (c < '0' || c > '9') throw std::invalid_argument("数字密钥只能包含 0-9");
}

// 数字密钥 --Argon2id--> 种子 --确定性洗牌--> 把密码表里的字重新排列 --BLAKE2b(以种子为密钥)--> 256 位密钥
// 数字密钥决定排列方式，密码表（字和原始顺序）提供内容；两者缺一不可。
std::array<uint8_t, 32> derive_key(const std::string& numeric, const std::vector<std::string>& cb) {
    check_numeric(numeric);
    static const unsigned char salt[crypto_pwhash_SALTBYTES] = {'z', 'h', 'c', '-', 'v', '1', '-', 's',
                                                                 'e', 'e', 'd', '-', 's', 'a', 'l', 't'};
    unsigned char seed[32];
    if (crypto_pwhash(seed, sizeof seed, numeric.data(), numeric.size(), salt, crypto_pwhash_OPSLIMIT_MODERATE,
                      crypto_pwhash_MEMLIMIT_MODERATE, crypto_pwhash_ALG_ARGON2ID13) != 0)
        throw std::runtime_error("密钥派生失败（内存不足？）");

    // 由种子生成确定性随机流，做 Fisher-Yates 洗牌（拒绝采样，无偏）
    std::vector<uint8_t> rnd(16384);
    randombytes_buf_deterministic(rnd.data(), rnd.size(), seed);
    size_t off = 0;
    auto next32 = [&]() -> uint32_t {
        if (off + 4 > rnd.size()) throw std::runtime_error("随机流耗尽");
        uint32_t v = rnd[off] | (rnd[off + 1] << 8) | (rnd[off + 2] << 16) | (static_cast<uint32_t>(rnd[off + 3]) << 24);
        off += 4;
        return v;
    };
    auto uniform = [&](uint32_t n) -> uint32_t {
        const uint64_t range = 1ULL << 32;
        const uint64_t limit = range - (range % n);
        uint32_t v;
        do { v = next32(); } while (v >= limit);
        return v % n;
    };
    const size_t n = cb.size();
    std::vector<uint32_t> idx(n);
    std::iota(idx.begin(), idx.end(), 0u);
    for (size_t i = n - 1; i >= 1; i--) std::swap(idx[i], idx[uniform(static_cast<uint32_t>(i + 1))]);

    std::string s = "zhc-v3|" + std::to_string(n) + "|";
    for (size_t i = 0; i < n; i++) s += cb[idx[i]];

    std::array<uint8_t, 32> key;
    crypto_generichash(key.data(), key.size(), reinterpret_cast<const unsigned char*>(s.data()), s.size(), seed,
                       sizeof seed);
    sodium_memzero(seed, sizeof seed);
    sodium_memzero(&s[0], s.size());
    sodium_memzero(rnd.data(), rnd.size());
    return key;
}

// 把"错误结果"整理成看起来像中文文本的乱码：每 2 个字节换成 1 个常用汉字（GB2312 一级字，共 3755 个），
// 并按字节值夹入少量逗号、句号。长度与真实的中文明文相近，选字只由字节决定。
std::string render_garbage(const std::vector<uint8_t>& b) {
    static const std::vector<std::string> table = utf8_chars(
        u8"啊阿埃挨哎唉哀皑癌蔼矮艾碍爱隘鞍氨安俺按暗岸胺案肮昂盎凹敖熬翱袄傲奥懊澳芭捌扒叭吧笆八疤巴拔跋靶把耙坝霸罢爸白柏百摆佰败拜稗斑班搬扳般颁板版扮拌伴瓣半办绊邦帮梆榜膀绑棒磅蚌镑傍谤苞胞包褒剥薄雹保堡饱宝抱报暴豹鲍爆杯碑悲卑北辈背贝钡倍狈备惫焙被奔苯本笨崩绷甭泵蹦迸逼鼻比鄙笔彼碧蓖蔽毕毙毖币庇痹闭敝弊必辟壁臂避陛鞭边编贬扁便变卞辨辩辫遍标彪膘表鳖憋别瘪彬斌濒滨宾摈兵冰柄丙秉饼炳病并玻菠播拨钵波博勃搏铂箔伯帛舶脖膊渤泊驳捕卜哺补埠不布步簿部怖擦猜裁材才财睬踩采彩菜蔡餐参蚕残惭惨灿苍舱仓沧藏操糙槽曹草厕策侧册测层蹭插叉茬茶查碴搽察岔差诧拆柴豺搀掺蝉馋谗缠铲产阐颤昌猖场尝常长偿肠厂敞畅唱倡超抄钞朝嘲潮巢吵炒车扯撤掣彻澈郴臣辰尘晨忱沉陈趁衬撑称城橙成呈乘程惩澄诚承逞骋秤吃痴持匙池迟弛驰耻齿侈尺赤翅斥炽充冲虫崇宠抽酬畴踌稠愁筹仇绸瞅丑臭初出橱厨躇锄雏滁除楚础储矗搐触处揣川穿椽传船喘串疮窗幢床闯创吹炊捶锤垂春椿醇唇淳纯蠢戳绰疵茨磁雌辞慈瓷词此刺赐次聪葱囱匆从丛凑粗醋簇促蹿篡窜摧崔催脆瘁粹淬翠村存寸磋撮搓措挫错搭达答瘩打大呆歹傣戴带殆代贷袋待逮怠耽担丹单郸掸胆旦氮但惮淡诞弹蛋当挡党荡档刀捣蹈倒岛祷导到稻悼道盗德得的蹬灯登等瞪凳邓堤低滴迪敌笛狄涤翟嫡抵底地蒂第帝弟递缔颠掂滇碘点典靛垫电佃甸店惦奠淀殿碉叼雕凋刁掉吊钓调跌爹碟蝶迭谍叠丁盯叮钉顶鼎锭定订丢东冬董懂动栋侗恫冻洞兜抖斗陡豆逗痘都督毒犊独读堵睹赌杜镀肚度渡妒端短锻段断缎堆兑队对墩吨蹲敦顿囤钝盾遁掇哆多夺垛躲朵跺舵剁惰堕蛾峨鹅俄额讹娥恶厄扼遏鄂饿恩而儿耳尔饵洱二贰发罚筏伐乏阀法珐藩帆番翻樊矾钒繁凡烦反返范贩犯饭泛坊芳方肪房防妨仿访纺放菲非啡飞肥匪诽吠肺废沸费芬酚吩氛分纷坟焚汾粉奋份忿愤粪丰封枫蜂峰锋风疯烽逢冯缝讽奉凤佛否夫敷肤孵扶拂辐幅氟符伏俘服浮涪福袱弗甫抚辅俯釜斧脯腑府腐赴副覆赋复傅付阜父腹负富讣附妇缚咐噶嘎该改概钙盖溉干甘杆柑竿肝赶感秆敢赣冈刚钢缸肛纲岗港杠篙皋高膏羔糕搞镐稿告哥歌搁戈鸽胳疙割革葛格蛤阁隔铬个各给根跟耕更庚羹埂耿梗工攻功恭龚供躬公宫弓巩汞拱贡共钩勾沟苟狗垢构购够辜菇咕箍估沽孤姑鼓古蛊骨谷股故顾固雇刮瓜剐寡挂褂乖拐怪棺关官冠观管馆罐惯灌贯光广逛瑰规圭硅归龟闺轨鬼诡癸桂柜跪贵刽辊滚棍锅郭国果裹过哈骸孩海氦亥害骇酣憨邯韩含涵寒函喊罕翰撼捍旱憾悍焊汗汉夯杭航壕嚎豪毫郝好耗号浩呵喝荷菏核禾和何合盒貉阂河涸赫褐鹤贺嘿黑痕很狠恨哼亨横衡恒轰哄烘虹鸿洪宏弘红喉侯猴吼厚候后呼乎忽瑚壶葫胡蝴狐糊湖弧虎唬护互沪户花哗华猾滑画划化话槐徊怀淮坏欢环桓还缓换患唤痪豢焕涣宦幻荒慌黄磺蝗簧皇凰惶煌晃幌恍谎灰挥辉徽恢蛔回毁悔慧卉惠晦贿秽会烩汇讳诲绘荤昏婚魂浑混豁活伙火获或惑霍货祸击圾基机畸稽积箕肌饥迹激讥鸡姬绩缉吉极棘辑籍集及急疾汲即嫉级挤几脊己蓟技冀季伎祭剂悸济寄寂计记既忌际妓继纪嘉枷夹佳家加荚颊贾甲钾假稼价架驾嫁歼监坚尖笺间煎兼肩艰奸缄茧检柬碱硷拣捡简俭剪减荐槛鉴践贱见键箭件健舰剑饯渐溅涧建僵姜将浆江疆蒋桨奖讲匠酱降蕉椒礁焦胶交郊浇骄娇嚼搅铰矫侥脚狡角饺缴绞剿教酵轿较叫窖揭接皆秸街阶截劫节桔杰捷睫竭洁结解姐戒藉芥界借介疥诫届巾筋斤金今津襟紧锦仅谨进靳晋禁近烬浸尽劲荆兢茎睛晶鲸京惊精粳经井警景颈静境敬镜径痉靖竟竞净炯窘揪究纠玖韭久灸九酒厩救旧臼舅咎就疚鞠拘狙疽居驹菊局咀矩举沮聚拒据巨具距踞锯俱句惧炬剧捐鹃娟倦眷卷绢撅攫抉掘倔爵觉决诀绝均菌钧军君峻俊竣浚郡骏喀咖卡咯开揩楷凯慨刊堪勘坎砍看康慷糠扛抗亢炕考拷烤靠坷苛柯棵磕颗科壳咳可渴克刻客课肯啃垦恳坑吭空恐孔控抠口扣寇枯哭窟苦酷库裤夸垮挎跨胯块筷侩快宽款匡筐狂框矿眶旷况亏盔岿窥葵奎魁傀馈愧溃坤昆捆困括扩廓阔垃拉喇蜡腊辣啦莱来赖蓝婪栏拦篮阑兰澜谰揽览懒缆烂滥琅榔狼廊郎朗浪捞劳牢老佬姥酪烙涝勒乐雷镭蕾磊累儡垒擂肋类泪棱楞冷厘梨犁黎篱狸离漓理李里鲤礼莉荔吏栗丽厉励砾历利傈例俐痢立粒沥隶力璃哩俩联莲连镰廉怜涟帘敛脸链恋炼练粮凉梁粱良两辆量晾亮谅撩聊僚疗燎寥辽潦了撂镣廖料列裂烈劣猎琳林磷霖临邻鳞淋凛赁吝拎玲菱零龄铃伶羚凌灵陵岭领另令溜琉榴硫馏留刘瘤流柳六龙聋咙笼窿隆垄拢陇楼娄搂篓漏陋芦卢颅庐炉掳卤虏鲁麓碌露路赂鹿潞禄录陆戮驴吕铝侣旅履屡缕虑氯律率滤绿峦挛孪滦卵乱掠略抡轮伦仑沦纶论萝螺罗逻锣箩骡裸落洛骆络妈麻玛码蚂马骂嘛吗埋买麦卖迈脉瞒馒蛮满蔓曼慢漫谩芒茫盲氓忙莽猫茅锚毛矛铆卯茂冒帽貌贸么玫枚梅酶霉煤没眉媒镁每美昧寐妹媚门闷们萌蒙檬盟锰猛梦孟眯醚靡糜迷谜弥米秘觅泌蜜密幂棉眠绵冕免勉娩缅面苗描瞄藐秒渺庙妙蔑灭民抿皿敏悯闽明螟鸣铭名命谬摸摹蘑模膜磨摩魔抹末莫墨默沫漠寞陌谋牟某拇牡亩姆母墓暮幕募慕木目睦牧穆拿哪呐钠那娜纳氖乃奶耐奈南男难囊挠脑恼闹淖呢馁内嫩能妮霓倪泥尼拟你匿腻逆溺蔫拈年碾撵捻念娘酿鸟尿捏聂孽啮镊镍涅您柠狞凝宁拧泞牛扭钮纽脓浓农弄奴努怒女暖虐疟挪懦糯诺哦欧鸥殴藕呕偶沤啪趴爬帕怕琶拍排牌徘湃派攀潘盘磐盼畔判叛乓庞旁耪胖抛咆刨炮袍跑泡呸胚培裴赔陪配佩沛喷盆砰抨烹澎彭蓬棚硼篷膨朋鹏捧碰坯砒霹批披劈琵毗啤脾疲皮匹痞僻屁譬篇偏片骗飘漂瓢票撇瞥拼频贫品聘乒坪苹萍平凭瓶评屏坡泼颇婆破魄迫粕剖扑铺仆莆葡菩蒲埔朴圃普浦谱曝瀑期欺栖戚妻七凄漆柒沏其棋奇歧畦崎脐齐旗祈祁骑起岂乞企启契砌器气迄弃汽泣讫掐恰洽牵扦钎铅千迁签仟谦乾黔钱钳前潜遣浅谴堑嵌欠歉枪呛腔羌墙蔷强抢橇锹敲悄桥瞧乔侨巧鞘撬翘峭俏窍切茄且怯窃钦侵亲秦琴勤芹擒禽寝沁青轻氢倾卿清擎晴氰情顷请庆琼穷秋丘邱球求囚酋泅趋区蛆曲躯屈驱渠取娶龋趣去圈颧权醛泉全痊拳犬券劝缺炔瘸却鹊榷确雀裙群然燃冉染瓤壤攘嚷让饶扰绕惹热壬仁人忍韧任认刃妊纫扔仍日戎茸蓉荣融熔溶容绒冗揉柔肉茹蠕儒孺如辱乳汝入褥软阮蕊瑞锐闰润若弱撒洒萨腮鳃塞赛三叁伞散桑嗓丧搔骚扫嫂瑟色涩森僧莎砂杀刹沙纱傻啥煞筛晒珊苫杉山删煽衫闪陕擅赡膳善汕扇缮墒伤商赏晌上尚裳梢捎稍烧芍勺韶少哨邵绍奢赊蛇舌舍赦摄射慑涉社设砷申呻伸身深娠绅神沈审婶甚肾慎渗声生甥牲升绳省盛剩胜圣师失狮施湿诗尸虱十石拾时什食蚀实识史矢使屎驶始式示士世柿事拭誓逝势是嗜噬适仕侍释饰氏市恃室视试收手首守寿授售受瘦兽蔬枢梳殊抒输叔舒淑疏书赎孰熟薯暑曙署蜀黍鼠属术述树束戍竖墅庶数漱恕刷耍摔衰甩帅栓拴霜双爽谁水睡税吮瞬顺舜说硕朔烁斯撕嘶思私司丝死肆寺嗣四伺似饲巳松耸怂颂送宋讼诵搜艘擞嗽苏酥俗素速粟僳塑溯宿诉肃酸蒜算虽隋随绥髓碎岁穗遂隧祟孙损笋蓑梭唆缩琐索锁所塌他它她塔獭挞蹋踏胎苔抬台泰酞太态汰坍摊贪瘫滩坛檀痰潭谭谈坦毯袒碳探叹炭汤塘搪堂棠膛唐糖倘躺淌趟烫掏涛滔绦萄桃逃淘陶讨套特藤腾疼誊梯剔踢锑提题蹄啼体替嚏惕涕剃屉天添填田甜恬舔腆挑条迢眺跳贴铁帖厅听烃汀廷停亭庭挺艇通桐酮瞳同铜彤童桶捅筒统痛偷投头透凸秃突图徒途涂屠土吐兔湍团推颓腿蜕褪退吞屯臀拖托脱鸵陀驮驼椭妥拓唾挖哇蛙洼娃瓦袜歪外豌弯湾玩顽丸烷完碗挽晚皖惋宛婉万腕汪王亡枉网往旺望忘妄威巍微危韦违桅围唯惟为潍维苇萎委伟伪尾纬未蔚味畏胃喂魏位渭谓尉慰卫瘟温蚊文闻纹吻稳紊问嗡翁瓮挝蜗涡窝我斡卧握沃巫呜钨乌污诬屋无芜梧吾吴毋武五捂午舞伍侮坞戊雾晤物勿务悟误昔熙析西硒矽晰嘻吸锡牺稀息希悉膝夕惜熄烯溪汐犀檄袭席习媳喜铣洗系隙戏细瞎虾匣霞辖暇峡侠狭下厦夏吓掀锨先仙鲜纤咸贤衔舷闲涎弦嫌显险现献县腺馅羡宪陷限线相厢镶香箱襄湘乡翔祥详想响享项巷橡像向象萧硝霄削哮嚣销消宵淆晓小孝校肖啸笑效楔些歇蝎鞋协挟携邪斜胁谐写械卸蟹懈泄泻谢屑薪芯锌欣辛新忻心信衅星腥猩惺兴刑型形邢行醒幸杏性姓兄凶胸匈汹雄熊休修羞朽嗅锈秀袖绣墟戌需虚嘘须徐许蓄酗叙旭序畜恤絮婿绪续轩喧宣悬旋玄选癣眩绚靴薛学穴雪血勋熏循旬询寻驯巡殉汛训讯逊迅压押鸦鸭呀丫芽牙蚜崖衙涯雅哑亚讶焉咽阉烟淹盐严研蜒岩延言颜阎炎沿奄掩眼衍演艳堰燕厌砚雁唁彦焰宴谚验殃央鸯秧杨扬佯疡羊洋阳氧仰痒养样漾邀腰妖瑶摇尧遥窑谣姚咬舀药要耀椰噎耶爷野冶也页掖业叶曳腋夜液一壹医揖铱依伊衣颐夷遗移仪胰疑沂宜姨彝椅蚁倚已乙矣以艺抑易邑屹亿役臆逸肄疫亦裔意毅忆义益溢诣议谊译异翼翌绎茵荫因殷音阴姻吟银淫寅饮尹引隐印英樱婴鹰应缨莹萤营荧蝇迎赢盈影颖硬映哟拥佣臃痈庸雍踊蛹咏泳涌永恿勇用幽优悠忧尤由邮铀犹油游酉有友右佑釉诱又幼迂淤于盂榆虞愚舆余俞逾鱼愉渝渔隅予娱雨与屿禹宇语羽玉域芋郁吁遇喻峪御愈欲狱育誉浴寓裕预豫驭鸳渊冤元垣袁原援辕园员圆猿源缘远苑愿怨院曰约越跃钥岳粤月悦阅耘云郧匀陨允运蕴酝晕韵孕匝砸杂栽哉灾宰载再在咱攒暂赞赃脏葬遭糟凿藻枣早澡蚤躁噪造皂灶燥责择则泽贼怎增憎曾赠扎喳渣札轧铡闸眨栅榨咋乍炸诈摘斋宅窄债寨瞻毡詹粘沾盏斩辗崭展蘸栈占战站湛绽樟章彰漳张掌涨杖丈帐账仗胀瘴障招昭找沼赵照罩兆肇召遮折哲蛰辙者锗蔗这浙珍斟真甄砧臻贞针侦枕疹诊震振镇阵蒸挣睁征狰争怔整拯正政帧症郑证芝枝支吱蜘知肢脂汁之织职直植殖执值侄址指止趾只旨纸志挚掷至致置帜峙制智秩稚质炙痔滞治窒中盅忠钟衷终种肿重仲众舟周州洲诌粥轴肘帚咒皱宙昼骤珠株蛛朱猪诸诛逐竹烛煮拄瞩嘱主著柱助蛀贮铸筑住注祝驻抓爪拽专砖转撰赚篆桩庄装妆撞壮状椎锥追赘坠缀谆准捉拙卓桌琢茁酌啄着灼浊兹咨资姿滋淄孜紫仔籽滓子自渍字鬃棕踪宗综总纵邹走奏揍租足卒族祖诅阻组钻纂嘴醉最罪尊遵昨左佐柞做作坐座");
    std::string out;
    for (size_t i = 0; i < b.size(); i += 2) {
        uint32_t v = b[i];
        if (i + 1 < b.size()) v = (v << 8) | b[i + 1];
        out += table[v % table.size()];
        uint32_t h = v * 2654435761u;
        if ((h >> 29) == 0) out += ((h >> 28) & 1) ? "，" : "。";
    }
    return out;
}

}  // namespace

CodebookInfo codebook_info(const std::string& codebook) {
    auto cb = clean_codebook(codebook);
    return {cb.size(), std::unordered_set<std::string>(cb.begin(), cb.end()).size()};
}

std::string encrypt(const std::string& plaintext, const std::string& numeric_key, const std::string& codebook) {
    init_sodium();
    const std::string gb = to_gb(plaintext);
    if (gb.size() + kWireNonce + kTagBytes > 65535) throw std::length_error("明文过长");
    auto key = derive_key(numeric_key, clean_codebook(codebook));
    SubKeys sk = split_key(key);

    // blob = 随机数(6) || 密文 || 标签(8)；ChaCha20 用的 12 字节 nonce = 随机数(6) || 6 个 0
    unsigned char nonce[kNonceBytes] = {0};
    randombytes_buf(nonce, kWireNonce);
    std::vector<uint8_t> blob(kWireNonce + gb.size() + kTagBytes);
    std::copy(nonce, nonce + kWireNonce, blob.begin());
    if (!gb.empty())
        crypto_stream_chacha20_ietf_xor_ic(blob.data() + kWireNonce, reinterpret_cast<const unsigned char*>(gb.data()),
                                           gb.size(), nonce, 0, sk.enc.data());
    make_tag(blob.data() + kWireNonce + gb.size(), sk, blob.data(), kWireNonce + gb.size());
    sodium_memzero(key.data(), key.size());
    sodium_memzero(sk.enc.data(), sk.enc.size());
    sodium_memzero(sk.mac.data(), sk.mac.size());
    return poem_encode(blob);
}

DecryptResult decrypt(const std::string& poem, const std::string& numeric_key, const std::string& codebook) {
    init_sodium();
    std::vector<uint8_t> blob = poem_decode(poem);  // 密文格式错误在这里抛异常
    if (blob.size() < kWireNonce + kTagBytes) throw std::runtime_error("密文过短");
    auto key = derive_key(numeric_key, clean_codebook(codebook));
    SubKeys sk = split_key(key);

    const size_t mlen = blob.size() - kWireNonce - kTagBytes;
    unsigned char nonce[kNonceBytes] = {0};
    std::copy(blob.begin(), blob.begin() + kWireNonce, nonce);

    // 先校验标签，但不管对错都照常解出字节：密钥或密码表不对时输出的是（错误的）结果，不报错。
    uint8_t tag[kTagBytes];
    make_tag(tag, sk, blob.data(), kWireNonce + mlen);
    const bool ok = sodium_memcmp(tag, blob.data() + kWireNonce + mlen, kTagBytes) == 0;

    std::vector<uint8_t> m(mlen);
    if (mlen > 0)
        crypto_stream_chacha20_ietf_xor_ic(m.data(), blob.data() + kWireNonce, mlen, nonce, 0, sk.enc.data());

    DecryptResult r;
    if (ok) {
        r.text = convert(std::string(reinterpret_cast<const char*>(m.data()), mlen), "UTF-8", "GB18030");
        r.authentic = true;
    } else {
        r.text = render_garbage(m);
        r.authentic = false;
    }
    sodium_memzero(key.data(), key.size());
    sodium_memzero(sk.enc.data(), sk.enc.size());
    sodium_memzero(sk.mac.data(), sk.mac.size());
    return r;
}

}  // namespace zhc
