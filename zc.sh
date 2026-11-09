#!/usr/bin/env bash
# 中西部山顶火车票 —— 菜单版。用法：bash zc.sh        （第一次先运行：bash zc.sh --install）
# 碑号和碣文都在窗口里输入（输入时不显示），不会保存到任何文件。
# 解石时输错碑号或碣文，不会报错、不会提示，只会输出一段看起来像中文的乱码。
export LC_ALL=C.UTF-8
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
BIN="$HERE/build/zhcipher"
OUT_DIR="$HOME/zhc-output"       # 着衣结果（新语，不是秘密）放这里
mkdir -p "$OUT_DIR"

# ---------- 小工具 ----------
# 取得 Windows 的“文档”或“桌面”文件夹在 Ubuntu 里的路径（结果缓存起来）
win_path() {   # $1 = MyDocuments | Desktop
  local cache="$HOME/.zhc_win_$1" p up
  if [ -s "$cache" ]; then cat "$cache"; return; fi
  p="$( cd /mnt/c 2>/dev/null; powershell.exe -NoProfile -Command "[Environment]::GetFolderPath('$1')" 2>/dev/null | tr -d '\r' )"
  [ -n "$p" ] && p="$(wslpath -u "$p" 2>/dev/null)"
  if [ -z "$p" ] || [ ! -d "$p" ]; then
    up="$( cd /mnt/c 2>/dev/null; cmd.exe /c 'echo %USERPROFILE%' 2>/dev/null | tr -d '\r' )"
    up="$(wslpath -u "$up" 2>/dev/null)"
    if [ "$1" = MyDocuments ]; then p="$up/Documents"; else p="$up/Desktop"; fi
  fi
  [ -d "$p" ] && echo "$p" > "$cache"
  echo "$p"
}
pause()    { echo; read -r -p "按回车返回菜单……" _; }
need_bin() { if [ ! -x "$BIN" ]; then echo "找不到编译好的程序：$BIN"; return 1; fi; }
flush_input() { local _j; while IFS= read -r -s -t 0.2 _j; do :; done; }   # 清掉粘贴时多出来的尾巴

read_key() {   # 结果放进 KEY；$1=confirm 时要输入两遍
  local k k2
  while true; do
    read -r -s -p "碑号（输入时不显示，输 q 返回）：" k; echo
    [ "$k" = q ] && return 1
    if ! [[ "$k" =~ ^[0-9]+$ ]]; then echo "只能输入数字，请重试。"; continue; fi
    [ "${#k}" -lt 16 ] && echo "提示：少于 16 位，容易被穷举。"
    if [ "$1" = confirm ]; then
      read -r -s -p "再输入一遍确认：" k2; echo
      [ "$k" = "$k2" ] || { echo "两次不一致，请重试。"; continue; }
    fi
    KEY="$k"; return 0
  done
}

# 保证文件里是 UTF-8：自动去掉 BOM；如果是 Windows 记事本的 ANSI/GBK 编码，自动转换。
normalize_text() {   # $1 = 文件
  python3 - "$1" <<'PY'
import sys
p = sys.argv[1]
b = open(p, 'rb').read()
if b.startswith(b'\xef\xbb\xbf'):
    b = b[3:]
try:
    s = b.decode('utf-8')
except UnicodeDecodeError as e:
    try:
        s = b.decode('gb18030')
        print('提示：原文不是 UTF-8 编码（像是 Windows 记事本的 ANSI/GBK），已自动转换。')
    except UnicodeDecodeError:
        print('错误：原文里有无法识别的字节（第 %d 个字节附近），请检查是否有乱码，或重新输入。' % (e.start + 1))
        sys.exit(2)
open(p, 'wb').write(s.encode('utf-8'))
PY
}

# 去掉空白后统计：总字数、不重复字数
cb_info() {
  printf '%s' "$1" | python3 -c "
import sys
s = sys.stdin.read()
print(len(s), len(set(s)))"
}

# 在窗口里输入碣文（64～1024 字，可以有重复的字），结果放进 CB。可以一次粘贴，也可以分多段粘贴。
read_codebook() {
  local line all="" clean n d a
  echo "请粘贴碣文（64～1024 字，建议 256 字；允许有重复的字；输入时不显示）"
  echo "  粘贴后按回车；可以分多段粘贴；全部粘完后，在空行直接按回车确认"
  echo "  输入 r 清空重来，输入 q 返回"
  while true; do
    IFS= read -r -s -p "碣文：" line; echo
    [ "$line" = q ] && return 1
    if [ "$line" = r ]; then all=""; echo "已清空。"; continue; fi
    if [ -z "$line" ]; then   # 空行：确认
      read -r n d <<< "$(cb_info "$all")"
      if [ "$n" -lt 64 ]; then
        echo "目前只有 $n 字，至少要 64 字，请继续粘贴。"; continue
      fi
      flush_input
      [ "$n" -lt 128 ] && echo "提示：字数偏少，建议至少 256 字。"
      if [ "$d" -lt 64 ]; then
        read -r -p "不重复的字只有 $d 个，几乎起不到保护作用。仍要继续吗？[y/n]：" a
        if [ "$a" != y ] && [ "$a" != Y ]; then all=""; echo "已清空，请重新输入碣文。"; continue; fi
      fi
      echo "已确认：共 $n 字，其中不重复 $d 个。"
      CB="$all"; return 0
    fi
    clean="$(printf '%s' "$all$line" | python3 -c "import sys; sys.stdout.write(''.join(sys.stdin.read().split()))")"
    read -r n d <<< "$(cb_info "$clean")"
    if [ "$n" -gt 1024 ]; then
      echo "已输入 $n 字，超过 1024 字，请重新输入。"; all=""
    else
      all="$clean"
      echo "已输入 $n 字（其中不重复 $d 个）。没有更多了就直接按回车确认，还有就继续粘贴。"
    fi
  done
}

# ---------- 着衣 / 解石 ----------
do_encrypt() {
  need_bin || return
  echo "原文怎么来？  1) 直接输入或粘贴   2) 读取“文档”里的文本文件"
  read -r -p "选择 [1/2]：" m
  local tmp content; tmp="$(mktemp)"
  if [ "$m" = 2 ]; then
    local docs fn; docs="$(win_path MyDocuments)"
    read -r -p "文件名（在“文档”文件夹里，如 plain.txt）：" fn
    if [ ! -f "$docs/$fn" ]; then echo "找不到：$docs/$fn"; rm -f "$tmp"; return; fi
    cp "$docs/$fn" "$tmp"
  else
    echo "请输入或粘贴原文，结束时【另起一行】按 Ctrl-D："
    cat > "$tmp"
    content="$(cat "$tmp")"; printf '%s' "$content" > "$tmp"   # 去掉末尾多余换行
  fi
  normalize_text "$tmp" || { rm -f "$tmp"; return; }
  read_key confirm || { rm -f "$tmp"; return; }
  read_codebook || { rm -f "$tmp"; return; }
  local out; out="$OUT_DIR/新语_$(date +%Y%m%d_%H%M%S).txt"
  echo "正在着衣（需要几秒）……"
  if printf '%s\n%s\n' "$KEY" "$CB" | "$BIN" enc -i "$tmp" -o "$out" 2>"$tmp.err"; then
    echo; echo "———————— 新语 ————————"; cat "$out"; echo "————————————————"
    echo "已保存：$out"
    local docs dst; docs="$(win_path MyDocuments)"; dst="$docs/中西部山顶火车票"
    if mkdir -p "$dst" 2>/dev/null && cp "$out" "$dst"/ 2>/dev/null; then
      echo "并复制到 Windows：文档\\中西部山顶火车票"
    fi
  else
    echo "着衣失败："; sed "s/数字密钥/碑号/g; s/密码表/碣文/g; s/密文/新语/g" "$tmp.err"
  fi
  rm -f "$tmp" "$tmp.err"; KEY=""; CB=""
}

do_decrypt() {
  need_bin || return
  echo "新语怎么来？  1) 最新着衣的那份   2) 粘贴新语   3) 读取“文档”里的文件"
  read -r -p "选择 [1/2/3]：" m
  local tmp in; tmp="$(mktemp)"
  case "$m" in
    1) in="$(ls -t "$OUT_DIR"/新语_*.txt "$OUT_DIR"/密文_*.txt 2>/dev/null | head -1)"
       if [ -z "$in" ]; then echo "还没有着衣过的文件。"; rm -f "$tmp"; return; fi
       cp "$in" "$tmp"; echo "使用：$in" ;;
    2) echo "请粘贴完整新语（标点和换行都要保留），结束时【另起一行】按 Ctrl-D："
       cat > "$tmp" ;;
    3) local docs fn; docs="$(win_path MyDocuments)"
       read -r -p "文件名（在“文档”或“文档\\中西部山顶火车票”里）：" fn
       if   [ -f "$docs/$fn" ];                    then cp "$docs/$fn" "$tmp"
       elif [ -f "$docs/中西部山顶火车票/$fn" ]; then cp "$docs/中西部山顶火车票/$fn" "$tmp"
       else echo "找不到文件：$fn"; rm -f "$tmp"; return; fi ;;
    *) echo "无效选择"; rm -f "$tmp"; return ;;
  esac
  read_key || { rm -f "$tmp"; return; }
  read_codebook || { rm -f "$tmp"; return; }
  echo "正在解石（需要几秒）……"
  if printf '%s\n%s\n' "$KEY" "$CB" | "$BIN" dec -i "$tmp" >"$tmp.out" 2>"$tmp.err"; then
    # 碑号或碣文不对时不会报错，也不会提示，输出的是一段看起来像中文的乱码。
    echo; echo "———————— 结果 ————————"; cat "$tmp.out"; echo "————————————————"
  else
    echo "解石失败（新语格式不对？）："; sed "s/数字密钥/碑号/g; s/密码表/碣文/g; s/密文/新语/g" "$tmp.err"
  fi
  rm -f "$tmp" "$tmp.out" "$tmp.err"; KEY=""; CB=""
}

# ---------- 碣文小工具（不保存任何文件） ----------
check_codebook() {
  read_codebook || return
  echo "这张碣文可用。"
  CB=""
}

# ---------- 安装 ----------
do_install() {
  local dsk
  grep -q "alias zc=" "$HOME/.bashrc" 2>/dev/null || echo "alias zc='bash $HERE/zc.sh'" >> "$HOME/.bashrc"
  dsk="$(win_path Desktop)"
  if [ -d "$dsk" ]; then
    printf '@echo off\r\nchcp 65001 >nul\r\nwsl -d Ubuntu -- bash -lc "bash %s/zc.sh"\r\npause\r\n' "$HERE" > "$dsk/中西部山顶火车票.bat"
    echo "已在 Windows 桌面创建“中西部山顶火车票.bat”，以后双击它就能打开菜单。"
  else
    echo "没找到桌面文件夹，跳过创建桌面图标。"
  fi
  echo "安装完成。以后在 Ubuntu 里输入 zc 回车（需重新打开 Ubuntu 窗口），或双击桌面的“中西部山顶火车票.bat”。"
}

# ---------- 主菜单 ----------
main_menu() {
  local c
  stty iutf8 2>/dev/null   # 让退格键一次删掉一个汉字，而不是半个汉字
  while true; do
    clear
    echo "============ 中西部山顶火车票 ============"
    echo "  1) 着衣"
    echo "  2) 解石"
    echo "  3) 检查碣文（字数、重复）"
    echo "  0) 退出"
    read -r -p "请选择：" c || exit 0
    case "$c" in
      1) do_encrypt; pause ;;
      2) do_decrypt; pause ;;
      3) check_codebook; pause ;;
      0) exit 0 ;;
      *) ;;
    esac
  done
}

case "$1" in
  --install) do_install ;;
  *) main_menu ;;
esac
