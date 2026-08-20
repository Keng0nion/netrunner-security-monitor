#!/bin/bash
# ╔══════════════════════════════════════════════════════════════╗
# ║   网络侦察终端 · NETRUNNER TERMINAL — 赛博朋克交互版 (macOS)  ║
# ╚══════════════════════════════════════════════════════════════╝
# 主流程以统一采集、SQLite 历史、基线变化和威胁分析为中心；
# 原设备识别 / 渗透测试 / 信息收集 / 家庭监控探测入口保留在高级菜单。
# 界面继续使用开机动画、故障字、进度条和霓虹配色。

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOURCE_DIR="$SCRIPT_DIR/source"
JS_DIR="$SCRIPT_DIR/源码"

# ══════════════════════════════════════════════════════════
# 霓虹配色 (256色 ANSI)
# ══════════════════════════════════════════════════════════
NEON_GREEN='\033[38;5;46m'
NEON_CYAN='\033[38;5;51m'
NEON_PINK='\033[38;5;201m'
NEON_PURPLE='\033[38;5;135m'
NEON_YELLOW='\033[38;5;226m'
NEON_RED='\033[38;5;196m'
NEON_BLUE='\033[38;5;39m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo -e "${NEON_RED}[!] 本工具只支持 macOS。${RESET}"
    exit 1
fi

# ══════════════════════════════════════════════════════════
# 视觉特效函数
# ══════════════════════════════════════════════════════════

# 打字机效果
typewriter() {
    local text="$1" color="${2:-$NEON_GREEN}" delay="${3:-0.012}"
    local i
    for ((i = 0; i < ${#text}; i++)); do
        printf "${color}%s${RESET}" "${text:$i:1}"
        sleep "$delay"
    done
    echo ""
}

# 故障字效果：先乱码闪几帧，再定格成正确文字
glitch_line() {
    local text="$1"
    local chars='!@#$%^&*<>/\|~▓▒░╳╱╲'
    local f glitched i ch
    for ((f = 0; f < 4; f++)); do
        glitched=""
        for ((i = 0; i < ${#text}; i++)); do
            ch="${text:$i:1}"
            if [[ "$ch" != " " ]] && (( RANDOM % 5 == 0 )); then
                glitched+="${chars:$((RANDOM % ${#chars})):1}"
            else
                glitched+="$ch"
            fi
        done
        printf "\r  ${NEON_PINK}%s${RESET}" "$glitched"
        sleep 0.045
    done
    printf "\r  ${NEON_CYAN}${BOLD}%s${RESET}\n" "$text"
}

# 加载进度条
loading_bar() {
    local label="$1" width=28 i pct bar space
    for ((i = 0; i <= width; i++)); do
        pct=$((i * 100 / width))
        bar=$(printf "%${i}s" | tr ' ' '█')
        space=$(printf "%$((width - i))s")
        printf "\r  ${DIM}%-14s${RESET} [${NEON_GREEN}%s${RESET}%s] ${NEON_CYAN}%3d%%${RESET}" "$label" "$bar" "$space" "$pct"
        sleep 0.008
    done
    echo ""
}

hr() { echo -e "  ${NEON_PURPLE}$(printf '─%.0s' $(seq 1 54))${RESET}"; }

beep() { printf '\a'; }

# ══════════════════════════════════════════════════════════
# 开机动画
# ══════════════════════════════════════════════════════════
boot_sequence() {
    clear 2>/dev/null || true
    echo -e "${NEON_GREEN}${BOLD}"
    cat << 'EOF'
   _   _ _____ _____   ____  _   _ _   _ _   _ _____ ____
  | \ | | ____|_   _| |  _ \| | | | \ | | \ | | ____|  _ \
  |  \| |  _|   | |   | |_) | | | |  \| |  \| |  _| | |_) |
  | |\  | |___  | |   |  _ <| |_| | |\  | |\  | |___|  _ <
  |_| \_|_____| |_|   |_| \_\\___/|_| \_|_| \_|_____|_| \_\

EOF
    echo -e "${RESET}"
    typewriter "  > 本地安全数据终端 v3.0 — NETRUNNER ANALYTICS" "$NEON_CYAN" 0.01
    typewriter "  > 正在建立本地节点连接..." "$DIM$NEON_GREEN" 0.006
    echo ""
    loading_bar "初始化内核"
    loading_bar "加载扫描模块"
    loading_bar "校验工具链"
    loading_bar "建立安全通道"
    echo ""
    glitch_line "  系统就绪。欢迎回来，运营者 (OPERATOR)。"
    beep
    sleep 0.35
}

# ══════════════════════════════════════════════════════════
# 依赖检测（Python 与 Node.js 都是主流程 home/quick/full 的必需环境）
# ══════════════════════════════════════════════════════════
PYTHON=""
NODE=""
if command -v python3 &>/dev/null; then PYTHON="$(command -v python3)"; fi
if command -v node &>/dev/null; then NODE="$(command -v node)"; fi

status_dot() { command -v "$1" &>/dev/null && echo -e "${NEON_GREEN}●${RESET}" || echo -e "${NEON_RED}●${RESET}"; }

if [ -z "$PYTHON" ] || [ -z "$NODE" ]; then
    boot_sequence
    if [ -z "$PYTHON" ]; then
        echo -e "${NEON_RED}[!] 错误：未找到 Python 3（主流程必需）${RESET}"
    fi
    if [ -z "$NODE" ]; then
        echo -e "${NEON_RED}[!] 错误：未找到 Node.js 18+（主流程周边采集必需）${RESET}"
    fi
    echo "[!] 请先运行同目录下的「环境检查.command」"
    echo ""
    read -r -p "按回车键退出..."
    exit 1
fi

NODE_MAJOR="$($NODE -p "process.versions.node.split('.')[0]" 2>/dev/null)"
if [[ ! "$NODE_MAJOR" =~ ^[0-9]+$ ]] || [ "$NODE_MAJOR" -lt 18 ]; then
    boot_sequence
    echo -e "${NEON_RED}[!] 错误：Node.js 版本过低，主流程要求 Node.js 18+。${RESET}"
    echo "[!] 当前版本: $($NODE --version 2>/dev/null || echo 未知)"
    read -r -p "按回车键退出..."
    exit 1
fi

NETRUNNER_SCRIPT="$SOURCE_DIR/netrunner.py"
AUDIT_SCRIPT="$SOURCE_DIR/audit_engine.py"
PENTEST_SCRIPT="$SOURCE_DIR/penetration_test.py"
RECON_SCRIPT="$SOURCE_DIR/recon.py"
SPY_JS="$JS_DIR/spy_detector.js"
SPY_BIN_ARM="$SCRIPT_DIR/dist/spy_detector_mac_arm64"
SPY_BIN_X64="$SCRIPT_DIR/dist/spy_detector_mac_x64"
TARGET=""
LAST_COMMAND_STATUS=0

for f in "$NETRUNNER_SCRIPT" "$AUDIT_SCRIPT" "$PENTEST_SCRIPT" "$RECON_SCRIPT"; do
    if [ ! -f "$f" ]; then
        echo -e "${NEON_RED}[!] 错误：未找到脚本 ($f)${RESET}"
        read -r -p "按回车键退出..."
        exit 1
    fi
done

# ══════════════════════════════════════════════════════════
# 目标输入
# ══════════════════════════════════════════════════════════
get_target() {
    local allow_lan="$1"
    local input=""
    TARGET=""
    echo ""
    echo -e "  ${NEON_PURPLE}┌─[ ${NEON_CYAN}TARGET LOCK${NEON_PURPLE} ]${RESET}"
    echo -e "  ${NEON_PURPLE}│${RESET}  输入授权 IP 地址或域名"
    if [[ "$allow_lan" == "yes" ]]; then
        echo -e "  ${NEON_PURPLE}│${RESET}  直接回车 → 扫描整个局域网"
    fi
    echo -e "  ${NEON_PURPLE}└─▶${RESET}"
    IFS= read -r -p "  地址> " input || return 1
    if [[ "$input" == -* ]]; then
        echo -e "${NEON_RED}  [!] 目标不能以前导 '-' 开始。${RESET}" >&2
        return 1
    fi
    if [[ "$input" == *$'\n'* || "$input" == *$'\r'* || "$input" == *$'\t'* ]] || LC_ALL=C printf '%s' "$input" | grep -q '[[:cntrl:]]'; then
        echo -e "${NEON_RED}  [!] 目标不能包含换行或控制字符。${RESET}" >&2
        return 1
    fi
    if [[ "$allow_lan" != "yes" && -z "$input" ]]; then
        echo -e "${NEON_RED}  [!] 此操作需要指定目标。${RESET}" >&2
        return 1
    fi
    TARGET="$input"
    return 0
}

run_and_report() {
    local label="$1"
    shift
    "$@"
    LAST_COMMAND_STATUS=$?
    if [ "$LAST_COMMAND_STATUS" -eq 0 ]; then
        echo -e "  ${NEON_GREEN}[✓] ${label}完成（退出码 0）。${RESET}"
    else
        echo -e "  ${NEON_RED}[!] ${label}失败或部分失败（退出码 ${LAST_COMMAND_STATUS}）。${RESET}"
    fi
    return "$LAST_COMMAND_STATUS"
}

# ══════════════════════════════════════════════════════════
# 数据中心主入口
# ══════════════════════════════════════════════════════════
run_home_analysis() {
    glitch_line "启动家庭全量采集与历史威胁分析..."
    loading_bar "建立数据批次"
    run_and_report "家庭全量采集" "$PYTHON" "$NETRUNNER_SCRIPT" collect --profile home
}

run_quick_analysis() {
    if ! get_target "no"; then return 2; fi
    glitch_line "启动指定目标快速数据分析..."
    loading_bar "部署采集器"
    run_and_report "快速综合分析" "$PYTHON" "$NETRUNNER_SCRIPT" collect --profile quick --target "$TARGET"
}

run_full_analysis() {
    if ! get_target "no"; then return 2; fi
    if [[ ! "$TARGET" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo -e "${NEON_RED}  [!] 完整模式包含 Masscan，只接受明确授权的 IPv4 地址；域名请用高级菜单的显式 OSINT/Nmap 入口。${RESET}"
        return 2
    fi
    IFS='.' read -r octet1 octet2 octet3 octet4 <<< "$TARGET"
    for octet in "$octet1" "$octet2" "$octet3" "$octet4"; do
        if [ "$octet" -gt 255 ]; then
            echo -e "${NEON_RED}  [!] IPv4 地址格式无效。${RESET}"
            return 2
        fi
    done
    echo -e "  ${NEON_YELLOW}[!] 完整模式可能运行全端口 Nmap、Masscan 和 Nikto。${RESET}"
    echo "  只可对你拥有或已获书面授权的 IPv4 目标使用。"
    read -r -p "  确认继续？[y/N] " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "  已取消。"
        return 2
    fi
    glitch_line "启动指定目标完整数据分析..."
    loading_bar "部署深度采集器"
    run_and_report "完整综合分析" "$PYTHON" "$NETRUNNER_SCRIPT" collect --profile full --target "$TARGET"
}

show_latest_report() {
    glitch_line "读取最新威胁分析报告..."
    run_and_report "最新报告生成" "$PYTHON" "$NETRUNNER_SCRIPT" report
}

show_changes() {
    glitch_line "计算最近批次与历史基线差异..."
    run_and_report "历史变化计算" "$PYTHON" "$NETRUNNER_SCRIPT" changes
}

show_history() {
    glitch_line "读取本地扫描历史..."
    run_and_report "扫描历史读取" "$PYTHON" "$NETRUNNER_SCRIPT" history
}

# 旧入口保留为高级工具，底层结果仍默认写入统一数据平台。
run_audit() {
    if ! get_target "yes"; then return 2; fi
    glitch_line "启动设备识别扫描..."
    loading_bar "唤醒探测器"
    if [ -n "$TARGET" ]; then
        echo -e "  ${NEON_YELLOW}[TARGET]${RESET} $TARGET"
        run_and_report "设备识别扫描" "$PYTHON" "$AUDIT_SCRIPT" --target "$TARGET"
    else
        echo -e "  ${NEON_YELLOW}[TARGET]${RESET} 整个局域网"
        run_and_report "设备识别扫描" "$PYTHON" "$AUDIT_SCRIPT"
    fi
}

run_pentest() {
    if ! get_target "no"; then return 2; fi
    glitch_line "启动渗透测试框架..."
    loading_bar "部署扫描载荷"
    echo -e "  ${NEON_YELLOW}[TARGET]${RESET} $TARGET"
    run_and_report "快速渗透测试" "$PYTHON" "$PENTEST_SCRIPT" "$TARGET" --quick
}

run_recon() {
    if ! get_target "no"; then return 2; fi
    glitch_line "启动明确范围的 Nmap 信息收集..."
    loading_bar "执行 Nmap 采集"
    echo -e "  ${NEON_YELLOW}[TARGET]${RESET} $TARGET"
    run_and_report "Nmap 信息收集" "$PYTHON" "$RECON_SCRIPT" "$TARGET" --type nmap
}

run_spy() {
    local arch binary="" binary_info=""
    glitch_line "启动家庭监控探测..."
    loading_bar "扫描射频信号"
    arch="$(uname -m)"
    case "$arch" in
        arm64) binary="$SPY_BIN_ARM" ;;
        x86_64) binary="$SPY_BIN_X64" ;;
        *)
            echo -e "${NEON_RED}  [!] 不支持的 macOS 架构: $arch${RESET}"
            return 1
            ;;
    esac

    if [ -f "$binary" ]; then
        if [ ! -x "$binary" ]; then
            echo -e "${NEON_RED}  [!] 预编译文件存在但不可执行: $binary${RESET}"
            echo "  可运行: chmod +x \"$binary\""
            return 1
        fi

        binary_info="$(/usr/bin/file "$binary" 2>/dev/null || true)"
        if [[ "$binary_info" != *"universal binary"* ]]; then
            if [[ "$arch" == "arm64" && "$binary_info" != *"arm64"* ]]; then
                echo -e "${NEON_RED}  [!] 二进制架构不匹配：当前为 arm64。${RESET}"
                echo "  文件信息: $binary_info"
                return 1
            fi
            if [[ "$arch" == "x86_64" && "$binary_info" != *"x86_64"* ]]; then
                echo -e "${NEON_RED}  [!] 二进制架构不匹配：当前为 x86_64。${RESET}"
                echo "  文件信息: $binary_info"
                return 1
            fi
        fi

        "$binary"
        LAST_COMMAND_STATUS=$?
        if [ "$LAST_COMMAND_STATUS" -ne 0 ]; then
            echo -e "${NEON_RED}  [!] 预编译探测器退出码: $LAST_COMMAND_STATUS${RESET}"
            if ! /usr/sbin/spctl --assess --type execute "$binary" 2>/dev/null; then
                echo "  Gatekeeper 评估未通过。请在“系统设置 → 隐私与安全性”查看拦截详情；不要绕过组织安全策略。"
            else
                echo "  Gatekeeper 评估通过；请结合上方系统错误检查权限、签名、依赖或运行时故障。"
            fi
        else
            echo -e "${NEON_GREEN}  [✓] 独立探测器完成（退出码 0）。${RESET}"
        fi
        return "$LAST_COMMAND_STATUS"
    fi

    echo -e "${NEON_YELLOW}  [!] 未找到与 $arch 匹配的预编译文件: $binary${RESET}"
    echo "  dist 二进制只是独立探测器的可选分发物，不能替代主流程要求的 Node.js 18+。"
    if [ -f "$SPY_JS" ]; then
        run_and_report "Node.js 独立探测器" "$NODE" "$SPY_JS"
    else
        echo -e "${NEON_RED}  [!] 同时缺少源码探测器: $SPY_JS${RESET}"
        return 1
    fi
}

advanced_menu() {
    while true; do
        echo ""
        echo -e "  ${NEON_PURPLE}── 高级兼容工具 ──${RESET}"
        echo -e "    ${BOLD}1${RESET}  旧版设备识别扫描"
        echo -e "    ${BOLD}2${RESET}  旧版快速渗透测试"
        echo -e "    ${BOLD}3${RESET}  旧版信息收集模块"
        echo -e "    ${BOLD}4${RESET}  独立家庭监控探测"
        echo -e "    ${BOLD}0${RESET}  返回主菜单"
        read -r -p "  > 输入高级指令 [0-4]: " advanced_choice
        case "$advanced_choice" in
            1) run_audit;   read -r -p "  按回车键继续...";;
            2) run_pentest; read -r -p "  按回车键继续...";;
            3) run_recon;   read -r -p "  按回车键继续...";;
            4) run_spy;     read -r -p "  按回车键继续...";;
            0) return;;
            *) echo -e "${NEON_RED}  [!] 未知指令${RESET}";;
        esac
    done
}

show_help() {
    echo ""
    echo -e "  ${NEON_PURPLE}╔══════════════════════════════════════════════════════╗${RESET}"
    echo -e "  ${NEON_PURPLE}║${RESET}  ${NEON_CYAN}${BOLD}HELP // 使用说明${RESET}                                    ${NEON_PURPLE}║${RESET}"
    echo -e "  ${NEON_PURPLE}╠══════════════════════════════════════════════════════╣${RESET}"
    echo -e "  ${NEON_PURPLE}║${RESET}"
    echo -e "  ${NEON_PURPLE}║${RESET}  ${NEON_YELLOW}[01]${RESET} 家庭全量分析  网络/WiFi/蓝牙采集并保存历史"
    echo -e "  ${NEON_PURPLE}║${RESET}  ${NEON_YELLOW}[02]${RESET} 快速目标分析  本地采集 + 指定目标 Nmap"
    echo -e "  ${NEON_PURPLE}║${RESET}  ${NEON_YELLOW}[03]${RESET} 完整目标分析  授权 IPv4 的 Nmap/Masscan/Nikto"
    echo -e "  ${NEON_PURPLE}║${RESET}  ${NEON_YELLOW}[04-06]${RESET} 查看最新报告、历史变化和扫描批次"
    echo -e "  ${NEON_PURPLE}║${RESET}  数据默认保存到 data/monitor.db 和 data/raw/"
    echo -e "  ${NEON_PURPLE}║${RESET}  威胁分用于排查排序，不等同于确认入侵"
    echo -e "  ${NEON_PURPLE}║${RESET}"
    echo -e "  ${NEON_PURPLE}║${RESET}  ${NEON_RED}${BOLD}规则${RESET}"
    echo -e "  ${NEON_PURPLE}║${RESET}  - 仅用于你拥有或已获得书面授权的网络/设备"
    echo -e "  ${NEON_PURPLE}║${RESET}  - 不用于未经授权的第三方网络"
    echo -e "  ${NEON_PURPLE}║${RESET}"
    echo -e "  ${NEON_PURPLE}╚══════════════════════════════════════════════════════╝${RESET}"
    echo ""
    read -r -p "  按回车键返回主菜单..."
}

exit_sequence() {
    echo ""
    glitch_line "正在断开节点连接..."
    loading_bar "清理会话"
    echo -e "  ${NEON_GREEN}${BOLD}[✓] 连接已终止。下线愉快，运营者。${RESET}"
    echo ""
}

# ══════════════════════════════════════════════════════════
# 主循环
# ══════════════════════════════════════════════════════════
boot_sequence

while true; do
    clear 2>/dev/null || true
    echo ""
    echo -e "  ${NEON_PURPLE}╔══════════════════════════════════════════════════════╗${RESET}"
    echo -e "  ${NEON_PURPLE}║${RESET}  ${NEON_GREEN}${BOLD}NETRUNNER${RESET} ${DIM}// 网络侦察终端${RESET}                          ${NEON_PURPLE}║${RESET}"
    echo -e "  ${NEON_PURPLE}║${RESET}  ${DIM}macOS $(uname -m) · $(date '+%H:%M:%S')${RESET}                             ${NEON_PURPLE}║${RESET}"
    echo -e "  ${NEON_PURPLE}╠══════════════════════════════════════════════════════╣${RESET}"
    echo -e "  ${NEON_PURPLE}║${RESET}  节点状态: nmap$(status_dot nmap) masscan$(status_dot masscan) theharvester$(status_dot theharvester) nikto$(status_dot nikto)  ${NEON_PURPLE}║${RESET}"
    echo -e "  ${NEON_PURPLE}╚══════════════════════════════════════════════════════╝${RESET}"
    echo ""
    echo -e "    ${NEON_PINK}▸${RESET} ${BOLD}1${RESET}  家庭全量采集与威胁分析   ${DIM}网络 · WiFi · 蓝牙 · 历史${RESET}"
    echo -e "    ${NEON_PINK}▸${RESET} ${BOLD}2${RESET}  指定目标快速综合分析     ${DIM}历史基线 · Nmap${RESET}"
    echo -e "    ${NEON_PINK}▸${RESET} ${BOLD}3${RESET}  指定目标完整综合分析     ${DIM}授权 IPv4 · 深度端口 · Web 检查${RESET}"
    echo -e "    ${NEON_PINK}▸${RESET} ${BOLD}4${RESET}  最新威胁报告             ${DIM}重新运行分析后端${RESET}"
    echo -e "    ${NEON_PINK}▸${RESET} ${BOLD}5${RESET}  历史变化                 ${DIM}新增资产 · 新端口 · 消失资产${RESET}"
    echo -e "    ${NEON_PINK}▸${RESET} ${BOLD}6${RESET}  扫描历史                 ${DIM}本地 SQLite 批次${RESET}"
    echo -e "    ${NEON_PINK}▸${RESET} ${BOLD}7${RESET}  高级兼容工具"
    echo -e "    ${NEON_PINK}▸${RESET} ${BOLD}8${RESET}  帮助"
    echo -e "    ${NEON_PINK}▸${RESET} ${BOLD}0${RESET}  断开连接"
    echo ""
    hr
    read -r -p "  > 输入指令 [0-8]: " choice
    echo ""
    case "$choice" in
        1) run_home_analysis;  read -r -p "  按回车键返回主菜单...";;
        2) run_quick_analysis; read -r -p "  按回车键返回主菜单...";;
        3) run_full_analysis;  read -r -p "  按回车键返回主菜单...";;
        4) show_latest_report; read -r -p "  按回车键返回主菜单...";;
        5) show_changes;       read -r -p "  按回车键返回主菜单...";;
        6) show_history;       read -r -p "  按回车键返回主菜单...";;
        7) advanced_menu;;
        8) show_help;;
        0) exit_sequence; exit 0;;
        *) echo -e "${NEON_RED}  [!] 未知指令，请重新输入${RESET}"; beep; sleep 0.6;;
    esac
done
