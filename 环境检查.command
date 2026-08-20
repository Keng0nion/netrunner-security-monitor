#!/bin/bash
# NETRUNNER 环境检查 / 依赖安装（macOS）

set -u
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

RED='\033[38;5;196m'; GREEN='\033[38;5;46m'; YELLOW='\033[38;5;226m'
CYAN='\033[38;5;51m'; PURPLE='\033[38;5;135m'; BOLD='\033[1m'; RESET='\033[0m'

pause_before_exit() {
    if [ -t 0 ]; then
        read -r -p "  按回车键退出..." _unused
    fi
}

fail_exit() {
    local code="$1"
    shift
    echo -e "  ${RED}[!] $*${RESET}" >&2
    echo ""
    pause_before_exit
    exit "$code"
}

command_path() {
    command -v "$1" 2>/dev/null || true
}

activate_brew() {
    local shellenv_output
    [ -n "$BREW_BIN" ] && [ -x "$BREW_BIN" ] || return 1
    shellenv_output="$("$BREW_BIN" shellenv)" || return 1
    eval "$shellenv_output"
}

node_is_compatible() {
    local node_path major
    node_path="$(command_path node)"
    [ -n "$node_path" ] || return 1
    major="$("$node_path" -p "process.versions.node.split('.')[0]" 2>/dev/null)"
    [[ "$major" =~ ^[0-9]+$ ]] && [ "$major" -ge 18 ]
}

echo ""
echo -e "  ${PURPLE}╔══════════════════════════════════════════════════════╗${RESET}"
echo -e "  ${PURPLE}║${RESET}  ${GREEN}${BOLD}NETRUNNER${RESET} ${CYAN}// 环境诊断${RESET}                              ${PURPLE}║${RESET}"
echo -e "  ${PURPLE}╚══════════════════════════════════════════════════════╝${RESET}"
echo ""

if [[ "$(uname -s)" != "Darwin" ]]; then
    fail_exit 1 "本脚本只适配 macOS，检测到系统: $(uname -s)"
fi

ARCH="$(uname -m)"
case "$ARCH" in
    arm64)
        BREW_PREFIX="/opt/homebrew"
        echo -e "${GREEN}[*] 检测到 Apple Silicon (arm64)${RESET}"
        ;;
    x86_64)
        BREW_PREFIX="/usr/local"
        echo -e "${GREEN}[*] 检测到 Intel Mac (x86_64)${RESET}"
        ;;
    *)
        fail_exit 1 "不支持的 macOS 架构: $ARCH"
        ;;
esac

BREW_BIN=""
if [ -x "$BREW_PREFIX/bin/brew" ]; then
    BREW_BIN="$BREW_PREFIX/bin/brew"
elif [ -x "/opt/homebrew/bin/brew" ]; then
    BREW_BIN="/opt/homebrew/bin/brew"
elif [ -x "/usr/local/bin/brew" ]; then
    BREW_BIN="/usr/local/bin/brew"
else
    detected_brew="$(command_path brew)"
    if [ -n "$detected_brew" ] && [ -x "$detected_brew" ]; then
        BREW_BIN="$detected_brew"
    fi
fi

if [ -n "$BREW_BIN" ]; then
    detected_prefix="$($BREW_BIN --prefix 2>/dev/null)" || fail_exit 1 "无法读取 Homebrew prefix。"
    BREW_PREFIX="$detected_prefix"
    activate_brew || fail_exit 1 "Homebrew shellenv 加载失败。"
fi

echo ""
echo -e "${BOLD}[1/3] Profile 依赖说明${RESET}"
echo "  home  : Python 3 + Node.js 18+（主流程必需；网络/WiFi/蓝牙采集）"
echo "  quick : home + nmap（指定授权目标的服务识别）"
echo "  full  : quick + masscan（授权 IP 高速端口采集）+ nikto（授权 Web 服务检查）"
echo "  OSINT : theharvester 仅用于你获授权的域名公开信息收集"
echo -e "  ${YELLOW}说明：nmap、masscan、nikto、theharvester 不是 home 档位的必需项。${RESET}"

echo ""
echo -e "${BOLD}[2/3] 检查当前环境${RESET}"

if [ -n "$BREW_BIN" ]; then
    echo -e "  ${GREEN}[✓]${RESET} Homebrew  ($BREW_BIN)"
else
    echo -e "  ${YELLOW}[!]${RESET} Homebrew 未安装（仅自动安装缺失工具时需要）"
fi

declare -a MISSING_BREW_PKGS=()
declare -a MISSING_COMMANDS=()
declare -a MISSING_LABELS=()
declare -a MISSING_SCOPES=()
REQUIRED_MISSING=0

record_missing() {
    local command_name="$1" label="$2" brew_pkg="$3" scope="$4" required="$5"
    if [[ "$required" == "required" ]]; then
        echo -e "  ${RED}[✗]${RESET} $label — 缺失或版本不合格（$scope，必需）"
        REQUIRED_MISSING=$((REQUIRED_MISSING + 1))
    else
        echo -e "  ${YELLOW}[✗]${RESET} $label — 未安装（$scope，可选）"
    fi
    MISSING_COMMANDS+=("$command_name")
    MISSING_LABELS+=("$label")
    MISSING_BREW_PKGS+=("$brew_pkg")
    MISSING_SCOPES+=("$scope")
}

PYTHON_PATH="$(command_path python3)"
if [ -n "$PYTHON_PATH" ] && "$PYTHON_PATH" -c 'import sys; raise SystemExit(0 if sys.version_info.major == 3 else 1)' 2>/dev/null; then
    echo -e "  ${GREEN}[✓]${RESET} Python 3  ($PYTHON_PATH) — home/quick/full 必需"
else
    record_missing python3 "Python 3" python "home/quick/full" required
fi

NODE_PATH="$(command_path node)"
if node_is_compatible; then
    echo -e "  ${GREEN}[✓]${RESET} Node.js $($NODE_PATH --version)  ($NODE_PATH) — home/quick/full 必需"
else
    if [ -n "$NODE_PATH" ]; then
        echo -e "  ${YELLOW}[!]${RESET} 当前 Node.js: $($NODE_PATH --version 2>/dev/null || echo 版本未知)；要求 18+"
    fi
    record_missing node "Node.js 18+" node "home/quick/full" required
fi

check_optional() {
    local command_name="$1" label="$2" brew_pkg="$3" scope="$4"
    local path
    path="$(command_path "$command_name")"
    if [ -n "$path" ]; then
        echo -e "  ${GREEN}[✓]${RESET} $label  ($path) — $scope"
    else
        record_missing "$command_name" "$label" "$brew_pkg" "$scope" optional
    fi
}

check_optional nmap "nmap" nmap "quick/full 的授权目标服务识别"
check_optional masscan "masscan" masscan "full 的授权 IP 高速端口采集"
check_optional nikto "nikto" nikto "full 的授权 Web 服务检查"
check_optional theharvester "theharvester" theharvester "授权域名 OSINT"

echo ""
echo -e "${BOLD}[3/3] 汇总与修复${RESET}"

if [ ${#MISSING_BREW_PKGS[@]} -eq 0 ]; then
    echo -e "  ${GREEN}[✓] 主流程与全部扩展 profile 依赖均已就绪。${RESET}"
    echo ""
    pause_before_exit
    exit 0
fi

if [ "$REQUIRED_MISSING" -eq 0 ]; then
    echo -e "  ${GREEN}[✓] home 主流程已就绪。${RESET}"
    echo -e "  ${YELLOW}[!] 以下扩展 profile 工具缺失：${RESET}"
else
    echo -e "  ${RED}[✗] home 主流程仍缺少 $REQUIRED_MISSING 个必需环境。${RESET}"
    echo -e "  ${YELLOW}以下项目需要安装或升级：${RESET}"
fi

for index in "${!MISSING_LABELS[@]}"; do
    echo "    - ${MISSING_LABELS[$index]}（${MISSING_SCOPES[$index]}）"
done

echo ""
if [ -z "$BREW_BIN" ]; then
    echo "  自动修复需要 Homebrew。官方安装器将从 brew.sh 指向的 GitHub 地址下载并执行。"
    read -r -p "  是否现在安装 Homebrew？[y/N]: " install_brew_answer
    if [[ ! "$install_brew_answer" =~ ^[Yy]$ ]]; then
        fail_exit 2 "已拒绝安装；环境仍有缺失项。"
    fi

    BREW_INSTALLER="$(mktemp -t netrunner-homebrew.XXXXXX)" || fail_exit 1 "无法创建 Homebrew 安装器临时文件。"
    if ! /usr/bin/curl -fsSL "https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh" -o "$BREW_INSTALLER"; then
        rm -f "$BREW_INSTALLER"
        fail_exit 1 "Homebrew 安装器下载失败。"
    fi
    if ! /bin/bash "$BREW_INSTALLER"; then
        rm -f "$BREW_INSTALLER"
        fail_exit 1 "Homebrew 安装失败。"
    fi
    rm -f "$BREW_INSTALLER"

    BREW_BIN="$BREW_PREFIX/bin/brew"
    if [ ! -x "$BREW_BIN" ]; then
        fail_exit 1 "Homebrew 安装后未找到预期可执行文件: $BREW_BIN"
    fi
    activate_brew || fail_exit 1 "Homebrew 安装成功，但 shellenv 加载失败。"
fi

read -r -p "  是否用 Homebrew 安装/升级以上缺失项？[y/N]: " install_answer
if [[ ! "$install_answer" =~ ^[Yy]$ ]]; then
    fail_exit 2 "已拒绝安装；环境仍有缺失项。"
fi

INSTALL_SCRIPT="$SCRIPT_DIR/安装缺失依赖.command"
{
    echo '#!/bin/bash'
    echo 'set -euo pipefail'
    printf 'BREW_BIN=%q\n' "$BREW_BIN"
    echo 'if [ ! -x "$BREW_BIN" ]; then'
    echo '    echo "[!] Homebrew 不可执行: $BREW_BIN" >&2'
    echo '    exit 1'
    echo 'fi'
    echo 'BREW_SHELLENV="$("$BREW_BIN" shellenv)" || exit 1'
    echo 'eval "$BREW_SHELLENV"'
    echo 'echo "开始安装缺失依赖..."'
    for pkg in "${MISSING_BREW_PKGS[@]}"; do
        printf 'echo %q\n' "--- $BREW_BIN install $pkg ---"
        printf '"$BREW_BIN" install %q\n' "$pkg"
    done
    echo 'echo "安装命令全部完成。"'
} > "$INSTALL_SCRIPT" || fail_exit 1 "无法生成安装脚本: $INSTALL_SCRIPT"

chmod +x "$INSTALL_SCRIPT" || fail_exit 1 "无法给安装脚本添加执行权限。"
echo -e "  ${GREEN}[*] 已生成安装脚本: $INSTALL_SCRIPT${RESET}"
echo -e "  ${GREEN}[*] 正在使用绝对 Homebrew 路径执行安装...${RESET}"

if ! "$INSTALL_SCRIPT"; then
    fail_exit 1 "依赖安装脚本执行失败。"
fi

activate_brew || fail_exit 1 "安装完成后 Homebrew shellenv 重新加载失败。"
echo ""
echo -e "${BOLD}[*] 重新检查缺失项：${RESET}"
RECHECK_FAILURES=0
for index in "${!MISSING_COMMANDS[@]}"; do
    command_name="${MISSING_COMMANDS[$index]}"
    label="${MISSING_LABELS[$index]}"
    if [ "$command_name" = "node" ]; then
        if node_is_compatible; then
            echo -e "  ${GREEN}[✓]${RESET} $label"
        else
            echo -e "  ${RED}[✗]${RESET} $label — 复检失败" >&2
            RECHECK_FAILURES=$((RECHECK_FAILURES + 1))
        fi
    elif [ "$command_name" = "python3" ]; then
        python_path="$(command_path python3)"
        if [ -n "$python_path" ] && "$python_path" -c 'import sys; raise SystemExit(0 if sys.version_info.major == 3 else 1)' 2>/dev/null; then
            echo -e "  ${GREEN}[✓]${RESET} $label"
        else
            echo -e "  ${RED}[✗]${RESET} $label — 复检失败" >&2
            RECHECK_FAILURES=$((RECHECK_FAILURES + 1))
        fi
    elif command -v "$command_name" &>/dev/null; then
        echo -e "  ${GREEN}[✓]${RESET} $label"
    else
        echo -e "  ${RED}[✗]${RESET} $label — 复检失败" >&2
        RECHECK_FAILURES=$((RECHECK_FAILURES + 1))
    fi
done

if [ "$RECHECK_FAILURES" -ne 0 ]; then
    fail_exit 1 "$RECHECK_FAILURES 个依赖在安装后复检失败。"
fi

echo ""
echo -e "  ${GREEN}[✓] 所有请求的依赖均已安装并通过复检。${RESET}"
pause_before_exit
exit 0
