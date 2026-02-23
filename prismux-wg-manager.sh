#!/usr/bin/env bash
set -euo pipefail

# Prismux + WireGuard manager script (adapted from udplex-wg-manager)
#
# Commands:
#   install | uninstall | start | stop | pause | resume | status | logs
#   show-keys | update | reload | lang <zh|en> | set-threshold <number>
#
# Example:
#   sudo bash prismux-wg-manager.sh install
#   sudo bash prismux-wg-manager.sh start

BASE_DIR="/opt/prismux"
COMPOSE_FILE="${BASE_DIR}/docker-compose.yml"
CONFIG_FILE="${BASE_DIR}/config.yaml"
ROLE_FILE="${BASE_DIR}/role"
SECRET_FILE="${BASE_DIR}/secret"
LANG_FILE="${BASE_DIR}/lang"
THRESHOLD_FILE="${BASE_DIR}/threshold"

WG_DIR="/etc/wireguard"
WG_CONF="${WG_DIR}/wg0.conf"
WG_PRIV="${WG_DIR}/wg_private.key"
WG_PUB="${WG_DIR}/wg_public.key"

DOCKER_INSTALL_SCRIPT_URL="https://get.docker.com"
PRISMUX_IMAGE="${PRISMUX_IMAGE:-ghcr.io/tao08141/prismux:latest}"

DOCKER_COMPOSE=""

get_lang() {
  if [[ -f "${LANG_FILE}" ]]; then
    cat "${LANG_FILE}"
  else
    echo "zh"
  fi
}

set_lang_file() {
  local lang="${1:-zh}"
  if [[ "$lang" != "zh" && "$lang" != "en" ]]; then
    lang="zh"
  fi
  mkdir -p "${BASE_DIR}"
  echo -n "$lang" > "${LANG_FILE}"
}

LANG_SEL="$(get_lang)"

t() {
  local key="$1"
  shift || true
  local msg=""
  case "${key}|${LANG_SEL}" in
    "need_root|zh") msg="请使用 root 权限运行脚本（例如：sudo bash $0 ...）" ;;
    "need_root|en") msg="Please run this script as root (e.g., sudo bash $0 ...)." ;;

    "docker_installed|zh") msg="Docker 已安装。" ;;
    "docker_installed|en") msg="Docker is already installed." ;;
    "docker_installing|zh") msg="正在安装 Docker..." ;;
    "docker_installing|en") msg="Installing Docker..." ;;
    "compose_missing|zh") msg="未检测到 docker compose，尝试安装 compose 插件..." ;;
    "compose_missing|en") msg="Docker compose not found. Trying to install compose plugin..." ;;
    "compose_failed|zh") msg="无法自动安装 docker compose，请手动安装后重试。" ;;
    "compose_failed|en") msg="Failed to auto-install docker compose. Install it manually and retry." ;;

    "wg_installed|zh") msg="WireGuard 已安装。" ;;
    "wg_installed|en") msg="WireGuard is already installed." ;;
    "wg_installing|zh") msg="正在安装 WireGuard..." ;;
    "wg_installing|en") msg="Installing WireGuard..." ;;

    "gen_keys|zh") msg="正在生成 WireGuard 密钥..." ;;
    "gen_keys|en") msg="Generating WireGuard keys..." ;;
    "keys_exist|zh") msg="检测到已存在 WireGuard 密钥，跳过生成。" ;;
    "keys_exist|en") msg="WireGuard keys already exist. Skipping generation." ;;
    "show_pub|zh") msg="本机 WireGuard 公钥（请复制给对端）：" ;;
    "show_pub|en") msg="Local WireGuard public key (share with peer):" ;;

    "prompt_threshold|zh") msg="设置带宽阈值 bps（默认 50000000）: " ;;
    "prompt_threshold|en") msg="Set bandwidth threshold in bps (default 50000000): " ;;
    "threshold_saved|zh") msg="带宽阈值已设置为 %s bps" ;;
    "threshold_saved|en") msg="Bandwidth threshold set to %s bps" ;;

    "select_role|zh") msg="选择角色: [1] 入口(client)  [2] 出口(server)" ;;
    "select_role|en") msg="Select role: [1] Entry(client)  [2] Exit(server)" ;;
    "invalid_choice|zh") msg="无效选择。" ;;
    "invalid_choice|en") msg="Invalid choice." ;;

    "secret_found|zh") msg="检测到已存在共享密钥，将复用。" ;;
    "secret_found|en") msg="Existing shared secret found. Reusing it." ;;
    "prompt_secret|zh") msg="设置 Prismux 鉴权密钥（两端一致，留空自动生成）: " ;;
    "prompt_secret|en") msg="Set Prismux auth secret (must match on both ends, empty to auto-generate): " ;;

    "prompt_peer_pub|zh") msg="请粘贴对端 WireGuard 公钥：" ;;
    "prompt_peer_pub|en") msg="Paste the peer WireGuard public key:" ;;
    "bad_pubkey|zh") msg="公钥格式不正确，请重试。" ;;
    "bad_pubkey|en") msg="Invalid public key format. Try again." ;;

    "enable_tcp|zh") msg="是否启用 UDP over TCP（使用 tcp_tunnel_* 组件）? (y/N): " ;;
    "enable_tcp|en") msg="Enable UDP over TCP (use tcp_tunnel_* components)? (y/N): " ;;

    "compose_written|zh") msg="已生成 docker-compose.yml" ;;
    "compose_written|en") msg="docker-compose.yml generated." ;;
    "client_cfg_written|zh") msg="已生成客户端 config.yaml" ;;
    "client_cfg_written|en") msg="Client config.yaml generated." ;;
    "server_cfg_written|zh") msg="已生成服务端 config.yaml" ;;
    "server_cfg_written|en") msg="Server config.yaml generated." ;;
    "wg_client_written|zh") msg="已生成 WireGuard 客户端配置 /etc/wireguard/wg0.conf" ;;
    "wg_client_written|en") msg="WireGuard client config /etc/wireguard/wg0.conf generated." ;;
    "wg_server_written|zh") msg="已生成 WireGuard 服务端配置 /etc/wireguard/wg0.conf" ;;
    "wg_server_written|en") msg="WireGuard server config /etc/wireguard/wg0.conf generated." ;;

    "prompt_client_wg_port|zh") msg="客户端本地 Prismux 监听端口（默认 7000）: " ;;
    "prompt_client_wg_port|en") msg="Client local listen port (default 7000): " ;;
    "prompt_line1|zh") msg="转发线路1目标地址（出口IP:端口，例如 1.2.3.4:9000）: " ;;
    "prompt_line1|en") msg="Forward line #1 target (ExitIP:port, e.g. 1.2.3.4:9000): " ;;
    "prompt_line2|zh") msg="转发线路2目标地址（出口IP:端口，例如 1.2.3.4:9001）: " ;;
    "prompt_line2|en") msg="Forward line #2 target (ExitIP:port, e.g. 1.2.3.4:9001): " ;;
    "need_two_lines|zh") msg="必须提供两条线路目标地址。" ;;
    "need_two_lines|en") msg="Both forward line targets are required." ;;

    "prompt_server_p1|zh") msg="服务端线路1监听端口（默认 9000）: " ;;
    "prompt_server_p1|en") msg="Server line #1 listen port (default 9000): " ;;
    "prompt_server_p2|zh") msg="服务端线路2监听端口（默认 9001）: " ;;
    "prompt_server_p2|en") msg="Server line #2 listen port (default 9001): " ;;
    "prompt_server_wg|zh") msg="WireGuard 服务端端口（默认 51820）: " ;;
    "prompt_server_wg|en") msg="WireGuard server port (default 51820): " ;;

    "prompt_client_addr|zh") msg="WireGuard 本机地址（默认 10.0.0.1/24）: " ;;
    "prompt_client_addr|en") msg="WireGuard local address (default 10.0.0.1/24): " ;;
    "prompt_client_peer|zh") msg="WireGuard 对端地址（默认 10.0.0.2）: " ;;
    "prompt_client_peer|en") msg="WireGuard peer address (default 10.0.0.2): " ;;
    "prompt_server_addr|zh") msg="WireGuard 本机地址（默认 10.0.0.2/24）: " ;;
    "prompt_server_addr|en") msg="WireGuard local address (default 10.0.0.2/24): " ;;
    "prompt_server_peer|zh") msg="WireGuard 对端地址（默认 10.0.0.1）: " ;;
    "prompt_server_peer|en") msg="WireGuard peer address (default 10.0.0.1): " ;;

    "install_done|zh") msg="安装准备完成。下一步可执行: sudo bash $0 start" ;;
    "install_done|en") msg="Install prepared. Next run: sudo bash $0 start" ;;

    "start_prismux|zh") msg="Prismux 容器已启动。" ;;
    "start_prismux|en") msg="Prismux container started." ;;
    "start_wg_ok|zh") msg="WireGuard 已启动。" ;;
    "start_wg_ok|en") msg="WireGuard started." ;;
    "start_wg_fail|zh") msg="WireGuard 启动失败，请检查配置和密钥。" ;;
    "start_wg_fail|en") msg="WireGuard failed to start. Check config and keys." ;;
    "wg_enable_boot|zh") msg="已设置 WireGuard 开机自启。" ;;
    "wg_enable_boot|en") msg="WireGuard enabled on boot." ;;

    "stopped_all|zh") msg="Prismux 与 WireGuard 均已停止。" ;;
    "stopped_all|en") msg="Prismux and WireGuard stopped." ;;
    "paused_wg|zh") msg="已暂停 WireGuard (wg0 down)，Prismux 保持运行。" ;;
    "paused_wg|en") msg="WireGuard paused (wg0 down), Prismux keeps running." ;;
    "wg_not_running|zh") msg="WireGuard wg0 未运行。" ;;
    "wg_not_running|en") msg="WireGuard wg0 is not running." ;;
    "resumed_wg|zh") msg="WireGuard wg0 已恢复。" ;;
    "resumed_wg|en") msg="WireGuard wg0 resumed." ;;
    "wg_start_failed|zh") msg="WireGuard 启动失败。" ;;
    "wg_start_failed|en") msg="WireGuard start failed." ;;

    "no_config|zh") msg="未找到配置，请先执行: sudo bash $0 install" ;;
    "no_config|en") msg="Config not found. Run: sudo bash $0 install first." ;;
    "no_compose|zh") msg="未找到 docker-compose.yml" ;;
    "no_compose|en") msg="docker-compose.yml not found." ;;
    "logs_follow|zh") msg="正在跟随 Prismux 容器日志..." ;;
    "logs_follow|en") msg="Following Prismux container logs..." ;;

    "updated_image|zh") msg="镜像已更新并重启容器。" ;;
    "updated_image|en") msg="Image updated and container restarted." ;;
    "reload_done|zh") msg="配置已重载（compose up -d）。" ;;
    "reload_done|en") msg="Configuration reloaded (compose up -d)." ;;

    "show_local_pub|zh") msg="本机 WireGuard 公钥：" ;;
    "show_local_pub|en") msg="Local WireGuard public key:" ;;
    "no_local_pub|zh") msg="未找到本机公钥，请先执行 install。" ;;
    "no_local_pub|en") msg="No local public key found. Run install first." ;;

    "lang_set|zh") msg="语言已切换为: %s" ;;
    "lang_set|en") msg="Language switched to: %s" ;;
    "threshold_updated|zh") msg="带宽阈值已更新为 %s bps" ;;
    "threshold_updated|en") msg="Bandwidth threshold updated to %s bps" ;;
    "threshold_patch_fail|zh") msg="配置中未找到 seq 分流规则，请重新 install 生成配置。" ;;
    "threshold_patch_fail|en") msg="Config does not contain seq split rules. Re-run install to regenerate config." ;;

    "uninstall_confirm|zh") msg="将停止服务并删除 %s 下文件，继续? (y/N): " ;;
    "uninstall_confirm|en") msg="This will stop services and remove files under %s. Continue? (y/N): " ;;
    "uninstall_cancel|zh") msg="已取消。" ;;
    "uninstall_cancel|en") msg="Cancelled." ;;
    "removed_base|zh") msg="已删除 %s" ;;
    "removed_base|en") msg="%s removed." ;;
    "prompt_del_wg|zh") msg="是否同时删除 WireGuard 配置和密钥（/etc/wireguard）? (y/N): " ;;
    "prompt_del_wg|en") msg="Also delete WireGuard config and keys in /etc/wireguard? (y/N): " ;;
    "deleted_wg|zh") msg="已删除 WireGuard 配置和密钥。" ;;
    "deleted_wg|en") msg="WireGuard config and keys deleted." ;;
    "kept_wg|zh") msg="已保留 WireGuard 配置和密钥。" ;;
    "kept_wg|en") msg="WireGuard config and keys kept." ;;
    "uninstall_done|zh") msg="卸载完成。" ;;
    "uninstall_done|en") msg="Uninstall completed." ;;

    "unknown_cmd|zh") msg="未知命令: %s" ;;
    "unknown_cmd|en") msg="Unknown command: %s" ;;
    *) msg="$key" ;;
  esac
  # shellcheck disable=SC2059
  printf -- "$msg" "$@"
}

info() { echo "[INFO] $(t "$@")"; }
warn() { echo "[WARN] $(t "$@")"; }
err() { echo "[ERROR] $(t "$@")" >&2; }

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    err need_root
    exit 1
  fi
}

detect_pkg_mgr() {
  if command -v apt-get >/dev/null 2>&1; then
    echo "apt"
  elif command -v dnf >/dev/null 2>&1; then
    echo "dnf"
  elif command -v yum >/dev/null 2>&1; then
    echo "yum"
  else
    echo ""
  fi
}

ensure_dirs() {
  mkdir -p "${BASE_DIR}"
  mkdir -p "${WG_DIR}"
}

ensure_compose_cmd() {
  if docker compose version >/dev/null 2>&1; then
    DOCKER_COMPOSE="docker compose"
  elif command -v docker-compose >/dev/null 2>&1; then
    DOCKER_COMPOSE="docker-compose"
  else
    DOCKER_COMPOSE=""
  fi
}

install_docker() {
  if command -v docker >/dev/null 2>&1; then
    info docker_installed
  else
    info docker_installing
    curl -fsSL "${DOCKER_INSTALL_SCRIPT_URL}" -o /tmp/install-docker.sh
    sh /tmp/install-docker.sh
    rm -f /tmp/install-docker.sh
    systemctl enable docker >/dev/null 2>&1 || true
    systemctl start docker >/dev/null 2>&1 || true
  fi

  ensure_compose_cmd
  if [[ -n "${DOCKER_COMPOSE}" ]]; then
    return
  fi

  warn compose_missing
  local pm
  pm="$(detect_pkg_mgr)"
  if [[ "$pm" == "apt" ]]; then
    apt-get update -y
    apt-get install -y docker-compose-plugin || true
  elif [[ "$pm" == "dnf" ]]; then
    dnf install -y docker-compose-plugin || true
  elif [[ "$pm" == "yum" ]]; then
    yum install -y docker-compose-plugin || true
  fi

  ensure_compose_cmd
  if [[ -z "${DOCKER_COMPOSE}" ]]; then
    err compose_failed
    exit 1
  fi
}

install_wireguard() {
  if command -v wg >/dev/null 2>&1 && command -v wg-quick >/dev/null 2>&1; then
    info wg_installed
    return
  fi

  info wg_installing
  local pm
  pm="$(detect_pkg_mgr)"
  case "$pm" in
    apt)
      apt-get update -y
      apt-get install -y wireguard
      ;;
    dnf)
      dnf install -y epel-release || true
      dnf install -y wireguard-tools
      ;;
    yum)
      yum install -y epel-release || true
      yum install -y wireguard-tools
      ;;
    *)
      echo "Please install WireGuard manually (wireguard/wireguard-tools)."
      exit 1
      ;;
  esac
}

random_secret() {
  openssl rand -base64 32 2>/dev/null || head -c 32 /dev/urandom | base64
}

generate_wg_keys() {
  if [[ -f "${WG_PRIV}" && -f "${WG_PUB}" ]]; then
    info keys_exist
    return
  fi

  info gen_keys
  umask 077
  wg genkey | tee "${WG_PRIV}" | wg pubkey > "${WG_PUB}"
  chmod 600 "${WG_PRIV}" "${WG_PUB}"
}

show_local_pubkey() {
  if [[ -f "${WG_PUB}" ]]; then
    echo
    echo "========================================"
    t show_pub
    echo
    cat "${WG_PUB}"
    echo
    echo "========================================"
    echo
  fi
}

validate_pubkey() {
  local key="${1:-}"
  [[ -n "$key" ]] || return 1
  [[ "$key" =~ ^[A-Za-z0-9+/=]{40,60}$ ]] || return 1
  return 0
}

write_compose_file() {
  cat > "${COMPOSE_FILE}" <<YAML
services:
  prismux:
    image: ${PRISMUX_IMAGE}
    container_name: prismux
    restart: always
    command: ["-c", "/app/config.yaml"]
    volumes:
      - ./config.yaml:/app/config.yaml
    network_mode: host
    logging:
      options:
        max-size: "10m"
        max-file: "3"
YAML
  info compose_written
}

write_client_config() {
  local line1_addr="${1}"
  local line2_addr="${2}"
  local wg_input_port="${3}"
  local secret="${4}"
  local threshold="${5}"
  local proto="${6:-udp}"

  local type="forward"
  local nodelay_cfg=""
  local suffix=""

  if [[ "$proto" == "tcp" ]]; then
    type="tcp_tunnel_forward"
    nodelay_cfg="    no_delay: true"
    suffix=":4"
  fi

  cat > "${CONFIG_FILE}" <<YAML
buffer_size: 1500
queue_size: 10240
worker_count: 4
logging:
  level: info
  format: console
  output_path: stdout
  caller: true
services:
  - type: listen
    tag: wg_input
    listen_addr: 127.0.0.1:${wg_input_port}
    timeout: 120
    replace_old_mapping: true
    detour: [load_balancer]
  - type: ${type}
    tag: redundant_forward1
    forwarders: [${line1_addr}${suffix}]
    reconnect_interval: 5
    connection_check_time: 30
${nodelay_cfg}
    detour: [wg_input]
    auth:
      secret: ${secret}
      enabled: true
      enable_encryption: false
      heartbeat_interval: 30
  - type: ${type}
    tag: redundant_forward2
    forwarders: [${line2_addr}${suffix}]
    reconnect_interval: 5
    connection_check_time: 30
${nodelay_cfg}
    detour: [wg_input]
    auth:
      secret: ${secret}
      enabled: true
      enable_encryption: false
      heartbeat_interval: 30
  - type: load_balancer
    tag: load_balancer
    window_size: 3
    detour:
      - rule: "bps <= ${threshold} || !available_redundant_forward1 || !available_redundant_forward2"
        targets: [redundant_forward1, redundant_forward2]
      - rule: "(bps > ${threshold}) && (seq % 2 == 0) && available_redundant_forward1 && available_redundant_forward2"
        targets: [redundant_forward1]
      - rule: "(bps > ${threshold}) && (seq % 2 == 1) && available_redundant_forward2 && available_redundant_forward1"
        targets: [redundant_forward2]
YAML
  info client_cfg_written
}

write_server_config() {
  local listen1_port="${1}"
  local listen2_port="${2}"
  local wg_port="${3}"
  local secret="${4}"
  local threshold="${5}"
  local proto="${6:-udp}"

  local type="listen"
  local nodelay_cfg=""

  if [[ "$proto" == "tcp" ]]; then
    type="tcp_tunnel_listen"
    nodelay_cfg="    no_delay: true"
  fi

  cat > "${CONFIG_FILE}" <<YAML
buffer_size: 1500
queue_size: 10240
worker_count: 4
logging:
  level: info
  format: console
  output_path: stdout
  caller: true
services:
  - type: ${type}
    tag: server_listen1
    listen_addr: 0.0.0.0:${listen1_port}
    timeout: 120
    replace_old_mapping: false
${nodelay_cfg}
    detour: [wg_forward]
    auth:
      secret: ${secret}
      enabled: true
      enable_encryption: false
      heartbeat_interval: 30
  - type: ${type}
    tag: server_listen2
    listen_addr: 0.0.0.0:${listen2_port}
    timeout: 120
    replace_old_mapping: false
${nodelay_cfg}
    detour: [wg_forward]
    auth:
      secret: ${secret}
      enabled: true
      enable_encryption: false
      heartbeat_interval: 30
  - type: forward
    tag: wg_forward
    forwarders: [127.0.0.1:${wg_port}]
    reconnect_interval: 5
    connection_check_time: 30
    send_keepalive: false
    detour: [load_balancer]
  - type: load_balancer
    tag: load_balancer
    window_size: 3
    detour:
      - rule: "bps <= ${threshold} || !available_server_listen1 || !available_server_listen2"
        targets: [server_listen1, server_listen2]
      - rule: "(bps > ${threshold}) && (seq % 2 == 0) && available_server_listen1 && available_server_listen2"
        targets: [server_listen1]
      - rule: "(bps > ${threshold}) && (seq % 2 == 1) && available_server_listen2 && available_server_listen1"
        targets: [server_listen2]
YAML
  info server_cfg_written
}

write_wg_conf_client() {
  local local_addr="${1}"
  local peer_addr="${2}"
  local peer_pubkey="${3}"
  local wg_input_port="${4}"

  local priv
  priv="$(cat "${WG_PRIV}")"
  cat > "${WG_CONF}" <<CONF
[Interface]
PrivateKey = ${priv}
Address = ${local_addr}

[Peer]
PublicKey = ${peer_pubkey}
Endpoint = 127.0.0.1:${wg_input_port}
AllowedIPs = ${peer_addr}/32
PersistentKeepalive = 25
CONF
  chmod 600 "${WG_CONF}"
  info wg_client_written
}

write_wg_conf_server() {
  local local_addr="${1}"
  local peer_addr="${2}"
  local peer_pubkey="${3}"
  local wg_port="${4}"

  local priv
  priv="$(cat "${WG_PRIV}")"
  cat > "${WG_CONF}" <<CONF
[Interface]
PrivateKey = ${priv}
Address = ${local_addr}
ListenPort = ${wg_port}

[Peer]
PublicKey = ${peer_pubkey}
AllowedIPs = ${peer_addr}/32
PersistentKeepalive = 25
CONF
  chmod 600 "${WG_CONF}"
  info wg_server_written
}

install_flow() {
  need_root
  ensure_dirs
  install_docker
  install_wireguard
  generate_wg_keys
  show_local_pubkey

  echo "Language / 语言: [1] English  [2] 中文"
  read -rp "> " lang_sel || true
  case "${lang_sel:-}" in
    1) set_lang_file "en" ;;
    2) set_lang_file "zh" ;;
    *) : ;;
  esac
  LANG_SEL="$(get_lang)"

  local threshold="50000000"
  read -rp "$(t prompt_threshold)" input_threshold || true
  if [[ -n "${input_threshold:-}" && "${input_threshold}" =~ ^[0-9]+$ ]]; then
    threshold="${input_threshold}"
  fi
  echo -n "${threshold}" > "${THRESHOLD_FILE}"
  info threshold_saved "${threshold}"

  echo "$(t select_role)"
  read -rp "> " role_sel
  local role=""
  if [[ "$role_sel" == "1" ]]; then
    role="client"
  elif [[ "$role_sel" == "2" ]]; then
    role="server"
  else
    err invalid_choice
    exit 1
  fi
  echo -n "${role}" > "${ROLE_FILE}"

  local secret=""
  if [[ -f "${SECRET_FILE}" ]]; then
    info secret_found
    secret="$(cat "${SECRET_FILE}")"
  else
    local default_secret
    default_secret="$(random_secret)"
    read -rp "$(t prompt_secret)" secret_input || true
    secret="${secret_input:-$default_secret}"
    echo -n "${secret}" > "${SECRET_FILE}"
  fi

  local peer_pubkey=""
  while true; do
    echo
    echo "$(t prompt_peer_pub)"
    read -r peer_pubkey
    if validate_pubkey "${peer_pubkey}"; then
      break
    fi
    warn bad_pubkey
  done

  local proto="udp"
  printf "$(t enable_tcp)"
  read -r enable_tcp_ans || true
  if [[ "${enable_tcp_ans:-}" =~ ^[Yy]$ ]]; then
    proto="tcp"
  fi

  write_compose_file

  if [[ "$role" == "client" ]]; then
    local wg_input_port line1_addr line2_addr
    read -rp "$(t prompt_client_wg_port)" wg_input_port || true
    wg_input_port="${wg_input_port:-7000}"
    read -rp "$(t prompt_line1)" line1_addr
    read -rp "$(t prompt_line2)" line2_addr
    if [[ -z "${line1_addr}" || -z "${line2_addr}" ]]; then
      err need_two_lines
      exit 1
    fi
    write_client_config "${line1_addr}" "${line2_addr}" "${wg_input_port}" "${secret}" "${threshold}" "${proto}"

    local local_addr peer_addr
    read -rp "$(t prompt_client_addr)" local_addr || true
    local_addr="${local_addr:-10.0.0.1/24}"
    read -rp "$(t prompt_client_peer)" peer_addr || true
    peer_addr="${peer_addr:-10.0.0.2}"
    write_wg_conf_client "${local_addr}" "${peer_addr}" "${peer_pubkey}" "${wg_input_port}"
  else
    local listen1_port listen2_port wg_port
    read -rp "$(t prompt_server_p1)" listen1_port || true
    listen1_port="${listen1_port:-9000}"
    read -rp "$(t prompt_server_p2)" listen2_port || true
    listen2_port="${listen2_port:-9001}"
    read -rp "$(t prompt_server_wg)" wg_port || true
    wg_port="${wg_port:-51820}"
    write_server_config "${listen1_port}" "${listen2_port}" "${wg_port}" "${secret}" "${threshold}" "${proto}"

    local local_addr peer_addr
    read -rp "$(t prompt_server_addr)" local_addr || true
    local_addr="${local_addr:-10.0.0.2/24}"
    read -rp "$(t prompt_server_peer)" peer_addr || true
    peer_addr="${peer_addr:-10.0.0.1}"
    write_wg_conf_server "${local_addr}" "${peer_addr}" "${peer_pubkey}" "${wg_port}"
  fi

  echo
  info install_done
  show_local_pubkey
}

start_services() {
  need_root
  ensure_compose_cmd
  if [[ ! -f "${COMPOSE_FILE}" || ! -f "${CONFIG_FILE}" ]]; then
    err no_config
    exit 1
  fi
  if [[ -z "${DOCKER_COMPOSE}" ]]; then
    err compose_failed
    exit 1
  fi

  $DOCKER_COMPOSE -f "${COMPOSE_FILE}" up -d
  info start_prismux

  if wg-quick up wg0 2>/dev/null; then
    info start_wg_ok
  else
    warn start_wg_fail
  fi

  systemctl enable wg-quick@wg0 >/dev/null 2>&1 || true
  info wg_enable_boot
}

stop_services() {
  need_root
  ensure_compose_cmd
  if wg show wg0 >/dev/null 2>&1; then
    wg-quick down wg0 || true
  fi
  if [[ -n "${DOCKER_COMPOSE}" && -f "${COMPOSE_FILE}" ]]; then
    $DOCKER_COMPOSE -f "${COMPOSE_FILE}" down || true
  fi
  info stopped_all
}

pause_wg() {
  need_root
  if wg show wg0 >/dev/null 2>&1; then
    wg-quick down wg0 || true
    info paused_wg
  else
    info wg_not_running
  fi
}

resume_wg() {
  need_root
  if wg-quick up wg0; then
    info resumed_wg
  else
    err wg_start_failed
    exit 1
  fi
}

show_status() {
  ensure_compose_cmd
  echo "=== Prismux ==="
  if [[ -n "${DOCKER_COMPOSE}" && -f "${COMPOSE_FILE}" ]]; then
    $DOCKER_COMPOSE -f "${COMPOSE_FILE}" ps || true
  else
    t no_compose
    echo
  fi

  echo
  echo "=== WireGuard ==="
  if command -v wg >/dev/null 2>&1; then
    wg show || true
  else
    echo "WireGuard not installed."
  fi

  echo
  echo "=== Listening Ports ==="
  if command -v ss >/dev/null 2>&1; then
    ss -lunpt | grep -E ":(7000|9000|9001|51820)\b" || true
  elif command -v netstat >/dev/null 2>&1; then
    netstat -tulpn | grep -E ":(7000|9000|9001|51820)\b" || true
  else
    echo "Neither ss nor netstat exists."
  fi

  echo
  echo "=== Meta ==="
  if [[ -f "${ROLE_FILE}" ]]; then
    echo "Role: $(cat "${ROLE_FILE}")"
  else
    echo "Role: (unset)"
  fi
  echo "BASE_DIR: ${BASE_DIR}"
  echo "COMPOSE_FILE: ${COMPOSE_FILE}"
  echo "CONFIG_FILE: ${CONFIG_FILE}"
  echo "WG_CONF: ${WG_CONF}"
  if [[ -f "${THRESHOLD_FILE}" ]]; then
    echo "Threshold(bps): $(cat "${THRESHOLD_FILE}")"
  else
    echo "Threshold(bps): 50000000"
  fi
  echo "Language: $(get_lang)"
  echo "Image: ${PRISMUX_IMAGE}"
}

show_logs() {
  ensure_compose_cmd
  if [[ -z "${DOCKER_COMPOSE}" || ! -f "${COMPOSE_FILE}" ]]; then
    err no_compose
    exit 1
  fi
  t logs_follow
  echo
  $DOCKER_COMPOSE -f "${COMPOSE_FILE}" logs -f
}

update_image() {
  ensure_compose_cmd
  if [[ -z "${DOCKER_COMPOSE}" || ! -f "${COMPOSE_FILE}" ]]; then
    err no_compose
    exit 1
  fi
  $DOCKER_COMPOSE -f "${COMPOSE_FILE}" pull
  $DOCKER_COMPOSE -f "${COMPOSE_FILE}" up -d
  info updated_image
}

reload_services() {
  ensure_compose_cmd
  if [[ -z "${DOCKER_COMPOSE}" || ! -f "${COMPOSE_FILE}" ]]; then
    err no_compose
    exit 1
  fi
  $DOCKER_COMPOSE -f "${COMPOSE_FILE}" up -d
  info reload_done
}

show_keys() {
  if [[ -f "${WG_PUB}" ]]; then
    t show_local_pub
    echo
    cat "${WG_PUB}"
    echo
  else
    err no_local_pub
  fi
}

patch_threshold_in_config() {
  local new="$1"
  if ! grep -q 'seq % 2' "${CONFIG_FILE}" 2>/dev/null; then
    err threshold_patch_fail
    exit 1
  fi
  sed -i -E "s/(\"rule\": \"bps <= )([0-9]+)(\")/\1${new}\3/" "${CONFIG_FILE}"
  sed -i -E "s/(\"rule\": \"\(bps > )([0-9]+)(\) && \(seq % 2 == 0\).*\")/\1${new}\3/" "${CONFIG_FILE}"
  sed -i -E "s/(\"rule\": \"\(bps > )([0-9]+)(\) && \(seq % 2 == 1\).*\")/\1${new}\3/" "${CONFIG_FILE}"
}

uninstall_flow() {
  need_root
  printf "$(t uninstall_confirm "${BASE_DIR}")"
  read -r ans || true
  ans="${ans:-N}"
  if [[ ! "$ans" =~ ^[Yy]$ ]]; then
    echo "$(t uninstall_cancel)"
    exit 0
  fi

  stop_services
  rm -rf "${BASE_DIR}"
  info removed_base "${BASE_DIR}"

  printf "$(t prompt_del_wg)"
  read -r delwg || true
  delwg="${delwg:-N}"
  if [[ "$delwg" =~ ^[Yy]$ ]]; then
    rm -f "${WG_CONF}" "${WG_PRIV}" "${WG_PUB}"
    info deleted_wg
  else
    info kept_wg
  fi

  info uninstall_done
}

usage() {
  cat <<EOF
Usage: sudo bash $0 <command>

Commands:
  install                Install and interactively configure Prismux + WireGuard
  uninstall              Uninstall (optionally remove WireGuard config and keys)
  start                  Start Prismux container and WireGuard
  stop                   Stop Prismux container and WireGuard
  pause                  Pause WireGuard (wg0 down), keep Prismux running
  resume                 Resume WireGuard (wg0 up)
  status                 Show status
  logs                   Follow Prismux logs
  update                 Pull latest image and restart container
  reload                 Reload configuration (docker compose up -d)
  show-keys              Print local WireGuard public key
  lang <zh|en>           Switch script language
  set-threshold <bps>    Update load_balancer threshold in config.yaml, then run reload

Env:
  PRISMUX_IMAGE          Override image used in compose (default: ghcr.io/tao08141/prismux:latest)

Examples:
  sudo bash $0 install
  sudo bash $0 set-threshold 80000000 && sudo bash $0 reload
  sudo bash $0 lang en
EOF
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    install) install_flow ;;
    uninstall) uninstall_flow ;;
    start) start_services ;;
    stop) stop_services ;;
    pause) pause_wg ;;
    resume) resume_wg ;;
    status) show_status ;;
    logs) show_logs ;;
    update) update_image ;;
    reload) reload_services ;;
    show-keys) show_keys ;;
    lang)
      shift || true
      local lang="${1:-zh}"
      if [[ "$lang" != "zh" && "$lang" != "en" ]]; then
        lang="zh"
      fi
      set_lang_file "$lang"
      LANG_SEL="$(get_lang)"
      info lang_set "$lang"
      ;;
    set-threshold)
      shift || true
      local new="${1:-}"
      if [[ -z "${new}" || ! "${new}" =~ ^[0-9]+$ ]]; then
        echo "Usage: sudo bash $0 set-threshold <bps>"
        exit 1
      fi
      echo -n "${new}" > "${THRESHOLD_FILE}"
      if [[ -f "${CONFIG_FILE}" ]]; then
        patch_threshold_in_config "${new}"
      fi
      info threshold_updated "${new}"
      ;;
    ""|-h|--help|help)
      usage
      ;;
    *)
      err unknown_cmd "$cmd"
      usage
      exit 1
      ;;
  esac
}

main "$@"
