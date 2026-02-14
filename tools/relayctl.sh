#!/usr/bin/env bash
# relayctl.sh – Hiddify Relay control script
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/hiddify-relay}"
APP_DIR="${APP_DIR:-${INSTALL_DIR}/apps/relay}"
ENV_PATH="${ENV_PATH:-/etc/hiddify-relay/.env}"
ENV_DIR="$(dirname "${ENV_PATH}")"
NGINX_SITE="${NGINX_SITE:-/etc/nginx/sites-available/hiddify-relay.conf}"
NGINX_LINK="${NGINX_LINK:-/etc/nginx/sites-enabled/hiddify-relay.conf}"
CACHE_DIR="${CACHE_DIR:-${APP_DIR}/storage/cache}"
LOG_FILE="${LOG_FILE:-${APP_DIR}/storage/relay.log}"
REPO_URL="${REPO_URL:-https://github.com/NaxonM/HiRelay.git}"
REPO_BRANCH="${REPO_BRANCH:-main}"
STATE_DIR="${STATE_DIR:-/var/lib/hiddify-relay}"
INSTALLED_PKGS_FILE="${INSTALLED_PKGS_FILE:-${STATE_DIR}/installed-packages.txt}"

# When HAProxy (or anything else) already owns 80/443, set these to free ports.
# Nginx will listen on NGINX_HTTP_PORT / NGINX_HTTPS_PORT and HAProxy should
# proxy to them.  Certbot will use ACME_HTTP_PORT for the HTTP-01 challenge.
NGINX_HTTP_PORT="${NGINX_HTTP_PORT:-80}"
NGINX_HTTPS_PORT="${NGINX_HTTPS_PORT:-443}"
ACME_HTTP_PORT="${ACME_HTTP_PORT:-${NGINX_HTTP_PORT}}"

SCRIPT_NAME="$(basename "$0")"
PHP_FPM_UNITS=()
PHP_FPM_SOCK=""
IN_MENU=0

# ── Color codes ────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    COLOR_RESET='\033[0m'
    COLOR_RED='\033[0;31m'
    COLOR_GREEN='\033[0;32m'
    COLOR_YELLOW='\033[0;33m'
    COLOR_BLUE='\033[0;34m'
    COLOR_CYAN='\033[0;36m'
    COLOR_BOLD='\033[1m'
else
    COLOR_RESET='' COLOR_RED='' COLOR_GREEN='' COLOR_YELLOW=''
    COLOR_BLUE='' COLOR_CYAN='' COLOR_BOLD=''
fi

log_info()    { echo -e "${COLOR_CYAN}[INFO]${COLOR_RESET} $*"; }
log_success() { echo -e "${COLOR_GREEN}[OK]${COLOR_RESET} $*"; }
log_error()   { echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} $*" >&2; }
log_warning() { echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} $*"; }
log_header()  { echo -e "\n${COLOR_BOLD}${COLOR_BLUE}=== $* ===${COLOR_RESET}\n"; }

# ── Pipe / TTY guard ───────────────────────────────────────────────────────────
if [[ -p /dev/stdin && "${ALLOW_PIPE_EXECUTION:-0}" != "1" ]]; then
    log_error "Direct pipe execution detected."
    log_error "Use: sudo bash -c 'curl -fsSLo /tmp/relayctl.sh \\"
    log_error "  https://raw.githubusercontent.com/NaxonM/HiRelay/main/tools/relayctl.sh \\"
    log_error "  && chmod +x /tmp/relayctl.sh && /tmp/relayctl.sh menu'"
    log_error "(Set ALLOW_PIPE_EXECUTION=1 to override.)"
    exit 1
fi

if [[ ! -t 0 || ! -t 1 || ! -t 2 ]]; then
    if [[ -r /dev/tty ]]; then
        exec </dev/tty >/dev/tty 2>/dev/tty
    else
        log_error "Interactive TTY not detected. Download the script first, then run: sudo ./relayctl.sh menu"
        exit 1
    fi
fi

# ── Helpers ────────────────────────────────────────────────────────────────────
require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "${SCRIPT_NAME} must be run as root." >&2
        exit 1
    fi
}

press_enter() { read -rp "Press Enter to continue..." _; }
maybe_pause() { [[ ${IN_MENU} -eq 1 ]] && press_enter; }

format_bytes() {
    local bytes="$1"
    if [[ -z "$bytes" || "$bytes" == "0" ]]; then echo "0 B"; return; fi
    if command -v numfmt >/dev/null 2>&1; then
        numfmt --to=iec --format "%.2f" "$bytes"
    else
        echo "${bytes} B"
    fi
}

validate_url() {
    [[ "$1" =~ ^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$ ]]
}

# FIX #14: require at least one dot so single-label hostnames (which can never
# get a Let's Encrypt cert) are rejected at prompt time.
validate_domain() {
    [[ "$1" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$ ]]
}

validate_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 ))
}

# ── Safe .env writer ───────────────────────────────────────────────────────────
# FIX #1: replaced the broken sed escape pipeline with a Python rewriter that
# never treats the value as a regex or sed replacement expression.  Both the
# update and append paths produce identical bytes for any value content.
set_env_value() {
    local key="$1"
    local value="$2"
    if grep -q "^${key}=" "${ENV_PATH}" 2>/dev/null; then
        python3 -c "
import sys, os, tempfile
path, key, value = sys.argv[1], sys.argv[2], sys.argv[3]
new_line = key + '=' + value + '\n'
fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path))
try:
    with os.fdopen(fd, 'w') as fout, open(path) as fin:
        for line in fin:
            fout.write(new_line if line.startswith(key + '=') else line)
    os.replace(tmp, path)
except Exception:
    os.unlink(tmp)
    raise
" "${ENV_PATH}" "${key}" "${value}"
    else
        printf '%s=%s\n' "${key}" "${value}" >> "${ENV_PATH}"
    fi
}

get_env_value() {
    local key="$1"
    [[ -f "${ENV_PATH}" ]] && grep -E "^${key}=" "${ENV_PATH}" 2>/dev/null | head -n 1 | cut -d'=' -f2-
}

# FIX #12: safe line-by-line parser replaces 'source' so the .env file can
# never execute arbitrary code even if somehow maliciously modified.
load_env_settings() {
    [[ -f "${ENV_PATH}" ]] || return 0
    local had_nounset=0
    [[ $- == *u* ]] && { had_nounset=1; set +u; }
    while IFS= read -r line || [[ -n "${line}" ]]; do
        [[ -z "${line}" || "${line}" =~ ^[[:space:]]*# ]] && continue
        if [[ "${line}" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
            local k="${BASH_REMATCH[1]}"
            local v="${BASH_REMATCH[2]}"
            # Strip surrounding single or double quotes
            if [[ "${v}" =~ ^\"(.*)\"$ ]] || [[ "${v}" =~ ^\'(.*)\'$ ]]; then
                v="${BASH_REMATCH[1]}"
            fi
            export "${k}=${v}"
        fi
    done < "${ENV_PATH}"
    [[ ${had_nounset} -eq 1 ]] && set -u
}

has_existing_installation() {
    [[ -d "${APP_DIR}" && -f "${ENV_PATH}" ]]
}

detect_existing_domain() {
    [[ -n "${RELAY_DOMAIN:-}" ]] && { echo "${RELAY_DOMAIN}"; return; }
    [[ -f "${NGINX_SITE}" ]] && \
        awk '/server_name/ { for(i=2;i<=NF;++i){ gsub(";","",$i); if($i!="_") { print $i; exit } } }' \
            "${NGINX_SITE}" 2>/dev/null
}

detect_existing_email() {
    [[ -n "${RELAY_ADMIN_EMAIL:-}" ]] && echo "${RELAY_ADMIN_EMAIL}"
}

# ── PHP-FPM detection ──────────────────────────────────────────────────────────
# FIX #2: systemctl list-unit-files always exits 0 even for non-existent units;
# must grep its stdout to confirm the unit is actually registered.
detect_php_units() {
    local candidates=("php8.4-fpm" "php8.3-fpm" "php8.2-fpm" "php8.1-fpm"
                      "php8.0-fpm" "php7.4-fpm" "php-fpm")
    PHP_FPM_UNITS=()
    PHP_FPM_SOCK=""
    for unit in "${candidates[@]}"; do
        if systemctl list-unit-files "${unit}.service" 2>/dev/null | grep -q "${unit}"; then
            PHP_FPM_UNITS+=("${unit}")
        fi
    done
    # Resolve the best socket: prefer one whose socket file already exists.
    for unit in "${PHP_FPM_UNITS[@]}"; do
        local ver sock=""
        ver=$(echo "${unit}" | grep -oP 'php\K[0-9]+\.[0-9]+' || true)
        [[ -n "${ver}" ]] && sock="/run/php/php${ver}-fpm.sock" || sock="/run/php/php-fpm.sock"
        if [[ -S "${sock}" ]]; then
            PHP_FPM_SOCK="${sock}"; break
        elif systemctl is-active "${unit}" &>/dev/null; then
            [[ -z "${PHP_FPM_SOCK}" ]] && PHP_FPM_SOCK="${sock}"
        fi
    done
    [[ -z "${PHP_FPM_SOCK}" && -S "/run/php/php-fpm.sock" ]] && \
        PHP_FPM_SOCK="/run/php/php-fpm.sock"
}

reload_php_units() {
    detect_php_units
    if [[ ${#PHP_FPM_UNITS[@]} -eq 0 ]]; then
        log_warning "No php-fpm units detected; nothing to reload."
    else
        for unit in "${PHP_FPM_UNITS[@]}"; do
            log_info "Reloading ${unit}..."
            if systemctl reload "${unit}" 2>/dev/null; then
                log_success "${unit} reloaded."
            else
                log_warning "Failed to reload ${unit} (may not be running)."
            fi
        done
    fi
}

# ── Package management ─────────────────────────────────────────────────────────
ensure_packages() {
    if ! command -v apt-get >/dev/null 2>&1; then
        log_error "apt-get not found. This installer supports Debian/Ubuntu only."
        exit 1
    fi

    local packages=(git nginx php-cli php-curl certbot python3-certbot-nginx
                    unzip rsync openssl)

    # FIX #16: check dpkg first (no network needed) before falling back to
    # apt-cache, which requires a fresh cache and internet access.
    local php_fpm_pkg=""
    for ver in 8.4 8.3 8.2 8.1 8.0 7.4; do
        if dpkg -s "php${ver}-fpm" >/dev/null 2>&1; then
            php_fpm_pkg="php${ver}-fpm"; break
        fi
    done
    if [[ -z "${php_fpm_pkg}" ]]; then
        for ver in 8.4 8.3 8.2 8.1 8.0 7.4; do
            if apt-cache show "php${ver}-fpm" &>/dev/null 2>&1; then
                php_fpm_pkg="php${ver}-fpm"; break
            fi
        done
    fi
    [[ -n "${php_fpm_pkg}" ]] && packages+=("${php_fpm_pkg}") || packages+=("php-fpm")

    local missing=()
    for pkg in "${packages[@]}"; do
        dpkg -s "${pkg}" >/dev/null 2>&1 || missing+=("${pkg}")
    done

    # Always record the full managed package set so purge works even when
    # all packages were already present before this script ran.
    mkdir -p "${STATE_DIR}"
    for pkg in "${packages[@]}"; do
        grep -qxF "${pkg}" "${INSTALLED_PKGS_FILE}" 2>/dev/null || \
            echo "${pkg}" >> "${INSTALLED_PKGS_FILE}"
    done

    if [[ ${#missing[@]} -eq 0 ]]; then
        log_success "All required packages already present."
        return
    fi

    log_info "Installing missing packages: ${missing[*]}"
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
}

# ── Repository management ──────────────────────────────────────────────────────
# FIX #8: validate INSTALL_DIR is not a critical system path before rm -rf.
_assert_safe_install_dir() {
    local dir
    dir="$(realpath -m "${INSTALL_DIR}" 2>/dev/null || echo "${INSTALL_DIR}")"
    local unsafe=("/" "/usr" "/usr/local" "/var" "/etc" "/home" "/root"
                  "/bin" "/sbin" "/lib" "/lib64" "/boot" "/proc" "/sys" "/dev" "/run")
    for bad in "${unsafe[@]}"; do
        if [[ "${dir}" == "${bad}" ]]; then
            log_error "INSTALL_DIR='${INSTALL_DIR}' resolves to a critical system path. Aborting."
            exit 1
        fi
    done
    if [[ "${#dir}" -lt 4 ]]; then
        log_error "INSTALL_DIR='${INSTALL_DIR}' is suspiciously short. Aborting."
        exit 1
    fi
}

clone_or_update_repo() {
    _assert_safe_install_dir
    if [[ -d "${INSTALL_DIR}/.git" ]]; then
        log_info "Updating repository in ${INSTALL_DIR}..."
        git -C "${INSTALL_DIR}" fetch --all --prune
        git -C "${INSTALL_DIR}" checkout "${REPO_BRANCH}"
        git -C "${INSTALL_DIR}" reset --hard "origin/${REPO_BRANCH}"
    else
        log_info "Cloning ${REPO_URL} (branch ${REPO_BRANCH}) -> ${INSTALL_DIR}..."
        rm -rf "${INSTALL_DIR}"
        git clone --depth 1 --branch "${REPO_BRANCH}" "${REPO_URL}" "${INSTALL_DIR}"
    fi
}

# ── Permissions ────────────────────────────────────────────────────────────────
# FIX #6: use 770 on storage dirs so www-data can actually write to them.
# FIX #7: handle LOG_FILE that may be outside APP_DIR/storage when overridden.
ensure_storage_permissions() {
    local log_dir
    log_dir="$(dirname "${LOG_FILE}")"

    mkdir -p "${APP_DIR}/storage/cache" \
             "${APP_DIR}/storage/logs" \
             "${APP_DIR}/storage/ratelimit" \
             "${log_dir}"

    [[ -f "${LOG_FILE}" ]] || touch "${LOG_FILE}"

    chown -R www-data:www-data "${APP_DIR}/storage"
    chmod 770 "${APP_DIR}/storage" \
              "${APP_DIR}/storage/cache" \
              "${APP_DIR}/storage/logs" \
              "${APP_DIR}/storage/ratelimit" 2>/dev/null || true

    chown www-data:www-data "${LOG_FILE}" 2>/dev/null || true
    chmod 640 "${LOG_FILE}" 2>/dev/null || true

    # If the log lives outside the storage tree, fix its parent dir too.
    if [[ "${log_dir}" != "${APP_DIR}/storage"* ]]; then
        chown www-data:www-data "${log_dir}" 2>/dev/null || true
        chmod 770 "${log_dir}" 2>/dev/null || true
    fi
}

ensure_env_permissions() {
    [[ -f "${ENV_PATH}" ]] || return 0
    chmod 640 "${ENV_PATH}"
    chown root:www-data "${ENV_PATH}" 2>/dev/null || true
}

ensure_env_defaults() {
    local php_binary=""
    command -v php >/dev/null 2>&1 && php_binary=$(command -v php)

    set_env_value "RELAY_CACHE_DIR"            "${APP_DIR}/storage/cache"
    set_env_value "RELAY_LOG_FILE"             "${APP_DIR}/storage/relay.log"
    set_env_value "RELAY_ACCESS_LOG_FILE"      "${APP_DIR}/storage/access.log"
    set_env_value "RELAY_RATE_LIMIT_DIR"       "${APP_DIR}/storage/ratelimit"
    set_env_value "RELAY_SNAPSHOT_BACKUP_PATH" "${APP_DIR}/storage/cache/backup.json"

    [[ -n "${php_binary}" ]] && set_env_value "RELAY_PHP_BINARY" "${php_binary}"

    local backup_url
    backup_url=$(get_env_value "RELAY_BACKUP_API_URL")
    if [[ -z "${backup_url}" || "${backup_url}" == *"CHANGEME"* ]]; then
        set_env_value "RELAY_CRON_ENABLED" "0"
        log_warning "RELAY_BACKUP_API_URL missing/placeholder — cron refresh disabled."
    fi
}

# ── Configuration prompts ──────────────────────────────────────────────────────
prompt_install_values() {
    log_header "Installation Configuration"

    local default_domain="${DOMAIN:-$(detect_existing_domain)}"
    local default_email="${EMAIL:-$(detect_existing_email)}"
    local default_upstream="${UPSTREAM:-${RELAY_UPSTREAM_BASE_URL:-}}"
    local default_token="${TOKEN:-${RELAY_AUTH_TOKEN:-}}"
    local default_allowed="${ALLOWED:-${RELAY_ALLOWED_CLIENTS:-}}"
    local default_cache_ttl="${CACHE_TTL:-${RELAY_CACHE_TTL:-300}}"
    local default_http_port="${NGINX_HTTP_PORT}"
    local default_https_port="${NGINX_HTTPS_PORT}"

    # ── Ports ──────────────────────────────────────────────────────────────────
    echo -e "${COLOR_CYAN}HAProxy / port conflict mode${COLOR_RESET}"
    echo -e "  If HAProxy (or anything else) owns ports 80/443, set custom listen ports."
    echo -e "  Leave blank to keep current values."

    local input_http_port input_https_port
    while true; do
        read -rp "  Nginx HTTP port  [${default_http_port}]: " input_http_port
        [[ -z "${input_http_port}" ]] && input_http_port="${default_http_port}"
        validate_port "${input_http_port}" && break
        log_error "Invalid port number."
    done

    while true; do
        read -rp "  Nginx HTTPS port [${default_https_port}]: " input_https_port
        [[ -z "${input_https_port}" ]] && input_https_port="${default_https_port}"
        validate_port "${input_https_port}" && break
        log_error "Invalid port number."
    done

    NGINX_HTTP_PORT="${input_http_port}"
    NGINX_HTTPS_PORT="${input_https_port}"

    if [[ "${NGINX_HTTP_PORT}" != "80" || "${NGINX_HTTPS_PORT}" != "443" ]]; then
        log_warning "Non-standard ports selected. Configure your HAProxy frontend to"
        log_warning "proxy to 127.0.0.1:${NGINX_HTTP_PORT} (HTTP) and 127.0.0.1:${NGINX_HTTPS_PORT} (HTTPS)."
        local default_acme="${ACME_HTTP_PORT}"
        [[ "${default_acme}" == "${NGINX_HTTP_PORT}" && "${NGINX_HTTP_PORT}" != "80" ]] && \
            default_acme="80"
        local input_acme
        while true; do
            read -rp "  ACME challenge port (must be reachable as :80 from internet) [${default_acme}]: " input_acme
            [[ -z "${input_acme}" ]] && input_acme="${default_acme}"
            validate_port "${input_acme}" && break
            log_error "Invalid port number."
        done
        ACME_HTTP_PORT="${input_acme}"
    fi

    # ── Domain ─────────────────────────────────────────────────────────────────
    while [[ -z "${default_domain}" ]]; do
        echo -e "${COLOR_CYAN}Relay domain${COLOR_RESET} (e.g. ${COLOR_YELLOW}relay.example.com${COLOR_RESET})"
        read -rp "> " default_domain
        validate_domain "${default_domain}" || \
            { log_error "Invalid domain (must contain at least one dot, no IP addresses)."; default_domain=""; }
    done

    # ── Email ──────────────────────────────────────────────────────────────────
    while [[ -z "${default_email}" ]]; do
        echo -e "${COLOR_CYAN}Admin email for Let's Encrypt${COLOR_RESET} (e.g. ${COLOR_YELLOW}admin@example.com${COLOR_RESET})"
        read -rp "> " default_email
        [[ "${default_email}" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] || \
            { log_error "Invalid email."; default_email=""; }
    done

    # ── Upstream URL ───────────────────────────────────────────────────────────
    local input_upstream
    while true; do
        echo -e "${COLOR_CYAN}Upstream base URL${COLOR_RESET} (e.g. ${COLOR_YELLOW}https://sub.example.com${COLOR_RESET})"
        if [[ -n "${default_upstream}" ]]; then
            read -rp "> [${default_upstream}]: " input_upstream
            [[ -z "${input_upstream}" ]] && input_upstream="${default_upstream}"
        else
            read -rp "> " input_upstream
        fi
        if validate_url "${input_upstream}"; then
            default_upstream="${input_upstream}"; break
        else
            log_error "Invalid URL. Use a full URL (e.g. https://example.com)"
        fi
    done

    # ── Optional fields ────────────────────────────────────────────────────────
    echo -e "${COLOR_CYAN}Shared secret token${COLOR_RESET} (optional, press Enter to leave empty)"
    local input_token
    read -rp "> " input_token || true
    [[ -n "${input_token:-}" ]] && default_token="${input_token}"

    echo -e "${COLOR_CYAN}Allowed client IPs${COLOR_RESET} (comma-separated, blank = all)"
    echo -e "  Example: ${COLOR_YELLOW}1.2.3.4,5.6.7.8${COLOR_RESET}"
    local input_allowed
    read -rp "> " input_allowed || true
    [[ -n "${input_allowed:-}" ]] && default_allowed="${input_allowed}"

    echo -e "${COLOR_CYAN}Cache TTL seconds${COLOR_RESET} [${COLOR_YELLOW}${default_cache_ttl}${COLOR_RESET}]"
    local input_ttl
    read -rp "> " input_ttl || true
    [[ -n "${input_ttl:-}" ]] && default_cache_ttl="${input_ttl}"

    INSTALL_DOMAIN="${default_domain}"
    INSTALL_EMAIL="${default_email}"
    INSTALL_UPSTREAM="${default_upstream}"
    INSTALL_TOKEN="${default_token}"
    INSTALL_ALLOWED="${default_allowed}"
    INSTALL_CACHE_TTL="${default_cache_ttl}"

    log_info "Configuration summary:"
    echo -e "  Domain:      ${COLOR_GREEN}${INSTALL_DOMAIN}${COLOR_RESET}"
    echo -e "  Email:       ${COLOR_GREEN}${INSTALL_EMAIL}${COLOR_RESET}"
    echo -e "  Upstream:    ${COLOR_GREEN}${INSTALL_UPSTREAM}${COLOR_RESET}"
    echo -e "  HTTP port:   ${COLOR_GREEN}${NGINX_HTTP_PORT}${COLOR_RESET}"
    echo -e "  HTTPS port:  ${COLOR_GREEN}${NGINX_HTTPS_PORT}${COLOR_RESET}"
    echo -e "  Token:       ${COLOR_GREEN}${INSTALL_TOKEN:-<not set>}${COLOR_RESET}"
    echo -e "  Allowed IPs: ${COLOR_GREEN}${INSTALL_ALLOWED:-<all>}${COLOR_RESET}"
    echo -e "  Cache TTL:   ${COLOR_GREEN}${INSTALL_CACHE_TTL}s${COLOR_RESET}"
    echo
}

# ── .env writer ────────────────────────────────────────────────────────────────
# FIX #15: back up existing .env before overwriting so a crash mid-write does
# not leave a corrupt file.
write_env_file() {
    local timezone=""
    command -v timedatectl >/dev/null 2>&1 && \
        timezone=$(timedatectl show -p Timezone --value 2>/dev/null || true)
    [[ -z "${timezone}" && -f /etc/timezone ]] && \
        timezone=$(cat /etc/timezone 2>/dev/null || true)

    local php_binary=""
    command -v php >/dev/null 2>&1 && php_binary=$(command -v php)

    mkdir -p "${ENV_DIR}"

    if [[ -f "${ENV_PATH}" ]]; then
        cp "${ENV_PATH}" "${ENV_PATH}.bak"
        log_info "Existing .env backed up to ${ENV_PATH}.bak"
    fi

    if [[ -f "${APP_DIR}/.env.example" ]]; then
        cp "${APP_DIR}/.env.example" "${ENV_PATH}"
    else
        : > "${ENV_PATH}"
    fi

    set_env_value "RELAY_UPSTREAM_BASE_URL"    "${INSTALL_UPSTREAM}"
    set_env_value "CACHE_SOURCE_BASE_URL"      "${INSTALL_UPSTREAM}"
    set_env_value "RELAY_AUTH_TOKEN"           "${INSTALL_TOKEN}"
    set_env_value "RELAY_ALLOWED_CLIENTS"      "${INSTALL_ALLOWED}"
    set_env_value "RELAY_CACHE_TTL"            "${INSTALL_CACHE_TTL}"
    set_env_value "RELAY_CONNECT_TIMEOUT"      "10"
    set_env_value "RELAY_TRANSFER_TIMEOUT"     "60"
    set_env_value "RELAY_DOMAIN"               "${INSTALL_DOMAIN}"
    set_env_value "RELAY_ADMIN_EMAIL"          "${INSTALL_EMAIL}"
    set_env_value "RELAY_NGINX_HTTP_PORT"      "${NGINX_HTTP_PORT}"
    set_env_value "RELAY_NGINX_HTTPS_PORT"     "${NGINX_HTTPS_PORT}"
    [[ -n "${timezone}"   ]] && set_env_value "RELAY_TIMEZONE"   "${timezone}"
    [[ -n "${php_binary}" ]] && set_env_value "RELAY_PHP_BINARY" "${php_binary}"

    ensure_env_defaults
    ensure_env_permissions
}

# ── Nginx config writers ───────────────────────────────────────────────────────
_nginx_fpm_sock() {
    detect_php_units
    if [[ -n "${PHP_FPM_SOCK}" ]]; then
        echo "${PHP_FPM_SOCK}"
    else
        echo "/run/php/php-fpm.sock"
        log_warning "Could not resolve php-fpm socket path; defaulting to /run/php/php-fpm.sock."
        log_warning "Edit ${NGINX_SITE} if nginx fails to connect to PHP."
    fi
}

write_nginx_config() {
    local sock; sock="$(_nginx_fpm_sock)"
    mkdir -p "$(dirname "${NGINX_SITE}")" "$(dirname "${NGINX_LINK}")"
    cat > "${NGINX_SITE}" <<EOF
# Hiddify Relay - HTTP only (SSL handled externally or by certbot upgrade)
server {
    listen ${NGINX_HTTP_PORT};
    server_name ${INSTALL_DOMAIN};

    root ${APP_DIR}/public;
    index index.php;

    location ~ /\\.  { deny all; }

    location / {
        try_files \$uri /index.php?\$args;
    }

    location ~ \\.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:${sock};
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
}
EOF
    ln -sf "${NGINX_SITE}" "${NGINX_LINK}"
}

write_nginx_ssl_config() {
    local cert_path="$1"
    local key_path="$2"
    local sock; sock="$(_nginx_fpm_sock)"
    mkdir -p "$(dirname "${NGINX_SITE}")" "$(dirname "${NGINX_LINK}")"
    cat > "${NGINX_SITE}" <<EOF
# Hiddify Relay - HTTPS with redirect
server {
    listen ${NGINX_HTTP_PORT};
    server_name ${INSTALL_DOMAIN};
    return 301 https://\$host\$request_uri;
}

server {
    listen ${NGINX_HTTPS_PORT} ssl http2;
    server_name ${INSTALL_DOMAIN};

    ssl_certificate     ${cert_path};
    ssl_certificate_key ${key_path};
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    root ${APP_DIR}/public;
    index index.php;

    location ~ /\\.  { deny all; }

    location / {
        try_files \$uri /index.php?\$args;
    }

    location ~ \\.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:${sock};
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
}
EOF
    ln -sf "${NGINX_SITE}" "${NGINX_LINK}"
}

# ── Certbot - HAProxy-aware ────────────────────────────────────────────────────
# FIX #3: use awk with an anchored port match instead of fragile grep patterns.
# FIX #4: non-nginx process on port 80 goes straight to the failure handler
#         instead of printing a warning and then calling it anyway.
# FIX #5: removed spurious 2>&1 on certbot calls (output already on tty).
_port_owner() {
    local port="$1"
    local listeners
    listeners=$(ss -tlnp 2>/dev/null | awk -v p=":${port}" '$4 ~ p"$"')
    if [[ -z "${listeners}" ]]; then
        echo "free"
    elif echo "${listeners}" | grep -q 'nginx'; then
        echo "nginx"
    else
        echo "other"
    fi
}

run_certbot() {
    [[ "${SKIP_CERTBOT:-0}" == "1" ]] && { log_info "SKIP_CERTBOT=1 - skipping."; return; }
    [[ -z "${INSTALL_DOMAIN:-}" || -z "${INSTALL_EMAIL:-}" ]] && {
        log_warning "Domain or email missing - skipping certbot."; return; }

    local owner; owner="$(_port_owner 80)"
    local cert_issued=0

    if [[ "${owner}" == "nginx" ]]; then
        log_info "Nginx owns port 80 - using certbot --nginx plugin."
        if certbot --nginx \
                -d "${INSTALL_DOMAIN}" \
                -m "${INSTALL_EMAIL}" \
                --agree-tos --non-interactive --redirect; then
            log_success "Certificate issued via --nginx plugin."
            cert_issued=1
        fi
    elif [[ "${owner}" == "free" ]]; then
        log_info "Port 80 is free - using certbot standalone on port ${ACME_HTTP_PORT}."
        systemctl stop nginx 2>/dev/null || true
        if certbot certonly --standalone \
                --http-01-port "${ACME_HTTP_PORT}" \
                -d "${INSTALL_DOMAIN}" \
                -m "${INSTALL_EMAIL}" \
                --agree-tos --non-interactive; then
            log_success "Certificate issued via standalone."
            cert_issued=1
            local live_dir="/etc/letsencrypt/live/${INSTALL_DOMAIN}"
            write_nginx_ssl_config "${live_dir}/fullchain.pem" "${live_dir}/privkey.pem"
        fi
        systemctl start nginx 2>/dev/null || true
    else
        # Port 80 is owned by something other than nginx (e.g. HAProxy).
        # Skip straight to the interactive failure/fallback handler.
        log_warning "Port 80 is occupied by a non-nginx process."
    fi

    if [[ ${cert_issued} -eq 0 ]]; then
        _handle_certbot_failure
    fi
}

_handle_certbot_failure() {
    log_warning "Automatic certificate issuance failed. Options:"
    while true; do
        echo -e "  ${COLOR_CYAN}[S]${COLOR_RESET} Skip SSL for now (HTTP only)"
        echo -e "  ${COLOR_CYAN}[P]${COLOR_RESET} Provide existing certificate paths"
        echo -e "  ${COLOR_CYAN}[D]${COLOR_RESET} Show DNS-01 challenge instructions"
        echo -e "  ${COLOR_CYAN}[R]${COLOR_RESET} Retry certbot (standalone)"
        read -rp "> " cert_choice
        case "${cert_choice^^}" in
            S)
                log_warning "Skipping SSL. The relay will serve over HTTP only."
                return
                ;;
            P)
                local cert_path key_path
                read -rp "Fullchain certificate path: " cert_path
                read -rp "Private key path: " key_path
                [[ -z "${cert_path}" || -z "${key_path}" ]] && \
                    { log_error "Both paths required."; continue; }
                # FIX #13: trim leading/trailing whitespace only, not internal spaces.
                cert_path="$(echo "${cert_path}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
                key_path="$(echo "${key_path}"   | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
                if [[ ! -r "${cert_path}" || ! -r "${key_path}" ]]; then
                    log_error "Cannot read certificate or key. Check paths and permissions."
                    continue
                fi
                write_nginx_ssl_config "${cert_path}" "${key_path}"
                if nginx -t; then
                    systemctl reload nginx
                    log_success "Nginx updated with provided certificate."
                    return
                fi
                log_error "Nginx config test failed. Check the certificate paths."
                ;;
            D)
                echo
                echo -e "${COLOR_BOLD}DNS-01 Challenge Instructions:${COLOR_RESET}"
                echo "  1. Install a DNS plugin:"
                echo "       apt-get install -y certbot python3-certbot-dns-cloudflare"
                echo "     (or whichever matches your DNS provider)"
                echo "  2. Configure credentials per your provider's docs."
                echo "  3. Run:"
                echo "       certbot certonly --dns-cloudflare \\"
                echo "         --dns-cloudflare-credentials /etc/cloudflare.ini \\"
                echo "         -d ${INSTALL_DOMAIN:-your.domain} \\"
                echo "         -m ${INSTALL_EMAIL:-admin@example.com} --agree-tos"
                echo "  4. Then re-run:  sudo ${SCRIPT_NAME} install"
                echo "     and choose [P] to supply the resulting cert paths."
                echo
                ;;
            R)
                systemctl stop nginx 2>/dev/null || true
                if certbot certonly --standalone \
                        --http-01-port "${ACME_HTTP_PORT:-80}" \
                        -d "${INSTALL_DOMAIN}" \
                        -m "${INSTALL_EMAIL}" \
                        --agree-tos --non-interactive; then
                    log_success "Certificate issued."
                    local live_dir="/etc/letsencrypt/live/${INSTALL_DOMAIN}"
                    write_nginx_ssl_config "${live_dir}/fullchain.pem" "${live_dir}/privkey.pem"
                    systemctl start nginx 2>/dev/null || true
                    nginx -t && systemctl reload nginx
                    return
                fi
                systemctl start nginx 2>/dev/null || true
                log_warning "Certbot failed again."
                ;;
            *)
                log_error "Invalid choice."
                ;;
        esac
    done
}

# ── install / update ───────────────────────────────────────────────────────────
# FIX #10: use 'return 1' instead of 'exit 1' for validation errors so the
# interactive menu is not killed when install fails inside main_menu.
install_relay() {
    local reuse_config=0

    if has_existing_installation; then
        load_env_settings
        log_header "Existing Installation Detected"
        echo -e "Found prior config at ${COLOR_CYAN}${ENV_PATH}${COLOR_RESET} and code under ${COLOR_CYAN}${APP_DIR}${COLOR_RESET}."
        read -rp "Reuse existing configuration and certificates? [Y/n]: " reuse_answer
        [[ -z "${reuse_answer}" || "${reuse_answer}" =~ ^[Yy]$ ]] && reuse_config=1
    fi

    if [[ ${reuse_config} -eq 1 ]]; then
        ensure_packages
        clone_or_update_repo
        ensure_storage_permissions
        ensure_env_defaults
        ensure_env_permissions
        if ! nginx -t; then
            log_error "Nginx config test failed. Check ${NGINX_SITE} (php-fpm socket?)."
            log_error "Run: sudo ${SCRIPT_NAME} config  then: sudo ${SCRIPT_NAME} reload"
            maybe_pause; return 1
        fi
        systemctl reload nginx
        reload_php_units

        log_success "Code updated and services reloaded (existing config preserved)."
        echo -e "  Domain:   ${COLOR_GREEN}${RELAY_DOMAIN:-<unknown>}${COLOR_RESET}"
        echo -e "  Upstream: ${COLOR_GREEN}${RELAY_UPSTREAM_BASE_URL:-<not set>}${COLOR_RESET}"
        echo -e "  Token:    ${COLOR_GREEN}${RELAY_AUTH_TOKEN:-<not set>}${COLOR_RESET}"
        echo -e "  SSL:      ${COLOR_GREEN}(untouched)${COLOR_RESET}"
        return 0
    fi

    prompt_install_values

    if [[ -z "${INSTALL_DOMAIN:-}" ]]; then
        log_error "Domain is required."; maybe_pause; return 1
    fi
    if [[ -z "${INSTALL_UPSTREAM:-}" ]]; then
        log_error "Upstream URL is required."; maybe_pause; return 1
    fi
    if [[ -z "${INSTALL_EMAIL:-}" && "${SKIP_CERTBOT:-0}" != "1" ]]; then
        log_error "Email required for Let's Encrypt. Set SKIP_CERTBOT=1 to skip."
        maybe_pause; return 1
    fi

    ensure_packages
    clone_or_update_repo
    ensure_storage_permissions
    write_env_file
    write_nginx_config

    if ! nginx -t; then
        log_error "Nginx config test failed. Aborting to prevent breaking the web server."
        maybe_pause; return 1
    fi
    systemctl reload nginx
    log_success "Nginx reloaded with HTTP config."
    run_certbot
    if nginx -t; then
        systemctl reload nginx
        log_success "Nginx reloaded after SSL setup."
    else
        log_warning "Nginx config test failed after certbot. Check ${NGINX_SITE}."
    fi
    reload_php_units

    log_success "Installation complete."
    echo -e "  Domain:       ${COLOR_GREEN}${INSTALL_DOMAIN}${COLOR_RESET}"
    echo -e "  Shared token: ${COLOR_GREEN}${INSTALL_TOKEN:-<not set>}${COLOR_RESET}"
    echo -e "  Environment:  ${COLOR_GREEN}${ENV_PATH}${COLOR_RESET}"
    echo -e "  Install dir:  ${COLOR_GREEN}${INSTALL_DIR}${COLOR_RESET}"
    echo -e "  App dir:      ${COLOR_GREEN}${APP_DIR}${COLOR_RESET}"
    [[ "${NGINX_HTTP_PORT}" != "80" ]] && \
        log_warning "Remember to configure HAProxy to forward to port ${NGINX_HTTP_PORT}/${NGINX_HTTPS_PORT}."
}

# ── Status ─────────────────────────────────────────────────────────────────────
show_status() {
    local json_mode="${1:-}"
    [[ "${json_mode}" == "--json" ]] && { show_status_json; return; }

    log_header "Hiddify Relay Status"

    echo -e "${COLOR_BOLD}Installation:${COLOR_RESET}"
    if [[ -d "${APP_DIR}" ]]; then
        log_success "Present at ${COLOR_CYAN}${APP_DIR}${COLOR_RESET}"
    else
        log_error "NOT FOUND"
    fi

    echo -e "\n${COLOR_BOLD}Configuration:${COLOR_RESET}"
    if [[ -f "${ENV_PATH}" ]]; then
        log_success "${COLOR_CYAN}${ENV_PATH}${COLOR_RESET}"
        local upstream
        upstream=$(grep '^RELAY_UPSTREAM_BASE_URL=' "${ENV_PATH}" 2>/dev/null | cut -d'=' -f2 || true)
        if [[ -n "${upstream}" ]]; then
            echo -e "  Upstream: ${COLOR_GREEN}${upstream}${COLOR_RESET}"
        else
            log_warning "  Upstream not configured"
        fi
    else
        log_error "Missing (${ENV_PATH})"
    fi

    echo -e "\n${COLOR_BOLD}Web Server:${COLOR_RESET}"
    if [[ -L "${NGINX_LINK}" ]]; then
        log_success "Site enabled"
    else
        log_warning "Site disabled"
    fi
    systemctl is-active nginx >/dev/null 2>&1 && \
        log_success "nginx: ${COLOR_GREEN}active${COLOR_RESET}" || log_error "nginx: inactive"

    echo -e "\n${COLOR_BOLD}PHP-FPM:${COLOR_RESET}"
    detect_php_units
    if [[ ${#PHP_FPM_UNITS[@]} -gt 0 ]]; then
        for unit in "${PHP_FPM_UNITS[@]}"; do
            if systemctl is-active "${unit}" >/dev/null 2>&1; then
                log_success "${unit}: ${COLOR_GREEN}active${COLOR_RESET}"
            else
                log_warning "${unit}: inactive"
            fi
        done
        echo -e "  Socket: ${COLOR_CYAN}${PHP_FPM_SOCK:-<not detected>}${COLOR_RESET}"
    else
        log_warning "php-fpm: no service unit detected"
    fi

    echo -e "\n${COLOR_BOLD}Cache:${COLOR_RESET}"
    if [[ -d "${CACHE_DIR}" ]]; then
        local cache_size cache_entries
        cache_entries=$(find "${CACHE_DIR}" -type f 2>/dev/null | wc -l)
        cache_size=$(du -sh "${CACHE_DIR}" 2>/dev/null | awk '{print $1}')
        echo -e "  Files: ${COLOR_CYAN}${cache_entries}${COLOR_RESET}"
        echo -e "  Size:  ${COLOR_CYAN}${cache_size}${COLOR_RESET}"
    else
        log_warning "Directory not found (${CACHE_DIR})"
    fi

    echo -e "\n${COLOR_BOLD}Logs:${COLOR_RESET}"
    if [[ -f "${LOG_FILE}" ]]; then
        local total_lines error_lines
        total_lines=$(wc -l < "${LOG_FILE}" 2>/dev/null || echo 0)
        error_lines=$(grep -ci "error" "${LOG_FILE}" 2>/dev/null | tr -d '[:space:]' || echo 0)
        echo -e "  Location:    ${COLOR_CYAN}${LOG_FILE}${COLOR_RESET}"
        echo -e "  Total lines: ${COLOR_CYAN}${total_lines}${COLOR_RESET}"
        if [[ "${error_lines}" -gt 0 ]]; then
            echo -e "  Errors: ${COLOR_RED}${error_lines}${COLOR_RESET}"
        else
            echo -e "  Errors: ${COLOR_GREEN}0${COLOR_RESET}"
        fi
        echo -e "\n${COLOR_BOLD}Recent log entries:${COLOR_RESET}"
        tail -n 10 "${LOG_FILE}" 2>/dev/null | sed 's/^/  /' || true
    else
        log_warning "File not found (${LOG_FILE})"
    fi

    maybe_pause
}

# FIX #11: JSON-escape string values before embedding them in the JSON output.
_json_escape() {
    printf '%s' "$1" | python3 -c "
import sys, json
sys.stdout.write(json.dumps(sys.stdin.read())[1:-1])
"
}

show_status_json() {
    local installation_present="false" config_present="false"
    local nginx_enabled="false" nginx_active="false"
    local upstream="" cache_entries=0 cache_size=0
    local log_lines=0 log_errors=0

    [[ -d "${INSTALL_DIR}" ]]  && installation_present="true"
    [[ -f "${ENV_PATH}" ]]     && config_present="true"
    [[ -L "${NGINX_LINK}" ]]   && nginx_enabled="true"
    systemctl is-active nginx >/dev/null 2>&1 && nginx_active="true"

    [[ -r "${ENV_PATH}" ]] && \
        upstream=$(grep '^RELAY_UPSTREAM_BASE_URL=' "${ENV_PATH}" 2>/dev/null | \
                   cut -d'=' -f2 | tr -d '"' || true)

    if [[ -d "${CACHE_DIR}" ]]; then
        cache_entries=$(find "${CACHE_DIR}" -type f 2>/dev/null | wc -l)
        cache_size=$(du -sb "${CACHE_DIR}" 2>/dev/null | awk '{print $1}')
        [[ -z "${cache_size}" ]] && cache_size=0
    fi

    if [[ -f "${LOG_FILE}" ]]; then
        log_lines=$(wc -l < "${LOG_FILE}" 2>/dev/null || echo 0)
        log_errors=$(grep -ci "error" "${LOG_FILE}" 2>/dev/null || echo 0)
    fi

    detect_php_units
    local php_status="inactive"
    [[ ${#PHP_FPM_UNITS[@]} -gt 0 ]] && \
        systemctl is-active "${PHP_FPM_UNITS[0]}" >/dev/null 2>&1 && php_status="active"

    local j_upstream j_log_path j_install_path j_env_path j_sock
    j_upstream="$(_json_escape "${upstream}")"
    j_log_path="$(_json_escape "${LOG_FILE}")"
    j_install_path="$(_json_escape "${INSTALL_DIR}")"
    j_env_path="$(_json_escape "${ENV_PATH}")"
    j_sock="$(_json_escape "${PHP_FPM_SOCK:-}")"

    cat <<EOF
{
  "installation": { "present": ${installation_present}, "path": "${j_install_path}" },
  "configuration": { "present": ${config_present}, "path": "${j_env_path}", "upstream": "${j_upstream}" },
  "services": {
    "nginx": { "enabled": ${nginx_enabled}, "active": ${nginx_active} },
    "php_fpm": { "active": "${php_status}", "socket": "${j_sock}" }
  },
  "cache": { "entries": ${cache_entries}, "size_bytes": ${cache_size} },
  "logs": { "lines": ${log_lines}, "errors": ${log_errors}, "path": "${j_log_path}" }
}
EOF
}

# ── Monitoring dashboard ───────────────────────────────────────────────────────
monitoring_dashboard() {
    log_header "Monitoring Dashboard"

    if [[ ! -d "${APP_DIR}" ]]; then
        log_error "App directory not found at ${APP_DIR}. Run install first."
        maybe_pause; return
    fi

    load_env_settings
    local upstream="${RELAY_UPSTREAM_BASE_URL:-}"
    local cache_dir="${RELAY_CACHE_DIR:-${APP_DIR}/storage/cache}"
    local log_file="${RELAY_LOG_FILE:-${APP_DIR}/storage/relay.log}"

    local cache_entries=0 cache_size_bytes=0
    if [[ -d "${cache_dir}" ]]; then
        cache_entries=$(find "${cache_dir}" -type f 2>/dev/null | wc -l | tr -d ' ')
        cache_size_bytes=$(du -sb "${cache_dir}" 2>/dev/null | awk '{print $1}')
        [[ -z "${cache_size_bytes}" ]] && cache_size_bytes=0
    fi

    local log_lines=0 log_errors=0 recent_errors=""
    if [[ -f "${log_file}" ]]; then
        log_lines=$(wc -l < "${log_file}" 2>/dev/null || echo 0)
        log_errors=$(grep -c "[Ee]rror" "${log_file}" 2>/dev/null || echo 0)
        recent_errors=$(grep -i "error" "${log_file}" 2>/dev/null | tail -n 5)
    fi

    local upstream_status="not configured" upstream_http="-" upstream_time="-"
    if [[ -n "${upstream}" ]]; then
        local curl_output
        curl_output=$(curl -s -o /dev/null -w "%{http_code} %{time_total}" \
            --connect-timeout 3 --max-time 5 -I "${upstream}" 2>/dev/null || true)
        if [[ -n "${curl_output}" && "${curl_output}" != " " ]]; then
            upstream_http="${curl_output%% *}"
            upstream_time="${curl_output##* }"
            if [[ "${upstream_http}" =~ ^[0-9]+$ ]]; then
                if (( upstream_http >= 200 && upstream_http < 500 )); then
                    upstream_status="reachable"
                else
                    upstream_status="unreachable (HTTP ${upstream_http})"
                fi
            else
                upstream_status="unreachable (no response)"
                upstream_http="-"
            fi
        else
            upstream_status="unreachable (connection failed)"
        fi
    fi

    echo -e "${COLOR_BOLD}Upstream:${COLOR_RESET}"
    if [[ -n "${upstream}" ]]; then
        echo -e "  URL: ${COLOR_CYAN}${upstream}${COLOR_RESET}"
        local status_color="${COLOR_YELLOW}"
        [[ "${upstream_status}" == "reachable" ]]  && status_color="${COLOR_GREEN}"
        [[ "${upstream_status}" == unreachable* ]] && status_color="${COLOR_RED}"
        echo -e "  Status:        ${status_color}${upstream_status^^}${COLOR_RESET}"
        echo -e "  HTTP code:     ${COLOR_CYAN}${upstream_http}${COLOR_RESET}"
        echo -e "  Response time: ${COLOR_CYAN}${upstream_time}s${COLOR_RESET}"
    else
        log_warning "  Upstream not configured"
    fi

    echo -e "\n${COLOR_BOLD}Cache:${COLOR_RESET}"
    if [[ -d "${cache_dir}" ]]; then
        echo -e "  Directory: ${COLOR_CYAN}${cache_dir}${COLOR_RESET}"
        echo -e "  Entries:   ${COLOR_CYAN}${cache_entries}${COLOR_RESET}"
        echo -e "  Size:      ${COLOR_CYAN}$(format_bytes "${cache_size_bytes}")${COLOR_RESET}"
    else
        log_warning "  Cache directory missing (${cache_dir})"
    fi

    echo -e "\n${COLOR_BOLD}Logs:${COLOR_RESET}"
    if [[ -f "${log_file}" ]]; then
        echo -e "  File:   ${COLOR_CYAN}${log_file}${COLOR_RESET}"
        echo -e "  Lines:  ${COLOR_CYAN}${log_lines}${COLOR_RESET}"
        if [[ "${log_errors}" -gt 0 ]]; then
            echo -e "  Errors: ${COLOR_RED}${log_errors}${COLOR_RESET}"
            if [[ -n "${recent_errors}" ]]; then
                echo -e "\n  ${COLOR_BOLD}Recent errors:${COLOR_RESET}"
                while IFS= read -r line; do echo "    ${line}"; done <<< "${recent_errors}"
            fi
        else
            echo -e "  Errors: ${COLOR_GREEN}0${COLOR_RESET}"
        fi
    else
        log_warning "  Log file missing (${log_file})"
    fi

    echo -e "\n${COLOR_BOLD}System:${COLOR_RESET}"
    if command -v df >/dev/null 2>&1; then
        local disk_line
        disk_line=$(df -h "${APP_DIR}" 2>/dev/null | awk 'NR==2 {print $2" total, "$3" used ("$5")"}')
        [[ -n "${disk_line}" ]] && echo -e "  Disk (install path): ${COLOR_CYAN}${disk_line}${COLOR_RESET}"
    fi
    echo -e "  PHP version:  ${COLOR_CYAN}$(php -r 'echo PHP_VERSION;' 2>/dev/null || echo 'unknown')${COLOR_RESET}"
    detect_php_units
    echo -e "  PHP-FPM sock: ${COLOR_CYAN}${PHP_FPM_SOCK:-<not detected>}${COLOR_RESET}"

    maybe_pause
}

# ── Utility actions ────────────────────────────────────────────────────────────
ensure_paths() {
    if [[ ! -d "${INSTALL_DIR}" ]]; then
        log_error "Install directory ${INSTALL_DIR} not found."
        return 1
    fi
    mkdir -p "${APP_DIR}/storage" "${CACHE_DIR}"
}

edit_configuration() {
    ensure_paths || { maybe_pause; return; }
    if [[ ! -f "${ENV_PATH}" ]]; then
        log_info "Creating ${ENV_PATH} from template."
        mkdir -p "${ENV_DIR}"
        if [[ -f "${APP_DIR}/.env.example" ]]; then
            cp "${APP_DIR}/.env.example" "${ENV_PATH}"
        else
            touch "${ENV_PATH}"
        fi
        ensure_env_permissions
    fi
    local editor="${EDITOR:-nano}"
    "${editor}" "${ENV_PATH}"
    ensure_env_permissions
    ensure_env_defaults
    maybe_pause
}

# FIX #9: removed maybe_pause from reload_services so that update_from_git
# (which calls reload_services then its own maybe_pause) doesn't pause twice.
reload_services() {
    if nginx -t; then
        systemctl reload nginx
        log_success "nginx reloaded."
    else
        log_error "nginx config test failed - not reloading. Fix errors above first."
    fi
    reload_php_units
}

enable_nginx_site() {
    if [[ ! -f "${NGINX_SITE}" ]]; then
        log_error "Site configuration ${NGINX_SITE} is missing."
        maybe_pause; return
    fi
    ln -sf "${NGINX_SITE}" "${NGINX_LINK}"
    if nginx -t; then
        systemctl reload nginx
        log_success "Relay site enabled."
    else
        log_error "Nginx config test failed. Site symlink created but nginx not reloaded."
    fi
    maybe_pause
}

disable_nginx_site() {
    if [[ -L "${NGINX_LINK}" ]]; then
        rm -f "${NGINX_LINK}"
        if nginx -t; then
            systemctl reload nginx
            log_success "Relay site disabled."
        else
            log_warning "nginx config test failed after disabling site."
        fi
    else
        log_info "Relay site link not present; nothing to disable."
    fi
    maybe_pause
}

update_from_git() {
    ensure_paths || { maybe_pause; return; }
    if [[ ! -d "${INSTALL_DIR}/.git" ]]; then
        log_error "Git metadata not found in ${INSTALL_DIR}. Cannot auto-update."
        maybe_pause; return
    fi
    git -C "${INSTALL_DIR}" fetch --all --prune
    git -C "${INSTALL_DIR}" checkout "${REPO_BRANCH}"
    git -C "${INSTALL_DIR}" reset --hard "origin/${REPO_BRANCH}"
    log_success "Update complete. Reloading services..."
    ensure_storage_permissions
    ensure_env_defaults
    reload_services
    maybe_pause
}

clear_cache() {
    if [[ -d "${CACHE_DIR}" ]]; then
        find "${CACHE_DIR}" -type f -delete 2>/dev/null || true
        log_success "Cache cleared."
    else
        log_warning "Cache directory not found (${CACHE_DIR})."
    fi
    maybe_pause
}

tail_logs() {
    if [[ ! -f "${LOG_FILE}" ]]; then
        log_error "Log file not found: ${LOG_FILE}"
        maybe_pause; return
    fi
    log_header "Relay Logs (Ctrl+C to exit)"
    echo -e "${COLOR_CYAN}Following: ${LOG_FILE}${COLOR_RESET}\n"
    tail -f "${LOG_FILE}" || { log_error "Failed to tail log file"; maybe_pause; }
}

# ── Removal ────────────────────────────────────────────────────────────────────
_remove_common() {
    _assert_safe_install_dir
    [[ -L "${NGINX_LINK}" ]] && rm -f "${NGINX_LINK}"
    [[ -f "${NGINX_SITE}" ]] && rm -f "${NGINX_SITE}"
    [[ -d "${INSTALL_DIR}" ]] && rm -rf "${INSTALL_DIR}"
    [[ -d "${ENV_DIR}" ]]     && rm -rf "${ENV_DIR}"
    # NOTE: STATE_DIR intentionally not removed here — purge_installation reads
    # INSTALLED_PKGS_FILE from it after calling this function.
    if systemctl is-active nginx >/dev/null 2>&1; then
        nginx -t 2>/dev/null && systemctl reload nginx || true
    fi
}

remove_installation() {
    read -rp "Remove the relay installation? Data in ${INSTALL_DIR} and ${ENV_DIR} will be deleted. (y/N): " answer
    [[ "${answer}" =~ ^[Yy]$ ]] || { log_info "Aborted."; maybe_pause; return; }
    _remove_common
    [[ -d "${STATE_DIR}" ]] && rm -rf "${STATE_DIR}"
    log_success "Relay installation removed."
    maybe_pause
}

purge_installation() {
    read -rp "Remove installation AND purge packages installed by this script? (y/N): " answer
    [[ "${answer}" =~ ^[Yy]$ ]] || { log_info "Aborted."; maybe_pause; return; }

    # Read package list BEFORE _remove_common wipes STATE_DIR.
    local purge_pkgs=()
    [[ -f "${INSTALLED_PKGS_FILE}" ]] && mapfile -t purge_pkgs < "${INSTALLED_PKGS_FILE}"

    _remove_common

    if [[ ${#purge_pkgs[@]} -gt 0 ]]; then
        log_info "Purging packages managed by this script: ${purge_pkgs[*]}"
        DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y "${purge_pkgs[@]}"
        DEBIAN_FRONTEND=noninteractive apt-get autoremove -y
    else
        log_info "No package list found - nothing extra to purge."
        log_info "To remove packages manually:"
        log_info "  apt-get remove --purge git nginx php-cli php-curl certbot python3-certbot-nginx unzip rsync openssl php*-fpm"
    fi

    [[ -d "${STATE_DIR}" ]] && rm -rf "${STATE_DIR}"
    log_success "Relay installation removed."
    maybe_pause
}

# ── Usage ──────────────────────────────────────────────────────────────────────
show_usage() {
    cat <<EOF
Usage: sudo ${SCRIPT_NAME} [command] [options]

Commands:
  install           Install or reinstall the relay (interactive)
  status [--json]   Show relay status (optionally JSON)
  monitor           Detailed metrics and upstream health
  config / env      Edit configuration file (${ENV_PATH})
  reload            Reload nginx and php-fpm
  enable-site       Enable nginx site and reload
  disable-site      Disable nginx site and reload
  clear-cache       Remove cached subscription files
  tail-logs         Follow relay logs in real-time
  update            Pull latest code from git
  remove            Remove the relay installation
  purge             Remove installation and packages installed by this script
  menu              Interactive menu (default)
  help              Show this message

HAProxy / non-standard ports:
  Set NGINX_HTTP_PORT and NGINX_HTTPS_PORT before running install
  if ports 80/443 are already occupied by HAProxy or another service.
  Set ACME_HTTP_PORT to the port certbot should bind for the ACME challenge
  (this port must be reachable from the internet as TCP/80).

Environment overrides:
  INSTALL_DIR=      NGINX_HTTP_PORT=   DOMAIN=      UPSTREAM=
  ENV_PATH=         NGINX_HTTPS_PORT=  EMAIL=       TOKEN=
  REPO_URL=         ACME_HTTP_PORT=    ALLOWED=     CACHE_TTL=
  REPO_BRANCH=      SKIP_CERTBOT=1
EOF
}

# ── Main menu ──────────────────────────────────────────────────────────────────
main_menu() {
    IN_MENU=1
    while true; do
        clear
        echo -e "${COLOR_BOLD}${COLOR_BLUE}╔════════════════════════════════════════╗${COLOR_RESET}"
        echo -e "${COLOR_BOLD}${COLOR_BLUE}║     Hiddify Relay Control Panel        ║${COLOR_RESET}"
        echo -e "${COLOR_BOLD}${COLOR_BLUE}╚════════════════════════════════════════╝${COLOR_RESET}\n"
        echo -e "${COLOR_CYAN} 1)${COLOR_RESET} Install or update relay"
        echo -e "${COLOR_CYAN} 2)${COLOR_RESET} Show status"
        echo -e "${COLOR_CYAN} 3)${COLOR_RESET} Monitoring dashboard"
        echo -e "${COLOR_CYAN} 4)${COLOR_RESET} Edit .env configuration"
        echo -e "${COLOR_CYAN} 5)${COLOR_RESET} Reload nginx and php-fpm"
        echo -e "${COLOR_CYAN} 6)${COLOR_RESET} Enable relay site"
        echo -e "${COLOR_CYAN} 7)${COLOR_RESET} Disable relay site"
        echo -e "${COLOR_CYAN} 8)${COLOR_RESET} Clear cache"
        echo -e "${COLOR_CYAN} 9)${COLOR_RESET} Tail logs (live)"
        echo -e "${COLOR_CYAN}10)${COLOR_RESET} Update from git"
        echo -e "${COLOR_CYAN}11)${COLOR_RESET} Remove installation"
        echo -e "${COLOR_CYAN}12)${COLOR_RESET} Purge installation"
        echo -e "${COLOR_CYAN}13)${COLOR_RESET} Exit\n"
        echo -ne "${COLOR_YELLOW}Select an option:${COLOR_RESET} "
        read -r choice
        case "${choice}" in
            1)  install_relay; maybe_pause ;;
            2)  show_status ;;
            3)  monitoring_dashboard ;;
            4)  edit_configuration ;;
            5)  reload_services; maybe_pause ;;
            6)  enable_nginx_site ;;
            7)  disable_nginx_site ;;
            8)  clear_cache ;;
            9)  tail_logs ;;
            10) update_from_git ;;
            11) remove_installation ;;
            12) purge_installation ;;
            13) log_info "Goodbye."; exit 0 ;;
            *)  log_error "Invalid choice."; maybe_pause ;;
        esac
    done
}

# ── Entry point ────────────────────────────────────────────────────────────────
main() {
    require_root
    local cmd="${1:-menu}"
    shift || true
    case "${cmd}" in
        install)        install_relay ;;
        status)         show_status "$@" ;;
        monitor)        monitoring_dashboard ;;
        config|env)     edit_configuration ;;
        reload)         reload_services; maybe_pause ;;
        enable-site)    enable_nginx_site ;;
        disable-site)   disable_nginx_site ;;
        clear-cache)    clear_cache ;;
        tail-logs)      tail_logs ;;
        update)         update_from_git ;;
        remove)         remove_installation ;;
        purge)          purge_installation ;;
        menu)           main_menu ;;
        help|-h|--help) show_usage ;;
        *)  log_error "Unknown command: ${cmd}"; show_usage; exit 1 ;;
    esac
}

main "$@"