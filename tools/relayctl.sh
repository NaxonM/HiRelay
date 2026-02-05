#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/hiddify-relay}"
APP_DIR="${APP_DIR:-${INSTALL_DIR}/apps/relay}"
ENV_PATH="${ENV_PATH:-/etc/hiddify-relay/.env}"
NGINX_SITE="${NGINX_SITE:-/etc/nginx/sites-available/hiddify-relay.conf}"
NGINX_LINK="${NGINX_LINK:-/etc/nginx/sites-enabled/hiddify-relay.conf}"
CACHE_DIR="${CACHE_DIR:-${APP_DIR}/storage/cache}"
LOG_FILE="${LOG_FILE:-${APP_DIR}/storage/relay.log}"
REPO_URL="${REPO_URL:-https://github.com/NaxonM/HiRelay.git}"
REPO_BRANCH="${REPO_BRANCH:-main}"
STATE_DIR="${STATE_DIR:-/var/lib/hiddify-relay}"
INSTALLED_PKGS_FILE="${INSTALLED_PKGS_FILE:-${STATE_DIR}/installed-packages.txt}"
SCRIPT_NAME="$(basename "$0")"
PHP_FPM_UNITS=()
IN_MENU=0

# Color codes
if [[ -t 1 ]]; then
    COLOR_RESET='\033[0m'
    COLOR_RED='\033[0;31m'
    COLOR_GREEN='\033[0;32m'
    COLOR_YELLOW='\033[0;33m'
    COLOR_BLUE='\033[0;34m'
    COLOR_CYAN='\033[0;36m'
    COLOR_BOLD='\033[1m'
else
    COLOR_RESET=''
    COLOR_RED=''
    COLOR_GREEN=''
    COLOR_YELLOW=''
    COLOR_BLUE=''
    COLOR_CYAN=''
    COLOR_BOLD=''
fi

log_info() {
    echo -e "${COLOR_CYAN}[INFO]${COLOR_RESET} $*"
}

log_success() {
    echo -e "${COLOR_GREEN}[✓]${COLOR_RESET} $*"
}

log_error() {
    echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} $*" >&2
}

log_warning() {
    echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} $*"
}

log_header() {
    echo -e "\n${COLOR_BOLD}${COLOR_BLUE}=== $* ===${COLOR_RESET}\n"
}

set_env_value() {
    local key="$1"
    local value="$2"
    if grep -q "^${key}=" "${ENV_PATH}" 2>/dev/null; then
        sed -i "s|^${key}=.*|${key}=${value}|" "${ENV_PATH}"
    else
        echo "${key}=${value}" >> "${ENV_PATH}"
    fi
}

get_env_value() {
    local key="$1"
    if [[ -f "${ENV_PATH}" ]]; then
        grep -E "^${key}=" "${ENV_PATH}" 2>/dev/null | head -n 1 | cut -d'=' -f2-
    fi
}

ensure_env_defaults() {
    local php_binary
    local backup_url
    local snapshot_path

    if command -v php >/dev/null 2>&1; then
        php_binary=$(command -v php)
    else
        php_binary=""
    fi

    set_env_value "RELAY_CACHE_DIR" "${APP_DIR}/storage/cache"
    set_env_value "RELAY_LOG_FILE" "${APP_DIR}/storage/relay.log"
    set_env_value "RELAY_ACCESS_LOG_FILE" "${APP_DIR}/storage/access.log"
    set_env_value "RELAY_RATE_LIMIT_DIR" "${APP_DIR}/storage/ratelimit"
    set_env_value "RELAY_SNAPSHOT_BACKUP_PATH" "${APP_DIR}/storage/cache/backup.json"

    if [[ -n "${php_binary}" ]]; then
        set_env_value "RELAY_PHP_BINARY" "${php_binary}"
    fi

    backup_url=$(get_env_value "RELAY_BACKUP_API_URL")
    if [[ -z "${backup_url}" || "${backup_url}" == *"CHANGEME"* ]]; then
        set_env_value "RELAY_CRON_ENABLED" "0"
        log_warning "RELAY_BACKUP_API_URL is missing or a placeholder; cron refresh disabled."
    fi

    snapshot_path=$(get_env_value "RELAY_SNAPSHOT_BACKUP_PATH")
    if [[ -n "${snapshot_path}" && "${snapshot_path}" != /* ]]; then
        set_env_value "RELAY_SNAPSHOT_BACKUP_PATH" "${APP_DIR}/${snapshot_path#./}"
    fi
}

# Encourage downloading before execution to preserve TTY
if [[ -p /dev/stdin && "${ALLOW_PIPE_EXECUTION:-0}" != "1" ]]; then
    log_error "Direct pipe execution detected."
    log_error "Use: sudo bash -c 'curl -fsSLo /tmp/relayctl.sh https://raw.githubusercontent.com/NaxonM/HiRelay/main/tools/relayctl.sh && chmod +x /tmp/relayctl.sh && /tmp/relayctl.sh menu'"
    log_error "(Set ALLOW_PIPE_EXECUTION=1 to override this safety check.)"
    exit 1
fi

# Ensure interactive input/output are available even when launched via a pipe
if [[ ! -t 0 || ! -t 1 || ! -t 2 ]]; then
    if [[ -r /dev/tty ]]; then
        exec </dev/tty >/dev/tty 2>/dev/tty
    else
        log_error "Interactive TTY not detected. Download the script first, then run sudo ./relayctl.sh menu."
        exit 1
    fi
fi

format_bytes() {
    local bytes="$1"
    if [[ -z "$bytes" || "$bytes" == "0" ]]; then
        echo "0 B"
        return
    fi
    if command -v numfmt >/dev/null 2>&1; then
        numfmt --to=iec --format "%.2f" "$bytes"
    else
        echo "${bytes} B"
    fi
}

load_env_settings() {
    if [[ -f "${ENV_PATH}" ]]; then
        set -a
        # shellcheck disable=SC1090
        source "${ENV_PATH}"
        set +a
    fi
}

has_existing_installation() {
    [[ -d "${APP_DIR}" && -f "${ENV_PATH}" ]]
}

detect_existing_domain() {
    if [[ -n "${RELAY_DOMAIN:-}" ]]; then
        echo "${RELAY_DOMAIN}"
        return
    fi
    if [[ -f "${NGINX_SITE}" ]]; then
        awk '/server_name/ { for (i = 2; i <= NF; ++i) { gsub(";", "", $i); print $i; exit } }' "${NGINX_SITE}" 2>/dev/null
    fi
}

detect_existing_email() {
    if [[ -n "${RELAY_ADMIN_EMAIL:-}" ]]; then
        echo "${RELAY_ADMIN_EMAIL}"
        return
    fi
    return
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "${SCRIPT_NAME} must be run as root." >&2
        exit 1
    fi
}

press_enter() {
    read -rp "Press Enter to continue..." _
}

validate_url() {
    local url="$1"
    if [[ "${url}" =~ ^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$ ]]; then
        return 0
    fi
    return 1
}

validate_domain() {
    local domain="$1"
    if [[ "${domain}" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        return 0
    fi
    return 1
}

maybe_pause() {
    if [[ ${IN_MENU} -eq 1 ]]; then
        press_enter
    fi
}

detect_php_units() {
    local candidates=("php-fpm" "php8.3-fpm" "php8.2-fpm" "php8.1-fpm" "php8.0-fpm" "php7.4-fpm")
    PHP_FPM_UNITS=()
    for unit in "${candidates[@]}"; do
        if systemctl list-unit-files "${unit}.service" &>/dev/null; then
            PHP_FPM_UNITS+=("${unit}")
        fi
    done
}

reload_php_units() {
    detect_php_units
    if [[ ${#PHP_FPM_UNITS[@]} -eq 0 ]]; then
        echo "No php-fpm units detected; nothing to reload."
    else
        for unit in "${PHP_FPM_UNITS[@]}"; do
            echo "Reloading ${unit}..."
            if systemctl reload "${unit}"; then
                echo "${unit} reloaded."
            else
                echo "Failed to reload ${unit}." >&2
            fi
        done
    fi
}

ensure_packages() {
    if ! command -v apt-get >/dev/null 2>&1; then
        echo "apt-get not found. This installer currently supports Debian/Ubuntu systems." >&2
        exit 1
    fi

    local packages=(git nginx php php-fpm php-cli php-curl certbot python3-certbot-nginx unzip rsync openssl)
    local missing=()
    for pkg in "${packages[@]}"; do
        if ! dpkg -s "${pkg}" >/dev/null 2>&1; then
            missing+=("${pkg}")
        fi
    done
    echo "Installing required packages..."
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}"
    if [[ ${#missing[@]} -gt 0 ]]; then
        mkdir -p "${STATE_DIR}"
        printf "%s\n" "${missing[@]}" > "${INSTALLED_PKGS_FILE}"
    else
        rm -f "${INSTALLED_PKGS_FILE}" 2>/dev/null || true
    fi
}

clone_or_update_repo() {
    if [[ -d "${INSTALL_DIR}/.git" ]]; then
        echo "Updating existing repository in ${INSTALL_DIR}..."
        git -C "${INSTALL_DIR}" fetch --all --prune
        git -C "${INSTALL_DIR}" checkout "${REPO_BRANCH}"
        git -C "${INSTALL_DIR}" reset --hard "origin/${REPO_BRANCH}"
    else
        echo "Cloning repository ${REPO_URL} (branch ${REPO_BRANCH})..."
        rm -rf "${INSTALL_DIR}"
        git clone --depth 1 --branch "${REPO_BRANCH}" "${REPO_URL}" "${INSTALL_DIR}"
    fi
}

ensure_storage_permissions() {
    mkdir -p "${APP_DIR}/storage/cache"
    mkdir -p "${APP_DIR}/storage/logs"
    mkdir -p "$(dirname "${LOG_FILE}")"
    if [[ ! -f "${LOG_FILE}" ]]; then
        touch "${LOG_FILE}"
    fi
    chown -R www-data:www-data "${APP_DIR}/storage"
    chown www-data:www-data "${LOG_FILE}" 2>/dev/null || true
    chmod 750 "${APP_DIR}/storage"
    chmod 640 "${LOG_FILE}" 2>/dev/null || true
}

prompt_install_values() {
    local default_domain="${DOMAIN:-}"
    local default_email="${EMAIL:-}"
    local default_upstream="${UPSTREAM:-}"
    local default_token="${TOKEN:-}"
    local default_allowed="${ALLOWED:-}"
    local default_cache_ttl="${CACHE_TTL:-300}"

    log_header "Installation Configuration"

    if [[ -z "${default_domain}" ]]; then
        default_domain="$(detect_existing_domain)"
    fi
    if [[ -z "${default_email}" ]]; then
        default_email="$(detect_existing_email)"
    fi
    if [[ -z "${default_upstream}" && -n "${RELAY_UPSTREAM_BASE_URL:-}" ]]; then
        default_upstream="${RELAY_UPSTREAM_BASE_URL}"
    fi
    if [[ -z "${default_token}" && -n "${RELAY_AUTH_TOKEN:-}" ]]; then
        default_token="${RELAY_AUTH_TOKEN}"
    fi
    if [[ -z "${default_allowed}" && -n "${RELAY_ALLOWED_CLIENTS:-}" ]]; then
        default_allowed="${RELAY_ALLOWED_CLIENTS}"
    fi
    if [[ -z "${default_cache_ttl}" && -n "${RELAY_CACHE_TTL:-}" ]]; then
        default_cache_ttl="${RELAY_CACHE_TTL}"
    fi

    # Domain prompt with validation
    while [[ -z "${default_domain}" ]]; do
        echo -e "${COLOR_CYAN}Enter relay domain${COLOR_RESET} (e.g. ${COLOR_YELLOW}relay.example.com${COLOR_RESET})"
        read -rp "> " default_domain
        if ! validate_domain "${default_domain}"; then
            log_error "Invalid domain format. Please use a valid domain name."
            default_domain=""
        fi
    done

    # Email prompt with validation
    while [[ -z "${default_email}" ]]; do
        echo -e "${COLOR_CYAN}Admin email for Let's Encrypt${COLOR_RESET} (e.g. ${COLOR_YELLOW}admin@example.com${COLOR_RESET})"
        read -rp "> " default_email
        if [[ ! "${default_email}" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            log_error "Invalid email format. Please use a valid email address."
            default_email=""
        fi
    done

    # Upstream URL prompt with validation
    local input_upstream
    while true; do
        echo -e "${COLOR_CYAN}Upstream base URL${COLOR_RESET} (e.g. ${COLOR_YELLOW}https://sub.example.com${COLOR_RESET})"
        if [[ -n "${default_upstream}" ]]; then
            read -rp "> [${default_upstream}]: " input_upstream
        else
            read -rp "> " input_upstream
        fi
        
        if [[ -z "${input_upstream}" && -n "${default_upstream}" ]]; then
            break
        elif [[ -n "${input_upstream}" ]]; then
            if validate_url "${input_upstream}"; then
                default_upstream="${input_upstream}"
                break
            else
                log_error "Invalid URL format. Please use a full URL (e.g. https://example.com)"
            fi
        else
            log_error "Upstream URL is required."
        fi
    done

    # Token prompt (optional)
    echo -e "${COLOR_CYAN}Shared secret token${COLOR_RESET} (optional, press Enter to skip)"
    read -rp "> " input_token || true
    if [[ -n "${input_token:-}" ]]; then
        default_token="${input_token}"
    fi

    # Allowed IPs prompt
    echo -e "${COLOR_CYAN}Allowed client IPs${COLOR_RESET} (comma separated, blank for all)"
    echo -e "  Example: ${COLOR_YELLOW}1.2.3.4,5.6.7.8${COLOR_RESET}"
    read -rp "> " input_allowed || true
    if [[ -n "${input_allowed:-}" ]]; then
        default_allowed="${input_allowed}"
    fi

    # Cache TTL prompt
    echo -e "${COLOR_CYAN}Cache TTL seconds${COLOR_RESET} [${COLOR_YELLOW}${default_cache_ttl}${COLOR_RESET}]"
    read -rp "> " input_ttl || true
    if [[ -n "${input_ttl:-}" ]]; then
        default_cache_ttl="${input_ttl}"
    fi

    INSTALL_DOMAIN="${default_domain}"
    INSTALL_EMAIL="${default_email}"
    INSTALL_UPSTREAM="${default_upstream}"
    INSTALL_TOKEN="${default_token}"
    INSTALL_ALLOWED="${default_allowed}"
    INSTALL_CACHE_TTL="${default_cache_ttl}"

    log_info "Configuration summary:"
    echo -e "  Domain: ${COLOR_GREEN}${INSTALL_DOMAIN}${COLOR_RESET}"
    echo -e "  Email: ${COLOR_GREEN}${INSTALL_EMAIL}${COLOR_RESET}"
    echo -e "  Upstream: ${COLOR_GREEN}${INSTALL_UPSTREAM}${COLOR_RESET}"
    echo -e "  Token: ${COLOR_GREEN}${INSTALL_TOKEN:-<not set>}${COLOR_RESET}"
    echo -e "  Allowed IPs: ${COLOR_GREEN}${INSTALL_ALLOWED:-<all>}${COLOR_RESET}"
    echo -e "  Cache TTL: ${COLOR_GREEN}${INSTALL_CACHE_TTL}s${COLOR_RESET}"
    echo
}

write_env_file() {
    local timezone=""
    local php_binary=""

    if command -v timedatectl >/dev/null 2>&1; then
        timezone=$(timedatectl show -p Timezone --value 2>/dev/null || true)
    elif [[ -f /etc/timezone ]]; then
        timezone=$(cat /etc/timezone 2>/dev/null || true)
    fi
    if command -v php >/dev/null 2>&1; then
        php_binary=$(command -v php)
    fi

    mkdir -p "$(dirname "${ENV_PATH}")"
    if [[ -f "${APP_DIR}/.env.example" ]]; then
        cp "${APP_DIR}/.env.example" "${ENV_PATH}"
    else
        : > "${ENV_PATH}"
    fi

    set_env_value "RELAY_UPSTREAM_BASE_URL" "${INSTALL_UPSTREAM}"
    set_env_value "CACHE_SOURCE_BASE_URL" "${INSTALL_UPSTREAM}"
    set_env_value "RELAY_AUTH_TOKEN" "${INSTALL_TOKEN}"
    set_env_value "RELAY_ALLOWED_CLIENTS" "${INSTALL_ALLOWED}"
    set_env_value "RELAY_CACHE_TTL" "${INSTALL_CACHE_TTL}"
    set_env_value "RELAY_CONNECT_TIMEOUT" "10"
    set_env_value "RELAY_TRANSFER_TIMEOUT" "60"
    set_env_value "RELAY_CACHE_DIR" "${APP_DIR}/storage/cache"
    set_env_value "RELAY_LOG_FILE" "${APP_DIR}/storage/relay.log"
    set_env_value "RELAY_ACCESS_LOG_FILE" "${APP_DIR}/storage/access.log"
    set_env_value "RELAY_RATE_LIMIT_DIR" "${APP_DIR}/storage/ratelimit"
    set_env_value "RELAY_SNAPSHOT_BACKUP_PATH" "${APP_DIR}/storage/cache/backup.json"
    set_env_value "RELAY_SNAPSHOT_BASE_URL" "${INSTALL_UPSTREAM}"
    set_env_value "RELAY_DOMAIN" "${INSTALL_DOMAIN}"
    set_env_value "RELAY_ADMIN_EMAIL" "${INSTALL_EMAIL}"

    if [[ -n "${timezone}" ]]; then
        set_env_value "RELAY_TIMEZONE" "${timezone}"
    fi
    if [[ -n "${php_binary}" ]]; then
        set_env_value "RELAY_PHP_BINARY" "${php_binary}"
    fi

    ensure_env_defaults

    chmod 640 "${ENV_PATH}"
    chown root:www-data "${ENV_PATH}" 2>/dev/null || true
}

write_nginx_config() {
    cat > "${NGINX_SITE}" <<EOF
server {
    listen 80;
    server_name ${INSTALL_DOMAIN};

    root ${APP_DIR}/public;
    index index.php;

    location / {
        try_files \$uri /index.php?\$args;
    }

    location ~ \\.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    }
}
EOF
    ln -sf "${NGINX_SITE}" "${NGINX_LINK}"
}

write_nginx_ssl_config() {
    local cert_path="$1"
    local key_path="$2"

    cat > "${NGINX_SITE}" <<EOF
server {
    listen 80;
    server_name ${INSTALL_DOMAIN};
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name ${INSTALL_DOMAIN};

    ssl_certificate ${cert_path};
    ssl_certificate_key ${key_path};

    root ${APP_DIR}/public;
    index index.php;

    location / {
        try_files \$uri /index.php?\$args;
    }

    location ~ \\.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    }
}
EOF
    ln -sf "${NGINX_SITE}" "${NGINX_LINK}"
}

run_certbot() {
    if [[ "${SKIP_CERTBOT:-0}" == "1" ]]; then
        echo "SKIP_CERTBOT=1 set; skipping certificate issuance."
        return
    fi
    if [[ -z "${INSTALL_DOMAIN}" || -z "${INSTALL_EMAIL}" ]]; then
        echo "Domain or email not provided, skipping certbot." >&2
        return
    fi
    if certbot --nginx -d "${INSTALL_DOMAIN}" -m "${INSTALL_EMAIL}" --agree-tos --non-interactive --redirect; then
        log_success "Certificate issued and nginx updated."
        return
    fi

    log_warning "Certbot failed. Choose how to continue:"
    while true; do
        echo "  [S] Skip SSL for now"
        echo "  [P] Provide existing certificate paths"
        echo "  [R] Retry certbot"
        read -rp "> " cert_choice
        case "${cert_choice}" in
            S|s)
                log_warning "Skipping SSL setup. You can add it later."
                return
                ;;
            P|p)
                local cert_path
                local key_path
                read -rp "Fullchain certificate path: " cert_path
                read -rp "Private key path: " key_path
                if [[ -z "${cert_path}" || -z "${key_path}" ]]; then
                    log_error "Both certificate and key paths are required."
                    continue
                fi
                if [[ ! -r "${cert_path}" || ! -r "${key_path}" ]]; then
                    log_error "Certificate or key file not readable. Check paths and permissions."
                    continue
                fi
                write_nginx_ssl_config "${cert_path}" "${key_path}"
                if nginx -t; then
                    systemctl reload nginx
                    log_success "Nginx updated with provided certificate."
                    return
                fi
                log_error "Nginx config test failed. Please check the provided paths."
                ;;
            R|r)
                if certbot --nginx -d "${INSTALL_DOMAIN}" -m "${INSTALL_EMAIL}" --agree-tos --non-interactive --redirect; then
                    log_success "Certificate issued and nginx updated."
                    return
                fi
                log_warning "Certbot failed again."
                ;;
            *)
                log_error "Invalid choice."
                ;;
        esac
    done
}

install_relay() {
    local reuse_config=0

    if has_existing_installation; then
        load_env_settings
        log_header "Existing Installation Detected"
        echo -e "Found prior configuration at ${COLOR_CYAN}${ENV_PATH}${COLOR_RESET} and code under ${COLOR_CYAN}${APP_DIR}${COLOR_RESET}."
        read -rp "Reuse existing configuration and certificates? [Y/n]: " reuse_answer
        if [[ -z "${reuse_answer}" || "${reuse_answer}" =~ ^[Yy]$ ]]; then
            reuse_config=1
        fi
    fi

    if [[ ${reuse_config} -eq 1 ]]; then
        ensure_packages
        clone_or_update_repo
        ensure_storage_permissions
        nginx -t
        systemctl reload nginx
        reload_php_units

        local reused_domain="$(detect_existing_domain)"
        local reused_email="$(detect_existing_email)"
        local reused_upstream="${RELAY_UPSTREAM_BASE_URL:-}" 
        local reused_token="${RELAY_AUTH_TOKEN:-}" 
        local reused_allowed="${RELAY_ALLOWED_CLIENTS:-}" 
        local reused_cache_ttl="${RELAY_CACHE_TTL:-300}"

        log_success "Code updated and services reloaded using existing configuration."
        echo -e "  Domain: ${COLOR_GREEN}${reused_domain:-<unknown>}$( [[ -n "${reused_email}" ]] && printf " (cert email: %s)" "${reused_email}" )${COLOR_RESET}"
        echo -e "  Upstream: ${COLOR_GREEN}${reused_upstream:-<not set>}${COLOR_RESET}"
        echo -e "  Token: ${COLOR_GREEN}${reused_token:-<not set>}${COLOR_RESET}"
        echo -e "  Allowed IPs: ${COLOR_GREEN}${reused_allowed:-<all>}${COLOR_RESET}"
        echo -e "  Cache TTL: ${COLOR_GREEN}${reused_cache_ttl}s${COLOR_RESET}"
        log_info "Existing SSL certificates were left untouched."
        return
    fi

    prompt_install_values
    if [[ -z "${INSTALL_DOMAIN}" ]]; then
        echo "Domain is required for installation." >&2
        exit 1
    fi
    if [[ -z "${INSTALL_EMAIL}" && "${SKIP_CERTBOT:-0}" != "1" ]]; then
        echo "Email is required for Let's Encrypt. Provide EMAIL=you@example.com or set SKIP_CERTBOT=1." >&2
        exit 1
    fi
    if [[ -z "${INSTALL_UPSTREAM}" ]]; then
        echo "Upstream base URL is required." >&2
        exit 1
    fi
    ensure_packages
    clone_or_update_repo
    ensure_storage_permissions
    write_env_file
    write_nginx_config
    nginx -t
    systemctl reload nginx
    run_certbot
    systemctl reload nginx
    reload_php_units

    echo "Installation complete."
    echo "Domain: ${INSTALL_DOMAIN}"
    echo "Shared secret: ${INSTALL_TOKEN}"
    echo "Environment: ${ENV_PATH}"
    echo "Install directory: ${INSTALL_DIR}"
    echo "App directory: ${APP_DIR}"
}

show_status() {
    local json_mode="${1:-}"
    
    if [[ "${json_mode}" == "--json" ]]; then
        show_status_json
        return
    fi

    log_header "Hiddify Relay Status"

    # Installation status
    echo -e "${COLOR_BOLD}Installation:${COLOR_RESET}"
    if [[ -d "${APP_DIR}" ]]; then
        log_success "Present at ${COLOR_CYAN}${APP_DIR}${COLOR_RESET}"
    else
        log_error "NOT FOUND"
    fi

    # Configuration status
    echo -e "\n${COLOR_BOLD}Configuration:${COLOR_RESET}"
    if [[ -f "${ENV_PATH}" ]]; then
        log_success "${COLOR_CYAN}${ENV_PATH}${COLOR_RESET}"
        if [[ -r "${ENV_PATH}" ]]; then
            local upstream
            upstream=$(grep '^RELAY_UPSTREAM_BASE_URL=' "${ENV_PATH}" 2>/dev/null | cut -d'=' -f2)
            if [[ -n "${upstream}" ]]; then
                echo -e "  Upstream: ${COLOR_GREEN}${upstream}${COLOR_RESET}"
            else
                log_warning "  Upstream not configured"
            fi
        fi
    else
        log_error "Missing (${ENV_PATH})"
    fi

    # Nginx status
    echo -e "\n${COLOR_BOLD}Web Server:${COLOR_RESET}"
    if [[ -L "${NGINX_LINK}" ]]; then
        log_success "Site enabled"
    else
        log_warning "Site disabled"
    fi

    if systemctl is-active nginx >/dev/null 2>&1; then
        log_success "nginx: ${COLOR_GREEN}active${COLOR_RESET}"
    else
        log_error "nginx: inactive"
    fi

    # PHP-FPM status
    detect_php_units
    if [[ ${#PHP_FPM_UNITS[@]} -gt 0 ]]; then
        for unit in "${PHP_FPM_UNITS[@]}"; do
            if systemctl is-active "${unit}" >/dev/null 2>&1; then
                log_success "${unit}: ${COLOR_GREEN}active${COLOR_RESET}"
            else
                log_warning "${unit}: inactive"
            fi
        done
    else
        log_warning "php-fpm: service not detected"
    fi

    # Cache status
    echo -e "\n${COLOR_BOLD}Cache:${COLOR_RESET}"
    if [[ -d "${CACHE_DIR}" ]]; then
        local cache_size cache_entries
        cache_size=$(du -sh "${CACHE_DIR}" 2>/dev/null | awk '{print $1}')
        cache_entries=$(find "${CACHE_DIR}" -type f 2>/dev/null | wc -l)
        echo -e "  Files: ${COLOR_CYAN}${cache_entries}${COLOR_RESET}"
        echo -e "  Size: ${COLOR_CYAN}${cache_size}${COLOR_RESET}"
    else
        log_warning "Directory not found (${CACHE_DIR})"
    fi

    # Log status
    echo -e "\n${COLOR_BOLD}Logs:${COLOR_RESET}"
    if [[ -f "${LOG_FILE}" ]]; then
        local total_lines error_lines
        total_lines=$(wc -l < "${LOG_FILE}" 2>/dev/null || echo 0)
        error_lines=$(grep -ci "error" "${LOG_FILE}" 2>/dev/null || echo 0)
        echo -e "  Location: ${COLOR_CYAN}${LOG_FILE}${COLOR_RESET}"
        echo -e "  Total lines: ${COLOR_CYAN}${total_lines}${COLOR_RESET}"
        if [[ ${error_lines} -gt 0 ]]; then
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

show_status_json() {
    local installation_present="false"
    local config_present="false"
    local nginx_enabled="false"
    local nginx_active="false"
    local upstream=""
    local cache_entries=0
    local cache_size="0"
    local log_lines=0
    local log_errors=0
    
    [[ -d "${INSTALL_DIR}" ]] && installation_present="true"
    [[ -f "${ENV_PATH}" ]] && config_present="true"
    [[ -L "${NGINX_LINK}" ]] && nginx_enabled="true"
    systemctl is-active nginx >/dev/null 2>&1 && nginx_active="true"
    
    if [[ -r "${ENV_PATH}" ]]; then
        upstream=$(grep '^RELAY_UPSTREAM_BASE_URL=' "${ENV_PATH}" 2>/dev/null | cut -d'=' -f2 | tr -d '"')
    fi
    
    if [[ -d "${CACHE_DIR}" ]]; then
        cache_entries=$(find "${CACHE_DIR}" -type f 2>/dev/null | wc -l)
        cache_size=$(du -sb "${CACHE_DIR}" 2>/dev/null | awk '{print $1}')
    fi
    
    if [[ -f "${LOG_FILE}" ]]; then
        log_lines=$(wc -l < "${LOG_FILE}" 2>/dev/null || echo 0)
        log_errors=$(grep -ci "error" "${LOG_FILE}" 2>/dev/null || echo 0)
    fi
    
    detect_php_units
    local php_status="inactive"
    if [[ ${#PHP_FPM_UNITS[@]} -gt 0 ]] && systemctl is-active "${PHP_FPM_UNITS[0]}" >/dev/null 2>&1; then
        php_status="active"
    fi
    
    cat <<EOF
{
  "installation": {
    "present": ${installation_present},
    "path": "${INSTALL_DIR}"
  },
  "configuration": {
    "present": ${config_present},
    "path": "${ENV_PATH}",
    "upstream": "${upstream}"
  },
  "services": {
    "nginx": {
      "enabled": ${nginx_enabled},
      "active": ${nginx_active}
    },
    "php_fpm": {
      "active": "${php_status}"
    }
  },
  "cache": {
    "entries": ${cache_entries},
    "size_bytes": ${cache_size}
  },
  "logs": {
    "lines": ${log_lines},
    "errors": ${log_errors},
    "path": "${LOG_FILE}"
  }
}
EOF
}

monitoring_dashboard() {
    log_header "Monitoring Dashboard"

    if [[ ! -d "${APP_DIR}" ]]; then
        log_error "App directory not found at ${APP_DIR}. Run install first."
        maybe_pause
        return
    fi

    load_env_settings

    local upstream="${RELAY_UPSTREAM_BASE_URL:-}"
    local cache_dir="${RELAY_CACHE_DIR:-${APP_DIR}/storage/cache}"
    local log_file="${RELAY_LOG_FILE:-${APP_DIR}/storage/relay.log}"

    # Cache metrics
    local cache_entries=0
    local cache_size_bytes=0
    if [[ -d "${cache_dir}" ]]; then
        cache_entries=$(find "${cache_dir}" -type f 2>/dev/null | wc -l | tr -d ' ')
        cache_size_bytes=$(du -sb "${cache_dir}" 2>/dev/null | awk '{print $1}')
    fi
    local cache_size_human="$(format_bytes "${cache_size_bytes}")"

    # Log metrics
    local log_lines=0
    local log_errors=0
    local recent_errors=""
    if [[ -f "${log_file}" ]]; then
        log_lines=$(wc -l < "${log_file}" 2>/dev/null || echo 0)
        log_errors=$(grep -c "[Ee]rror" "${log_file}" 2>/dev/null || echo 0)
        recent_errors=$(grep -i "error" "${log_file}" 2>/dev/null | tail -n 5)
    fi

    # Upstream health check
    local upstream_status="not configured"
    local upstream_http="-"
    local upstream_time="-"
    if [[ -n "${upstream}" ]]; then
        local curl_output
        curl_output=$(curl -s -o /dev/null -w "%{http_code} %{time_total}" --connect-timeout 3 --max-time 5 -I "${upstream}" 2>/dev/null || true)
        if [[ -n "${curl_output}" ]]; then
            upstream_http="${curl_output%% *}"
            upstream_time="${curl_output##* }"
            if [[ "${upstream_http}" -ge 200 && "${upstream_http}" -lt 500 ]]; then
                upstream_status="reachable"
            else
                upstream_status="unreachable"
            fi
        else
            upstream_status="unreachable"
        fi
    fi

    echo -e "${COLOR_BOLD}Upstream:${COLOR_RESET}"
    if [[ -n "${upstream}" ]]; then
        echo -e "  URL: ${COLOR_CYAN}${upstream}${COLOR_RESET}"
        local status_color="${COLOR_YELLOW}"
        case "${upstream_status}" in
            reachable) status_color="${COLOR_GREEN}" ;;
            unreachable) status_color="${COLOR_RED}" ;;
            *) status_color="${COLOR_YELLOW}" ;;
        esac
        local status_text
        status_text=$(echo "${upstream_status}" | tr '[:lower:]' '[:upper:]')
        echo -e "  Status: ${status_color}${status_text}${COLOR_RESET}"
        echo -e "  HTTP code: ${COLOR_CYAN}${upstream_http}${COLOR_RESET}"
        echo -e "  Response time: ${COLOR_CYAN}${upstream_time}s${COLOR_RESET}"
    else
        log_warning "  Upstream not configured"
    fi

    echo -e "\n${COLOR_BOLD}Cache:${COLOR_RESET}"
    if [[ -d "${cache_dir}" ]]; then
        echo -e "  Directory: ${COLOR_CYAN}${cache_dir}${COLOR_RESET}"
        echo -e "  Entries: ${COLOR_CYAN}${cache_entries}${COLOR_RESET}"
        echo -e "  Size: ${COLOR_CYAN}${cache_size_human}${COLOR_RESET}"
    else
        log_warning "  Cache directory missing (${cache_dir})"
    fi

    echo -e "\n${COLOR_BOLD}Logs:${COLOR_RESET}"
    if [[ -f "${log_file}" ]]; then
        echo -e "  File: ${COLOR_CYAN}${log_file}${COLOR_RESET}"
        echo -e "  Lines: ${COLOR_CYAN}${log_lines}${COLOR_RESET}"
        if [[ "${log_errors}" -gt 0 ]]; then
            echo -e "  Errors: ${COLOR_RED}${log_errors}${COLOR_RESET}"
            if [[ -n "${recent_errors}" ]]; then
                echo -e "\n  ${COLOR_BOLD}Recent errors:${COLOR_RESET}"
                while IFS= read -r line; do
                    echo "    ${line}"
                done <<< "${recent_errors}"
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
        disk_line=$(df -h "${APP_DIR}" 2>/dev/null | awk 'NR==2 {print $2 " total, " $3 " used (" $5 ")"}')
        if [[ -n "${disk_line}" ]]; then
            echo -e "  Disk usage at install path: ${COLOR_CYAN}${disk_line}${COLOR_RESET}"
        fi
    fi
    echo -e "  PHP version: ${COLOR_CYAN}$(php -r 'echo PHP_VERSION;' 2>/dev/null || echo "unknown")${COLOR_RESET}"

    maybe_pause
}
 
ensure_paths() {
    if [[ ! -d "${INSTALL_DIR}" ]]; then
        echo "Install directory ${INSTALL_DIR} not found." >&2
        return 1
    fi
    mkdir -p "${APP_DIR}/storage"
    mkdir -p "${CACHE_DIR}"
}

edit_configuration() {
    ensure_paths || { maybe_pause; return; }
    if [[ ! -f "${ENV_PATH}" ]]; then
        echo "Creating ${ENV_PATH} from template."
        if [[ -f "${APP_DIR}/.env.example" ]]; then
            cp "${APP_DIR}/.env.example" "${ENV_PATH}"
        else
            touch "${ENV_PATH}"
        fi
        chmod 640 "${ENV_PATH}"
        chown root:www-data "${ENV_PATH}" 2>/dev/null || true
    fi
    local editor="${EDITOR:-nano}"
    "${editor}" "${ENV_PATH}"
    ensure_env_defaults
    maybe_pause
}

reload_services() {
    echo "Reloading nginx..."
    systemctl reload nginx
    reload_php_units
    maybe_pause
}

enable_nginx_site() {
    if [[ ! -f "${NGINX_SITE}" ]]; then
        echo "Site configuration ${NGINX_SITE} is missing." >&2
        maybe_pause
        return
    fi
    ln -sf "${NGINX_SITE}" "${NGINX_LINK}"
    nginx -t
    systemctl reload nginx
    echo "Relay site enabled."
    maybe_pause
}

disable_nginx_site() {
    if [[ -L "${NGINX_LINK}" ]]; then
        rm -f "${NGINX_LINK}"
        nginx -t
        systemctl reload nginx
        echo "Relay site disabled (nginx reloaded)."
    else
        echo "Relay site link not present; nothing to disable."
    fi
    maybe_pause
}

update_from_git() {
    ensure_paths || { maybe_pause; return; }
    if [[ ! -d "${INSTALL_DIR}/.git" ]]; then
        echo "Git metadata not found in ${INSTALL_DIR}. Cannot update automatically." >&2
        maybe_pause
        return
    fi
    git -C "${INSTALL_DIR}" fetch --all --prune
    git -C "${INSTALL_DIR}" pull --ff-only
    echo "Update complete. Consider reloading services if files changed."
    maybe_pause
}

clear_cache() {
    if [[ -d "${CACHE_DIR}" ]]; then
        rm -f "${CACHE_DIR}"/* 2>/dev/null || true
        log_success "Cache directory cleared."
    else
        log_warning "Cache directory not found (${CACHE_DIR})."
    fi
    maybe_pause
}

tail_logs() {
    if [[ ! -f "${LOG_FILE}" ]]; then
        log_error "Log file not found: ${LOG_FILE}"
        maybe_pause
        return
    fi
    
    log_header "Relay Logs (Press Ctrl+C to exit)"
    echo -e "${COLOR_CYAN}Following: ${LOG_FILE}${COLOR_RESET}\n"
    
    tail -f "${LOG_FILE}" 2>/dev/null || {
        log_error "Failed to tail log file"
        maybe_pause
    }
}

remove_installation() {
    read -rp "This will remove the relay installation. Continue? (y/N): " answer
    case "${answer}" in
        y|Y|yes|YES)
            ;;
        *)
            echo "Aborted."
            maybe_pause
            return
            ;;
    esac

    if [[ -L "${NGINX_LINK}" ]]; then
        rm -f "${NGINX_LINK}"
    fi
    if [[ -f "${NGINX_SITE}" ]]; then
        rm -f "${NGINX_SITE}"
    fi
    if [[ -d "${INSTALL_DIR}" ]]; then
        rm -rf "${INSTALL_DIR}"
    fi
    if [[ -f "${ENV_PATH}" ]]; then
        rm -f "${ENV_PATH}"
    fi
    systemctl reload nginx
    echo "Relay installation removed."
    maybe_pause
}

purge_installation() {
    read -rp "This will remove the relay installation and purge packages installed by this script. Continue? (y/N): " answer
    case "${answer}" in
        y|Y|yes|YES)
            ;;
        *)
            echo "Aborted."
            maybe_pause
            return
            ;;
    esac

    local had_nginx=0
    if dpkg -s nginx >/dev/null 2>&1; then
        had_nginx=1
    fi

    if [[ -L "${NGINX_LINK}" ]]; then
        rm -f "${NGINX_LINK}"
    fi
    if [[ -f "${NGINX_SITE}" ]]; then
        rm -f "${NGINX_SITE}"
    fi
    if [[ -d "${INSTALL_DIR}" ]]; then
        rm -rf "${INSTALL_DIR}"
    fi
    if [[ -f "${ENV_PATH}" ]]; then
        rm -f "${ENV_PATH}"
    fi

    if [[ -f "${INSTALLED_PKGS_FILE}" ]]; then
        mapfile -t purge_pkgs < "${INSTALLED_PKGS_FILE}"
        if [[ ${#purge_pkgs[@]} -gt 0 ]]; then
            echo "Purging packages installed by this script..."
            DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y "${purge_pkgs[@]}"
            DEBIAN_FRONTEND=noninteractive apt-get autoremove -y
        fi
    fi

    if [[ -d "${STATE_DIR}" ]]; then
        rm -rf "${STATE_DIR}"
    fi

    if [[ ${had_nginx} -eq 1 ]] && dpkg -s nginx >/dev/null 2>&1; then
        systemctl reload nginx || true
    fi

    echo "Relay installation and tracked packages removed."
    maybe_pause
}

show_usage() {
    cat <<EOF
Usage: sudo ${SCRIPT_NAME} [command] [options]

Commands:
  install           Install or reinstall the relay (interactive prompts)
  status [--json]   Show relay status information (optionally as JSON)
    monitor           Display detailed metrics and upstream health
    config            Edit configuration file (${ENV_PATH})
    env               Alias for config
  reload            Reload nginx and php-fpm services
  enable-site       Enable nginx site and reload nginx
  disable-site      Disable nginx site and reload nginx
  clear-cache       Remove cached subscription files
  tail-logs         Follow relay logs in real-time
  update            Pull latest code from git in ${INSTALL_DIR}
  remove            Remove the relay installation
    purge             Remove installation and packages installed by this script
  menu              Launch interactive menu (default)
  help              Show this message

Environment overrides:
  INSTALL_DIR=/path/to/install
  ENV_PATH=/etc/hiddify-relay/.env
  REPO_URL=https://github.com/your/repo.git
  REPO_BRANCH=branch-name
  DOMAIN=relay.example.com (for install)
  EMAIL=admin@example.com (for install)
  UPSTREAM=https://upstream.example.com
  TOKEN=shared-secret
  ALLOWED="1.2.3.4,5.6.7.8"
  CACHE_TTL=300
    SKIP_CERTBOT=1 (skip Let's Encrypt issuance during install)
EOF
}

main_menu() {
    IN_MENU=1
    while true; do
        clear
        echo -e "${COLOR_BOLD}${COLOR_BLUE}╔════════════════════════════════════════╗${COLOR_RESET}"
        echo -e "${COLOR_BOLD}${COLOR_BLUE}║     Hiddify Relay Control Panel       ║${COLOR_RESET}"
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
            1) install_relay; maybe_pause ;;
            2) show_status ;;
            3) monitoring_dashboard ;;
            4) edit_configuration ;;
            5) reload_services ;;
            6) enable_nginx_site ;;
            7) disable_nginx_site ;;
            8) clear_cache ;;
            9) tail_logs ;;
            10) update_from_git ;;
            11) remove_installation ;;
            12) purge_installation ;;
            13) log_info "Goodbye."; exit 0 ;;
            *) log_error "Invalid choice."; maybe_pause ;;
        esac
    done
}

main() {
    require_root
    local cmd="${1:-menu}"
    shift || true

    case "${cmd}" in
        install)
            install_relay
            ;;
        status)
            show_status "$@"
            ;;
        monitor)
            monitoring_dashboard
            ;;
        config|env)
            edit_configuration
            ;;
        reload)
            reload_services
            ;;
        enable-site)
            enable_nginx_site
            ;;
        disable-site)
            disable_nginx_site
            ;;
        clear-cache)
            clear_cache
            ;;
        tail-logs)
            tail_logs
            ;;
        update)
            update_from_git
            ;;
        remove)
            remove_installation
            ;;
        purge)
            purge_installation
            ;;
        menu)
            main_menu
            ;;
        help|-h|--help)
            show_usage
            ;;
        *)
            log_error "Unknown command: ${cmd}"
            show_usage
            exit 1
            ;;
    esac
}

main "$@"
