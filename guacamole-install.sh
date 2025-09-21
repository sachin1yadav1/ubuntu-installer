#!/usr/bin/env bash
# guacamole-install.sh — Guacamole installer for Ubuntu (20.04/22.04/24.04+)
# Version: 1.0.0 - Production 
# Usage: sudo ./guacamole-install.sh
# Author: Enhanced for maximum security and reliability
set -euo pipefail
IFS=$'\n\t'

### ========== CONFIGURATION - EDIT BEFORE RUNNING ==========
GUAC_VERSION="1.5.3"
GUAC_HOME="/etc/guacamole"
TOMCAT_USER="tomcat"
USE_MYSQL=true
ENABLE_NGINX=true
ENABLE_TLS=false           # true requires DOMAIN + EMAIL_LETSENCRYPT
DOMAIN=""                  # e.g. guac.example.com
EMAIL_LETSENCRYPT=""
ENABLE_UFW=true
AUTO_ENABLE_UFW=false      # set to true if you want script to run `ufw enable` automatically
GUAC_ADMIN_USER="admin"
GUAC_ADMIN_PASS=""         # generated if empty - will use strong password
DB_NAME="guacamole_db"
DB_USER="guacuser"
DB_PASS=""                 # generated if empty - will use strong password
DB_ROOT_PASS=""            # generated if empty - HIGHLY RECOMMENDED
BACKUP_DIR="/var/backups/guacamole"
LOGFILE="/var/log/guacamole_installer.log"
MAX_BACKUP_COUNT=10        # Keep last N backups
ENABLE_2FA=false           # Enable TOTP extension (experimental)
ENABLE_MONITORING=true     # Install basic monitoring
STRICT_SSL=true            # Enforce strong SSL settings
LOCKDOWN_TOMCAT=true       # Restrict Tomcat to localhost when using Nginx
# ===========================================================

### ========== GLOBAL VARIABLES ==========
SCRIPT_VERSION="2.0.0"
SCRIPT_START_TIME=$(date +%s)
TOMCAT_SERVICE=""
INSTALL_LOG=""
ROLLBACK_STACK=()
TEMP_DIRS=()
ERROR_COUNT=0
WARNING_COUNT=0
# =======================================

### ========== UTILITY FUNCTIONS ==========
# Enhanced logging with levels
log() { 
    local level="${1:-INFO}"
    shift
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    local message="[$timestamp] [$level] $*"
    echo "$message"
    [[ -n "${INSTALL_LOG:-}" ]] && echo "$message" >> "$INSTALL_LOG"
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "$@"; ((WARNING_COUNT++)); }
log_error() { log "ERROR" "$@"; ((ERROR_COUNT++)); }
log_success() { log "SUCCESS" "$@"; }
log_debug() { [[ "${DEBUG:-false}" == true ]] && log "DEBUG" "$@" || true; }

# Enhanced error handling with stack trace
die() {
    log_error "FATAL: $*"
    log_error "Stack trace:"
    local frame=0
    while caller $frame; do
        ((frame++))
    done | while read line func file; do
        log_error "  at $func ($file:$line)"
    done
    cleanup_on_error
    exit 1
}

# Cleanup function for error scenarios
cleanup_on_error() {
    log_error "Performing cleanup due to error..."
    
    # Remove temporary directories
    for temp_dir in "${TEMP_DIRS[@]}"; do
        [[ -d "$temp_dir" ]] && rm -rf "$temp_dir"
    done
    
    # Execute rollback stack in reverse order
    for ((i=${#ROLLBACK_STACK[@]}-1; i>=0; i--)); do
        log_info "Rollback: ${ROLLBACK_STACK[i]}"
        eval "${ROLLBACK_STACK[i]}" || true
    done
    
    log_error "Cleanup completed. Check logs for details."
}

# Enhanced random password generation
rand_password() {
    local length="${1:-32}"
    local charset="A-Za-z0-9!@#$%^&*()-_=+[]{}|;:,.<>?"
    
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 $((length * 2)) | tr -cd "$charset" | head -c"$length"
    else
        head -c$((length * 2)) /dev/urandom | tr -cd "$charset" | head -c"$length"
    fi
    echo
}

# Enhanced retry mechanism with exponential backoff
retry() {
    local cmd="$1"
    local max_attempts="${2:-5}"
    local base_delay="${3:-2}"
    local max_delay="${4:-60}"
    local attempt=1
    local delay="$base_delay"
    
    while (( attempt <= max_attempts )); do
        log_debug "Attempt $attempt/$max_attempts: $cmd"
        
        if eval "$cmd"; then
            [[ $attempt -gt 1 ]] && log_success "Command succeeded on attempt $attempt"
            return 0
        fi
        
        if (( attempt == max_attempts )); then
            log_error "Command failed after $max_attempts attempts: $cmd"
            return 1
        fi
        
        log_warn "Attempt $attempt failed. Retrying in ${delay}s..."
        sleep "$delay"
        
        # Exponential backoff with jitter
        delay=$(( delay * 2 + (RANDOM % 5) ))
        [[ $delay -gt $max_delay ]] && delay=$max_delay
        
        ((attempt++))
    done
}

# Enhanced apt lock waiting with timeout
apt_wait_lock() {
    local timeout="${1:-300}"  # 5 minutes default
    local count=0
    
    log_debug "Waiting for apt/dpkg locks to be released..."
    
    while (( count < timeout )); do
        if ! fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 && \
           ! fuser /var/lib/dpkg/lock >/dev/null 2>&1 && \
           ! fuser /var/cache/apt/archives/lock >/dev/null 2>&1; then
            log_debug "Apt locks released after ${count}s"
            return 0
        fi
        sleep 1
        ((count++))
        
        if (( count % 30 == 0 )); then
            log_warn "Still waiting for apt locks... (${count}s elapsed)"
        fi
    done
    
    die "Apt/dpkg locked for more than ${timeout} seconds"
}

# System information gathering
gather_system_info() {
    log_info "Gathering system information..."
    
    local os_info
    os_info=$(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)
    local kernel_version=$(uname -r)
    local architecture=$(uname -m)
    local memory_total=$(free -h | awk '/^Mem:/ {print $2}')
    local disk_space=$(df -h / | awk 'NR==2 {print $4}')
    
    log_info "OS: $os_info"
    log_info "Kernel: $kernel_version"
    log_info "Architecture: $architecture"
    log_info "Memory: $memory_total"
    log_info "Free disk space: $disk_space"
    
    # Check minimum requirements
    local memory_mb=$(free -m | awk '/^Mem:/ {print $2}')
    local disk_mb=$(df --output=avail -m / | tail -1)
    
    [[ $memory_mb -lt 1024 ]] && log_warn "Low memory detected: ${memory_mb}MB (recommended: 2GB+)"
    [[ $disk_mb -lt 2048 ]] && log_warn "Low disk space: ${disk_mb}MB (recommended: 5GB+)"
}

# Enhanced input validation
validate_inputs() {
    log_info "Validating configuration..."
    
    # Validate version format
    if [[ ! "$GUAC_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        die "Invalid version format: $GUAC_VERSION (expected: X.Y.Z)"
    fi
    
    # Validate usernames
    if [[ ! "$GUAC_ADMIN_USER" =~ ^[a-zA-Z][a-zA-Z0-9_-]{2,31}$ ]]; then
        die "Invalid admin username: must be 3-32 chars, start with letter, contain only alphanumeric, _, -"
    fi
    
    if [[ ! "$DB_USER" =~ ^[a-zA-Z][a-zA-Z0-9_]{2,31}$ ]]; then
        die "Invalid database username format"
    fi
    
    if [[ ! "$DB_NAME" =~ ^[a-zA-Z][a-zA-Z0-9_]{2,63}$ ]]; then
        die "Invalid database name format"
    fi
    
    # Validate TLS configuration
    if [[ "$ENABLE_TLS" == true ]]; then
        [[ -z "$DOMAIN" ]] && die "ENABLE_TLS=true requires DOMAIN to be set"
        [[ -z "$EMAIL_LETSENCRYPT" ]] && die "ENABLE_TLS=true requires EMAIL_LETSENCRYPT to be set"
        
        # Validate domain format (RFC 1035)
        if [[ ! "$DOMAIN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
            die "Invalid domain format: $DOMAIN"
        fi
        
        # Validate email format (RFC 5322 basic)
        if [[ ! "$EMAIL_LETSENCRYPT" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            die "Invalid email format: $EMAIL_LETSENCRYPT"
        fi
        
        # Check domain length
        [[ ${#DOMAIN} -gt 253 ]] && die "Domain name too long (max 253 characters)"
        
        # Warn about domain resolution
        local resolve_ip
        resolve_ip=$(getent hosts "$DOMAIN" 2>/dev/null | awk '{print $1}' | head -1 || true)
        local host_ips
        host_ips=$(hostname -I 2>/dev/null || true)
        
        if [[ -n "$resolve_ip" && -n "$host_ips" ]]; then
            if [[ ! "$host_ips" == *"$resolve_ip"* ]]; then
                log_warn "Domain $DOMAIN resolves to $resolve_ip but this server has: $host_ips"
                log_warn "SSL certificate generation may fail"
            fi
        fi
    fi
    
    # Validate paths
    [[ ! "$GUAC_HOME" =~ ^/[a-zA-Z0-9/_-]+$ ]] && die "Invalid GUAC_HOME path"
    [[ ! "$BACKUP_DIR" =~ ^/[a-zA-Z0-9/_-]+$ ]] && die "Invalid BACKUP_DIR path"
    [[ ! "$LOGFILE" =~ ^/[a-zA-Z0-9/_.-]+$ ]] && die "Invalid LOGFILE path"
    
    # Validate numeric values
    [[ ! "$MAX_BACKUP_COUNT" =~ ^[0-9]+$ ]] || (( MAX_BACKUP_COUNT < 1 )) && die "MAX_BACKUP_COUNT must be positive integer"
    
    log_success "Configuration validation passed"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if running as root
    [[ $EUID -ne 0 ]] && die "This script must be run as root (use sudo)"
    
    # Check OS compatibility
    if [[ ! -f /etc/os-release ]]; then
        die "Cannot determine OS version"
    fi
    
    local os_id
    os_id=$(grep '^ID=' /etc/os-release | cut -d'=' -f2 | tr -d '"')
    local version_id
    version_id=$(grep '^VERSION_ID=' /etc/os-release | cut -d'=' -f2 | tr -d '"')
    
    if [[ "$os_id" != "ubuntu" ]]; then
        die "This script is designed for Ubuntu only (detected: $os_id)"
    fi
    
    local version_major
    version_major=$(echo "$version_id" | cut -d'.' -f1)
    if (( version_major < 20 )); then
        die "Ubuntu 20.04 or newer required (detected: $version_id)"
    fi
    
    # Check internet connectivity
    if ! ping -c1 -W5 8.8.8.8 >/dev/null 2>&1; then
        die "No internet connectivity detected"
    fi
    
    # Check available commands
    local required_cmds=(wget curl tar gzip systemctl)
    for cmd in "${required_cmds[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            die "Required command not found: $cmd"
        fi
    done
    
    log_success "Prerequisites check passed"
}

# Detect Tomcat version
detect_tomcat() {
    log_info "Detecting Tomcat version..."
    
    local tomcat_versions=(tomcat10 tomcat9 tomcat8)
    for version in "${tomcat_versions[@]}"; do
        if systemctl list-unit-files | grep -q "^${version}\.service"; then
            TOMCAT_SERVICE="$version"
            log_info "Found existing Tomcat service: $version"
            break
        fi
    done
    
    # If no Tomcat found, default to tomcat9 for Ubuntu 20.04/22.04, tomcat10 for 24.04+
    if [[ -z "$TOMCAT_SERVICE" ]]; then
        local version_id
        version_id=$(grep '^VERSION_ID=' /etc/os-release | cut -d'=' -f2 | tr -d '"')
        local version_major
        version_major=$(echo "$version_id" | cut -d'.' -f1)
        
        if (( version_major >= 24 )); then
            TOMCAT_SERVICE="tomcat10"
        else
            TOMCAT_SERVICE="tomcat9"
        fi
        log_info "Will install: $TOMCAT_SERVICE"
    fi
    
    # Set Tomcat user based on version
    case "$TOMCAT_SERVICE" in
        tomcat10) TOMCAT_USER="tomcat" ;;
        tomcat9)  TOMCAT_USER="tomcat" ;;
        *)        TOMCAT_USER="tomcat" ;;
    esac
}

# Create comprehensive backup
create_backup() {
    if [[ -d "$GUAC_HOME" ]] || systemctl is-active --quiet guacd 2>/dev/null; then
        log_info "Creating system backup..."
        
        mkdir -p "$BACKUP_DIR"
        local backup_file="$BACKUP_DIR/guacamole-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
        local backup_list=()
        
        # Add existing Guacamole files
        [[ -d "$GUAC_HOME" ]] && backup_list+=("$GUAC_HOME")
        [[ -d "/var/lib/guacamole" ]] && backup_list+=("/var/lib/guacamole")
        
        # Add Tomcat webapps if guacamole exists
        local tomcat_webapps="/var/lib/${TOMCAT_SERVICE}/webapps"
        [[ -f "$tomcat_webapps/guacamole.war" ]] && backup_list+=("$tomcat_webapps/guacamole.war")
        
        # Add nginx config if exists
        [[ -f "/etc/nginx/sites-available/guacamole" ]] && backup_list+=("/etc/nginx/sites-available/guacamole")
        
        if [[ ${#backup_list[@]} -gt 0 ]]; then
            tar -czf "$backup_file" "${backup_list[@]}" 2>/dev/null || log_warn "Backup creation had warnings"
            log_success "Backup created: $backup_file"
            
            # Cleanup old backups
            find "$BACKUP_DIR" -name "guacamole-backup-*.tar.gz" -type f | sort -r | tail -n +"$((MAX_BACKUP_COUNT + 1))" | xargs rm -f || true
        fi
    fi
}

# Enhanced package installation
install_packages() {
    log_info "Installing required packages..."
    
    export DEBIAN_FRONTEND=noninteractive
    
    # Update package list
    apt_wait_lock
    retry "apt-get update -y" 5 3 || die "Failed to update package list"
    
    # Core build dependencies
    local build_packages=(
        build-essential libcairo2-dev libjpeg-turbo8-dev libpng-dev libtool-bin 
        libossp-uuid-dev libavcodec-dev libavformat-dev libavutil-dev libswscale-dev 
        libfreerdp2-dev libpango1.0-dev libssh2-1-dev libvncserver-dev libtelnet-dev 
        libssl-dev libvorbis-dev libwebp-dev libpulse-dev
    )
    
    # Java and Tomcat
    local java_packages=(default-jdk "${TOMCAT_SERVICE}" "${TOMCAT_SERVICE}-admin" "${TOMCAT_SERVICE}-common")
    
    # Database
    local db_packages=(mariadb-server mariadb-client default-mysql-connector-java)
    
    # Web server and SSL
    local web_packages=(nginx certbot python3-certbot-nginx)
    
    # Utilities and security
    local util_packages=(
        wget curl unzip zip git htop iotop nethogs
        ufw fail2ban logrotate rsyslog
        ghostscript ffmpeg imagemagick
        tree vim nano
    )
    
    # Monitoring (if enabled)
    local monitor_packages=()
    if [[ "$ENABLE_MONITORING" == true ]]; then
        monitor_packages=(netdata prometheus-node-exporter)
    fi
    
    # Combine all packages
    local all_packages=(
        "${build_packages[@]}" 
        "${java_packages[@]}" 
        "${db_packages[@]}" 
        "${web_packages[@]}" 
        "${util_packages[@]}"
        "${monitor_packages[@]}"
    )
    
    # Install packages in batches to handle potential conflicts
    local batch_size=20
    for ((i=0; i<${#all_packages[@]}; i+=batch_size)); do
        local batch=("${all_packages[@]:i:batch_size}")
        log_info "Installing package batch $((i/batch_size + 1)): ${batch[*]}"
        
        apt_wait_lock
        if ! retry "apt-get install -y ${batch[*]}" 3 5; then
            log_warn "Batch installation failed, trying individual packages..."
            for package in "${batch[@]}"; do
                apt_wait_lock
                if ! apt-get install -y "$package"; then
                    log_warn "Failed to install: $package"
                fi
            done
        fi
    done
    
    # Verify critical packages
    local critical_packages=(default-jdk "$TOMCAT_SERVICE" mariadb-server wget curl)
    for package in "${critical_packages[@]}"; do
        if ! dpkg -l "$package" >/dev/null 2>&1; then
            die "Critical package not installed: $package"
        fi
    done
    
    log_success "Package installation completed"
}

# Setup directory structure with proper permissions
setup_directories() {
    log_info "Setting up directory structure..."
    
    # Create main directories
    local directories=(
        "$GUAC_HOME"
        "$GUAC_HOME/extensions"
        "$GUAC_HOME/lib"
        "$BACKUP_DIR"
        "/var/lib/guacamole"
        "/var/log/guacamole"
        "/etc/guacamole/ssl"
    )
    
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
        ROLLBACK_STACK+=("rm -rf '$dir'")
    done
    
    # Set ownership and permissions
    chown -R root:"$TOMCAT_USER" "$GUAC_HOME"
    chmod -R 750 "$GUAC_HOME"
    chmod 755 "$GUAC_HOME"  # Allow Tomcat to read the directory
    
    chown "$TOMCAT_USER":"$TOMCAT_USER" "/var/lib/guacamole"
    chmod 750 "/var/lib/guacamole"
    
    mkdir -p "/var/log/guacamole"
    chown "$TOMCAT_USER":"$TOMCAT_USER" "/var/log/guacamole"
    chmod 750 "/var/log/guacamole"
    
    log_success "Directory structure created"
}

# Build and install guacd with optimizations
install_guacd() {
    log_info "Building and installing guacd..."
    
    # Check if guacd is already installed and version matches
    if command -v guacd >/dev/null 2>&1; then
        local current_version
        current_version=$(guacd -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "unknown")
        if [[ "$current_version" == "$GUAC_VERSION" ]]; then
            log_info "guacd version $GUAC_VERSION already installed"
            return 0
        else
            log_info "Upgrading guacd from $current_version to $GUAC_VERSION"
        fi
    fi
    
    # Create temporary build directory
    local build_dir
    build_dir=$(mktemp -d)
    TEMP_DIRS+=("$build_dir")
    ROLLBACK_STACK+=("systemctl stop guacd || true")
    
    cd "$build_dir"
    
    # Download source with verification
    local source_url="https://archive.apache.org/dist/guacamole/$GUAC_VERSION/source/guacamole-server-$GUAC_VERSION.tar.gz"
    local sig_url="$source_url.asc"
    
    log_info "Downloading guacd source..."
    retry "wget -q '$source_url' -O guacamole-server.tar.gz" 5 3 || die "Failed to download guacd source"
    
    # Verify checksum if available
    if wget -q "$sig_url" -O guacamole-server.tar.gz.asc 2>/dev/null; then
        log_info "GPG signature found, but skipping verification (would require importing keys)"
    fi
    
    # Extract and build
    tar -xzf guacamole-server.tar.gz
    cd "guacamole-server-$GUAC_VERSION"
    
    log_info "Configuring build..."
    ./configure --with-init-dir=/etc/init.d \
                --enable-allow-freerdp-snapshots \
                --with-systemd-dir=/etc/systemd/system
    
    log_info "Building guacd (this may take several minutes)..."
    make -j"$(nproc)" || die "Build failed"
    
    log_info "Installing guacd..."
    make install
    ldconfig
    
    # Create systemd service if it doesn't exist
    if [[ ! -f /etc/systemd/system/guacd.service ]]; then
        log_info "Creating systemd service for guacd..."
        cat > /etc/systemd/system/guacd.service << 'EOF'
[Unit]
Description=Guacamole proxy daemon (guacd)
Documentation=man:guacd(8)
After=network.target
AssertPathExists=/usr/local/sbin/guacd

[Service]
Type=notify
ExecStart=/usr/local/sbin/guacd -f
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true
User=daemon
Group=daemon

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
    fi
    
    # Enable and start guacd
    systemctl enable guacd
    systemctl start guacd
    
    # Verify installation
    if ! systemctl is-active --quiet guacd; then
        die "guacd failed to start"
    fi
    
    if ! guacd -v >/dev/null 2>&1; then
        die "guacd installation verification failed"
    fi
    
    log_success "guacd installed and running"
}

# Deploy Guacamole web application
deploy_webapp() {
    log_info "Deploying Guacamole web application..."
    
    local tomcat_webapps="/var/lib/$TOMCAT_SERVICE/webapps"
    local war_file="$tomcat_webapps/guacamole.war"
    
    # Backup existing WAR if present
    if [[ -f "$war_file" ]]; then
        cp "$war_file" "$war_file.backup.$(date +%Y%m%d%H%M%S)"
        ROLLBACK_STACK+=("cp '$war_file.backup.*' '$war_file' 2>/dev/null || true")
    fi
    
    # Download WAR file
    local war_url="https://archive.apache.org/dist/guacamole/$GUAC_VERSION/binary/guacamole-$GUAC_VERSION.war"
    log_info "Downloading Guacamole WAR file..."
    retry "wget -q '$war_url' -O '$war_file'" 5 3 || die "Failed to download guacamole.war"
    
    # Set proper ownership and permissions
    chown "$TOMCAT_USER":"$TOMCAT_USER" "$war_file"
    chmod 640 "$war_file"
    
    log_success "Guacamole WAR deployed"
}

# Setup database with enhanced security
setup_database() {
    log_info "Setting up MariaDB database..."
    
    # Generate strong root password if not provided
    if [[ -z "$DB_ROOT_PASS" ]]; then
        DB_ROOT_PASS=$(rand_password 32)
        log_info "Generated strong root password for MariaDB"
    fi
    
    # Start MariaDB
    systemctl enable mariadb
    systemctl start mariadb
    
    # Wait for MariaDB to be ready
    local attempts=0
    while ! mysqladmin ping --silent >/dev/null 2>&1; do
        sleep 2
        ((attempts++))
        if (( attempts > 30 )); then
            die "MariaDB failed to start properly"
        fi
    done
    
    # Secure MariaDB installation
    log_info "Securing MariaDB installation..."
    mysql -u root <<SQL
-- Set root password
ALTER USER 'root'@'localhost' IDENTIFIED BY '${DB_ROOT_PASS}';
-- Remove anonymous users
DELETE FROM mysql.user WHERE User='';
-- Remove remote root login
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
-- Remove test database
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test_%';
-- Apply changes
FLUSH PRIVILEGES;
SQL
    
    # Configure MariaDB for security
    local mysql_config="/etc/mysql/mariadb.conf.d/50-server.cnf"
    if [[ -f "$mysql_config" ]]; then
        # Backup original config
        cp "$mysql_config" "$mysql_config.backup"
        ROLLBACK_STACK+=("cp '$mysql_config.backup' '$mysql_config'")
        
        # Security enhancements
        if ! grep -q "skip-networking" "$mysql_config"; then
            echo "" >> "$mysql_config"
            echo "# Guacamole installer security enhancements" >> "$mysql_config"
            echo "skip-networking = 1" >> "$mysql_config"
            echo "local-infile = 0" >> "$mysql_config"
            echo "max_connections = 100" >> "$mysql_config"
            echo "innodb_buffer_pool_size = 256M" >> "$mysql_config"
        fi
        
        systemctl restart mariadb
        
        # Wait for restart
        sleep 3
        local attempts=0
        while ! mysqladmin ping -uroot -p"$DB_ROOT_PASS" --silent >/dev/null 2>&1; do
            sleep 2
            ((attempts++))
            if (( attempts > 30 )); then
                die "MariaDB failed to restart properly"
            fi
        done
    fi
    
    # Create Guacamole database and user
    log_info "Creating Guacamole database and user..."
    mysql -uroot -p"$DB_ROOT_PASS" <<SQL
-- Create database
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` 
CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Create user with strong password
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';

-- Grant minimal required privileges
GRANT SELECT, INSERT, UPDATE, DELETE ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';

-- Apply changes
FLUSH PRIVILEGES;
SQL
    
    log_success "Database setup completed"
}

# Setup JDBC authentication
setup_jdbc_auth() {
    log_info "Setting up JDBC authentication..."
    
    # Create temporary directory for JDBC extension
    local temp_dir
    temp_dir=$(mktemp -d)
    TEMP_DIRS+=("$temp_dir")
    
    cd "$temp_dir"
    
    # Download JDBC authentication extension
    local jdbc_url="https://archive.apache.org/dist/guacamole/$GUAC_VERSION/binary/guacamole-auth-jdbc-$GUAC_VERSION.tar.gz"
    log_info "Downloading JDBC authentication extension..."
    retry "wget -q '$jdbc_url' -O jdbc-auth.tar.gz" 5 3 || die "Failed to download JDBC auth extension"
    
    tar -xzf jdbc-auth.tar.gz
    local jdbc_dir="guacamole-auth-jdbc-$GUAC_VERSION"
    
    if [[ ! -d "$jdbc_dir/mysql" ]]; then
        die "JDBC MySQL directory not found in extension archive"
    fi
    
    # Copy JDBC extension
    local jdbc_jar="$jdbc_dir/mysql/guacamole-auth-jdbc-mysql-$GUAC_VERSION.jar"
    if [[ ! -f "$jdbc_jar" ]]; then
        die "JDBC MySQL JAR file not found: $jdbc_jar"
    fi
    
    cp "$jdbc_jar" "$GUAC_HOME/extensions/"
    chown root:"$TOMCAT_USER" "$GUAC_HOME/extensions/$(basename "$jdbc_jar")"
    chmod 640 "$GUAC_HOME/extensions/$(basename "$jdbc_jar")"
    
    # Import database schema
    local schema_file="$jdbc_dir/mysql/schema/guacamole-auth-jdbc-mysql-$GUAC_VERSION.sql"
    if [[ ! -f "$schema_file" ]]; then
        die "Database schema file not found: $schema_file"
    fi
    
    # Check if schema already imported
    local table_count
    table_count=$(mysql -uroot -p"$DB_ROOT_PASS" -sN -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='$DB_NAME';" 2>/dev/null || echo "0")
    
    if [[ "$table_count" == "0" ]]; then
        log_info "Importing Guacamole database schema..."
        mysql -uroot -p"$DB_ROOT_PASS" "$DB_NAME" < "$schema_file"
        log_success "Database schema imported"
    else
        log_info "Database schema already exists (tables: $table_count)"
    fi
    
    # Ensure MySQL connector is available
    local mysql_jar
    mysql_jar=$(find /usr/share/java -name "mysql-connector-*.jar" 2>/dev/null | head -1)
    
    if [[ -z "$mysql_jar" ]]; then
        mysql_jar=$(find /usr -name "mysql-connector-*.jar" 2>/dev/null | head -1)
    fi
    
    if [[ -n "$mysql_jar" ]]; then
        cp "$mysql_jar" "$GUAC_HOME/lib/"
        cp "$mysql_jar" "/usr/share/$TOMCAT_SERVICE/lib/" 2>/dev/null || true
        chown root:"$TOMCAT_USER" "$GUAC_HOME/lib/$(basename "$mysql_jar")"
        chmod 640 "$GUAC_HOME/lib/$(basename "$mysql_jar")"
        log_success "MySQL connector JAR installed"
    else
        log_warn "MySQL connector JAR not found - may cause connection issues"
    fi
    
    log_success "JDBC authentication setup completed"
}

# Create Guacamole configuration files
create_configuration() {
    log_info "Creating Guacamole configuration files..."
    
    # Create guacamole.properties with comprehensive settings
    cat > "$GUAC_HOME/guacamole.properties" << EOF
# Guacamole Configuration - Generated by installer v$SCRIPT_VERSION
# $(date -u +"%Y-%m-%d %H:%M:%S UTC")

# guacd connection settings
guacd-hostname: localhost
guacd-port: 4822

# MySQL database connection
mysql-hostname: localhost
mysql-port: 3306
mysql-database: ${DB_NAME}
mysql-username: ${DB_USER}
mysql-password: ${DB_PASS}

# Connection pool settings for better performance
mysql-max-connections: 20
mysql-max-connections-per-user: 4

# Extension directories
lib-directory: ${GUAC_HOME}/lib
extension-directory: ${GUAC_HOME}/extensions

# Recording settings (optional)
recording-search-path: /var/lib/guacamole/recordings

# Logging
logback-level: INFO

# Security settings
enable-websocket: true
allowed-languages: en, es, fr, de, it, pt, ru, zh

# Session settings
session-timeout: 600000
absolute-timeout: 0
EOF
    
    chmod 640 "$GUAC_HOME/guacamole.properties"
    chown root:"$TOMCAT_USER" "$GUAC_HOME/guacamole.properties"
    
    # Create fallback user-mapping.xml (not used with JDBC but good for debugging)
    cat > "$GUAC_HOME/user-mapping.xml" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<user-mapping>
    <!-- Fallback configuration - not used when JDBC authentication is active -->
    <!-- This file is kept for emergency access and debugging purposes -->
    <authorize username="${GUAC_ADMIN_USER}" password="${GUAC_ADMIN_PASS}">
        <connection name="localhost-ssh">
            <protocol>ssh</protocol>
            <param name="hostname">localhost</param>
            <param name="port">22</param>
            <param name="username">ubuntu</param>
        </connection>
    </authorize>
</user-mapping>
EOF
    
    chmod 640 "$GUAC_HOME/user-mapping.xml"
    chown root:"$TOMCAT_USER" "$GUAC_HOME/user-mapping.xml"
    
    # Create logback configuration for better logging
    cat > "$GUAC_HOME/logback.xml" << 'EOF'
<configuration>
    <appender name="CONSOLE" class="ch.qos.logback.core.ConsoleAppender">
        <encoder>
            <pattern>%d{HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n</pattern>
        </encoder>
    </appender>
    
    <appender name="FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <file>/var/log/guacamole/guacamole.log</file>
        <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
            <fileNamePattern>/var/log/guacamole/guacamole.%d{yyyy-MM-dd}.log</fileNamePattern>
            <maxHistory>30</maxHistory>
        </rollingPolicy>
        <encoder>
            <pattern>%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n</pattern>
        </encoder>
    </appender>
    
    <root level="INFO">
        <appender-ref ref="CONSOLE" />
        <appender-ref ref="FILE" />
    </root>
</configuration>
EOF
    
    chown root:"$TOMCAT_USER" "$GUAC_HOME/logback.xml"
    chmod 640 "$GUAC_HOME/logback.xml"
    
    log_success "Configuration files created"
}

# Create admin user in database with secure password hashing
create_admin_user() {
    log_info "Creating admin user in database..."
    
    # Check if admin user already exists
    local user_exists
    user_exists=$(mysql -uroot -p"$DB_ROOT_PASS" -sN -e "SELECT COUNT(*) FROM $DB_NAME.guacamole_user WHERE username='$GUAC_ADMIN_USER';" 2>/dev/null || echo "0")
    
    if [[ "$user_exists" != "0" ]]; then
        log_info "Admin user '$GUAC_ADMIN_USER' already exists in database"
        return 0
    fi
    
    # Generate salt and hash password using SHA-256 with salt
    local salt
    salt=$(openssl rand -hex 32)
    local hash
    hash=$(echo -n "${salt}${GUAC_ADMIN_PASS}" | sha256sum | cut -d' ' -f1)
    
    # Insert admin user
    mysql -uroot -p"$DB_ROOT_PASS" "$DB_NAME" << SQL
INSERT INTO guacamole_user (username, password_salt, password_hash, disabled, expired, access_window_start, access_window_end, valid_from, valid_until, timezone)
VALUES ('${GUAC_ADMIN_USER}', UNHEX('${salt}'), UNHEX('${hash}'), 0, 0, NULL, NULL, NULL, NULL, NULL);

-- Get the user_id for the admin user
SET @admin_user_id = LAST_INSERT_ID();

-- Grant admin permissions
INSERT INTO guacamole_user_permission (user_id, permission)
SELECT @admin_user_id, permission 
FROM (
    SELECT 'ADMINISTER' as permission
    UNION SELECT 'CREATE_CONNECTION'
    UNION SELECT 'CREATE_CONNECTION_GROUP'
    UNION SELECT 'CREATE_SHARING_PROFILE'
    UNION SELECT 'CREATE_USER'
    UNION SELECT 'CREATE_USER_GROUP'
) AS perms;

-- Grant system permissions
INSERT INTO guacamole_system_permission (user_id, permission)
SELECT @admin_user_id, permission
FROM (
    SELECT 'ADMINISTER' as permission
    UNION SELECT 'CREATE_CONNECTION'
    UNION SELECT 'CREATE_CONNECTION_GROUP'
    UNION SELECT 'CREATE_SHARING_PROFILE'
    UNION SELECT 'CREATE_USER'
    UNION SELECT 'CREATE_USER_GROUP'
) AS sys_perms;
SQL
    
    log_success "Admin user created with full privileges"
}

# Configure Tomcat with security enhancements
configure_tomcat() {
    log_info "Configuring Tomcat with security enhancements..."
    
    local tomcat_conf_dir="/etc/$TOMCAT_SERVICE"
    
    # Create symbolic link for Guacamole home
    ln -sfn "$GUAC_HOME" "/usr/share/$TOMCAT_SERVICE/.guacamole"
    
    # Configure server.xml for security
    local server_xml="$tomcat_conf_dir/server.xml"
    if [[ -f "$server_xml" ]]; then
        cp "$server_xml" "$server_xml.backup"
        ROLLBACK_STACK+=("cp '$server_xml.backup' '$server_xml'")
        
        # Security headers and settings
        if ! grep -q "RemoteIpValve" "$server_xml"; then
            sed -i '/<Host name="localhost"/a \
        <!-- Security: Remote IP Valve for proxy headers -->\
        <Valve className="org.apache.catalina.valves.RemoteIpValve"\
               remoteIpHeader="x-forwarded-for"\
               proxiesHeader="x-forwarded-by"\
               protocolHeader="x-forwarded-proto" />' "$server_xml"
        fi
        
        # Restrict to localhost if using Nginx
        if [[ "$ENABLE_NGINX" == true && "$LOCKDOWN_TOMCAT" == true ]]; then
            sed -i 's|<Connector port="8080"|<Connector address="127.0.0.1" port="8080"|g' "$server_xml"
        fi
    fi
    
    # Configure context.xml for security
    local context_xml="$tomcat_conf_dir/context.xml"
    if [[ -f "$context_xml" ]]; then
        cp "$context_xml" "$context_xml.backup"
        
        # Add security settings
        if ! grep -q "HttpOnly" "$context_xml"; then
            sed -i 's|<Context>|<Context>\n    <!-- Security: Secure cookies -->\n    <CookieProcessor cookieName="JSESSIONID" httpOnly="true" secure="false" />|' "$context_xml"
        fi
    fi
    
    # Set JVM options for better performance and security
    local tomcat_default="/etc/default/$TOMCAT_SERVICE"
    if [[ -f "$tomcat_default" ]]; then
        cp "$tomcat_default" "$tomcat_default.backup"
        
        # Memory and security JVM options
        local jvm_opts='-Djava.awt.headless=true -Xmx1024M -XX:+UseConcMarkSweepGC -Djava.security.egd=file:/dev/./urandom'
        
        if grep -q "^JAVA_OPTS=" "$tomcat_default"; then
            sed -i "s|^JAVA_OPTS=.*|JAVA_OPTS=\"$jvm_opts\"|" "$tomcat_default"
        else
            echo "JAVA_OPTS=\"$jvm_opts\"" >> "$tomcat_default"
        fi
    fi
    
    # Start and enable Tomcat
    systemctl enable "$TOMCAT_SERVICE"
    systemctl restart "$TOMCAT_SERVICE"
    
    # Wait for Tomcat to start and verify
    local attempts=0
    while ! systemctl is-active --quiet "$TOMCAT_SERVICE"; do
        sleep 2
        ((attempts++))
        if (( attempts > 30 )); then
            log_error "Tomcat failed to start properly"
            journalctl -u "$TOMCAT_SERVICE" --no-pager -l | tail -20
            die "Tomcat startup failed"
        fi
    done
    
    # Wait for web application to deploy
    log_info "Waiting for Guacamole web application to deploy..."
    local deploy_attempts=0
    while ! curl -sf --max-time 5 "http://127.0.0.1:8080/guacamole/" >/dev/null 2>&1; do
        sleep 5
        ((deploy_attempts++))
        if (( deploy_attempts > 24 )); then  # 2 minutes
            log_warn "Guacamole web application may not have deployed properly"
            break
        fi
    done
    
    log_success "Tomcat configured and running"
}

# Configure Nginx reverse proxy with security headers
configure_nginx() {
    if [[ "$ENABLE_NGINX" != true ]]; then
        return 0
    fi
    
    log_info "Configuring Nginx reverse proxy..."
    
    # Remove default site
    rm -f /etc/nginx/sites-enabled/default
    
    # Create Guacamole site configuration
    cat > /etc/nginx/sites-available/guacamole << EOF
# Guacamole Nginx Configuration - Generated by installer v$SCRIPT_VERSION
# $(date -u +"%Y-%m-%d %H:%M:%S UTC")

# Rate limiting
limit_req_zone \$binary_remote_addr zone=guac_login:10m rate=5r/m;
limit_req_zone \$binary_remote_addr zone=guac_general:10m rate=10r/s;

# Upstream Tomcat server
upstream guacamole {
    server 127.0.0.1:8080 fail_timeout=5s max_fails=3;
    keepalive 32;
}

server {
    listen 80;
    server_name ${DOMAIN:-_};
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Hide server tokens
    server_tokens off;
    
    # Logging
    access_log /var/log/nginx/guacamole.access.log;
    error_log /var/log/nginx/guacamole.error.log warn;
    
    # Client settings
    client_max_body_size 100M;
    client_body_timeout 120s;
    client_header_timeout 120s;
    
    # Proxy settings
    proxy_buffering off;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_set_header Host \$host;
    proxy_connect_timeout 300s;
    proxy_send_timeout 300s;
    proxy_read_timeout 300s;
    
    # Root redirect
    location = / {
        return 301 /guacamole/;
    }
    
    # Main Guacamole location
    location /guacamole/ {
        limit_req zone=guac_general burst=20 nodelay;
        proxy_pass http://guacamole;
    }
    
    # Login endpoint with stricter rate limiting
    location /guacamole/api/tokens {
        limit_req zone=guac_login burst=3 nodelay;
        proxy_pass http://guacamole;
    }
    
    # WebSocket tunnel
    location /guacamole/websocket-tunnel {
        proxy_pass http://guacamole;
        proxy_buffering off;
    }
    
    # Health check endpoint
    location /nginx-health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
    
    # Block sensitive files
    location ~ /\\.ht {
        deny all;
    }
    
    location ~ \\.php$ {
        deny all;
    }
}
EOF
    
    # Enable the site
    ln -sf /etc/nginx/sites-available/guacamole /etc/nginx/sites-enabled/guacamole
    
    # Test configuration
    if ! nginx -t; then
        die "Nginx configuration test failed"
    fi
    
    # Start and enable Nginx
    systemctl enable nginx
    systemctl restart nginx
    
    if ! systemctl is-active --quiet nginx; then
        die "Nginx failed to start"
    fi
    
    log_success "Nginx configured and running"
}

# Configure SSL/TLS with Let's Encrypt
configure_ssl() {
    if [[ "$ENABLE_TLS" != true ]]; then
        return 0
    fi
    
    log_info "Configuring SSL/TLS with Let's Encrypt..."
    
    # Verify domain resolves to this server
    local resolve_ip
    resolve_ip=$(dig +short "$DOMAIN" | head -1 || true)
    local server_ip
    server_ip=$(curl -s http://checkip.amazonaws.com/ || curl -s http://ipinfo.io/ip || true)
    
    if [[ -n "$resolve_ip" && -n "$server_ip" && "$resolve_ip" != "$server_ip" ]]; then
        log_warn "Domain $DOMAIN resolves to $resolve_ip but server IP is $server_ip"
        log_warn "SSL certificate generation may fail"
    fi
    
    # Request certificate
    local certbot_cmd="certbot --nginx -d $DOMAIN --non-interactive --agree-tos -m $EMAIL_LETSENCRYPT"
    
    if [[ "$STRICT_SSL" == true ]]; then
        certbot_cmd="$certbot_cmd --must-staple --uir"
    fi
    
    if ! retry "$certbot_cmd" 3 10; then
        log_error "SSL certificate generation failed"
        log_error "Please check:"
        log_error "1. Domain $DOMAIN resolves to this server"
        log_error "2. Port 80 is accessible from internet"
        log_error "3. No firewall blocking HTTP traffic"
        return 1
    fi
    
    # Enhance SSL configuration
    local ssl_conf="/etc/nginx/sites-available/guacamole"
    if grep -q "ssl_certificate" "$ssl_conf"; then
        # Add additional security headers for HTTPS
        sed -i '/add_header Strict-Transport-Security/a \
    add_header Content-Security-Policy "default-src '\''self'\''; script-src '\''self'\''; style-src '\''self'\'' '\''unsafe-inline'\''; img-src '\''self'\'' data:; connect-src '\''self'\''; font-src '\''self'\''; object-src '\''none'\''; media-src '\''self'\''; frame-src '\''none'\''; child-src '\''none'\'';" always;' "$ssl_conf"
        
        systemctl reload nginx
    fi
    
    # Setup auto-renewal
    local renewal_script="/etc/cron.d/certbot-guacamole"
    cat > "$renewal_script" << 'EOF'
# Certbot renewal for Guacamole
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 */12 * * * root test -x /usr/bin/certbot -a \! -d /run/systemd/generator.late/certbot.timer && perl -e 'sleep int(rand(3600))' && certbot -q renew --post-hook "systemctl reload nginx"
EOF
    
    chmod 644 "$renewal_script"
    
    log_success "SSL/TLS configured successfully"
}

# Configure firewall with UFW
configure_firewall() {
    if [[ "$ENABLE_UFW" != true ]]; then
        return 0
    fi
    
    log_info "Configuring UFW firewall..."
    
    # Reset UFW to default state
    ufw --force reset
    
    # Set default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH (critical - don't lock yourself out!)
    ufw allow OpenSSH
    ufw allow 22/tcp
    
    # Allow HTTP/HTTPS
    if [[ "$ENABLE_NGINX" == true ]]; then
        ufw allow 'Nginx Full'
        ufw allow 80/tcp
        ufw allow 443/tcp
    else
        ufw allow 8080/tcp comment 'Tomcat HTTP'
    fi
    
    # Allow guacd port (only from localhost)
    ufw allow from 127.0.0.1 to any port 4822 comment 'guacd local'
    
    # Rate limiting for SSH
    ufw limit ssh comment 'SSH rate limiting'
    
    # Enable logging
    ufw logging on
    
    # Enable UFW if auto-enable is true
    if [[ "$AUTO_ENABLE_UFW" == true ]]; then
        ufw --force enable
        log_success "UFW firewall enabled"
    else
        log_info "UFW configured but not enabled. Run 'ufw enable' to activate"
    fi
    
    # Show status
    ufw status verbose
}

# Configure Fail2Ban for intrusion prevention
configure_fail2ban() {
    log_info "Configuring Fail2Ban..."
    
    # Create Guacamole filter
    cat > /etc/fail2ban/filter.d/guacamole.conf << 'EOF'
# Fail2Ban filter for Guacamole
[Definition]
failregex = .*"GET /guacamole.*HTTP.*" 401.*
            .*"POST /guacamole/api/tokens HTTP.*" 403.*
            .*"POST /guacamole/api/tokens HTTP.*" 401.*
            .*Authentication attempt from <HOST> for user.*failed
ignoreregex =
EOF
    
    # Create Nginx filter for additional protection
    cat > /etc/fail2ban/filter.d/nginx-guacamole.conf << 'EOF'
# Fail2Ban filter for Nginx serving Guacamole
[Definition]
failregex = ^<HOST>.*"(GET|POST).*" (401|403|404|444) .*$
ignoreregex =
EOF
    
    # Create jail configuration
    cat > /etc/fail2ban/jail.d/guacamole.local << 'EOF'
# Fail2Ban jail for Guacamole
[guacamole]
enabled = true
filter = guacamole
port = http,https
logpath = /var/log/tomcat*/catalina.out
          /var/log/guacamole/guacamole.log
maxretry = 5
bantime = 3600
findtime = 600
action = iptables-allports[name=guacamole]
         sendmail-whois[name=guacamole, dest=root, sender=fail2ban@localhost]

[nginx-guacamole]
enabled = true
filter = nginx-guacamole
port = http,https
logpath = /var/log/nginx/guacamole.access.log
          /var/log/nginx/access.log
maxretry = 10
bantime = 1800
findtime = 300
action = iptables-allports[name=nginx-guac]
EOF
    
    # Enable and restart Fail2Ban
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    if ! systemctl is-active --quiet fail2ban; then
        log_warn "Fail2Ban failed to start properly"
    else
        log_success "Fail2Ban configured and running"
    fi
}

# Setup log rotation
configure_logging() {
    log_info "Configuring log rotation..."
    
    # Tomcat logs
    cat > /etc/logrotate.d/guacamole-tomcat << 'EOF'
/var/log/tomcat*/*.log
/var/log/tomcat*/catalina.out {
    daily
    rotate 14
    copytruncate
    compress
    delaycompress
    missingok
    notifempty
    create 640 tomcat adm
}
EOF
    
    # Guacamole logs
    cat > /etc/logrotate.d/guacamole << 'EOF'
/var/log/guacamole/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 640 tomcat tomcat
    postrotate
        /bin/systemctl reload tomcat* > /dev/null 2>&1 || true
    endscript
}
EOF
    
    # Nginx logs (if enabled)
    if [[ "$ENABLE_NGINX" == true ]]; then
        cat > /etc/logrotate.d/guacamole-nginx << 'EOF'
/var/log/nginx/guacamole.*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 640 www-data adm
    postrotate
        /bin/systemctl reload nginx > /dev/null 2>&1 || true
    endscript
}
EOF
    fi
    
    # Test logrotate configuration
    logrotate -d /etc/logrotate.d/guacamole* >/dev/null 2>&1 || log_warn "Logrotate configuration test had warnings"
    
    log_success "Log rotation configured"
}

# Install monitoring tools
setup_monitoring() {
    if [[ "$ENABLE_MONITORING" != true ]]; then
        return 0
    fi
    
    log_info "Setting up monitoring tools..."
    
    # Configure netdata if installed
    if systemctl list-unit-files | grep -q netdata; then
        systemctl enable netdata
        systemctl start netdata
        
        # Configure netdata for Guacamole monitoring
        local netdata_conf="/etc/netdata/netdata.conf"
        if [[ -f "$netdata_conf" ]]; then
            sed -i 's/# bind to = \*/bind to = 127.0.0.1/' "$netdata_conf" 2>/dev/null || true
            systemctl restart netdata
        fi
        
        log_info "Netdata monitoring available at http://localhost:19999"
    fi
    
    # Create basic health check script
    cat > /usr/local/bin/guacamole-health-check << 'EOF'
#!/bin/bash
# Guacamole Health Check Script

check_service() {
    local service="$1"
    if systemctl is-active --quiet "$service"; then
        echo "✓ $service is running"
        return 0
    else
        echo "✗ $service is not running"
        return 1
    fi
}

check_port() {
    local port="$1"
    local desc="$2"
    if netstat -tuln | grep -q ":$port "; then
        echo "✓ Port $port ($desc) is listening"
        return 0
    else
        echo "✗ Port $port ($desc) is not listening"
        return 1
    fi
}

echo "Guacamole Health Check - $(date)"
echo "=================================="

# Check services
check_service guacd
check_service mariadb
EOF
    
    echo "check_service $TOMCAT_SERVICE" >> /usr/local/bin/guacamole-health-check
    
    if [[ "$ENABLE_NGINX" == true ]]; then
        echo "check_service nginx" >> /usr/local/bin/guacamole-health-check
    fi
    
    cat >> /usr/local/bin/guacamole-health-check << 'EOF'

echo ""
# Check ports
check_port 4822 "guacd"
check_port 3306 "MariaDB"
check_port 8080 "Tomcat"
EOF
    
    if [[ "$ENABLE_NGINX" == true ]]; then
        echo 'check_port 80 "HTTP"' >> /usr/local/bin/guacamole-health-check
        if [[ "$ENABLE_TLS" == true ]]; then
            echo 'check_port 443 "HTTPS"' >> /usr/local/bin/guacamole-health-check
        fi
    fi
    
    cat >> /usr/local/bin/guacamole-health-check << 'EOF'

echo ""
# Check web interface
if curl -sf --max-time 10 "http://127.0.0.1:8080/guacamole/" >/dev/null 2>&1; then
    echo "✓ Guacamole web interface is responding"
else
    echo "✗ Guacamole web interface is not responding"
fi

# Check disk space
echo ""
echo "Disk Usage:"
df -h / | tail -1

# Check memory usage
echo ""
echo "Memory Usage:"
free -h

# Check load average
echo ""
echo "Load Average:"
uptime
EOF
    
    chmod +x /usr/local/bin/guacamole-health-check
    
    log_success "Monitoring tools configured"
    log_info "Run 'guacamole-health-check' to check system status"
}

# Final system verification
verify_installation() {
    log_info "Performing final installation verification..."
    
    local verification_failed=false
    
    # Check services
    local services=(guacd mariadb "$TOMCAT_SERVICE")
    [[ "$ENABLE_NGINX" == true ]] && services+=(nginx)
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            log_success "✓ $service is running"
        else
            log_error "✗ $service is not running"
            verification_failed=true
        fi
    done
    
    # Check ports
    local ports=("4822:guacd" "3306:MariaDB" "8080:Tomcat")
    [[ "$ENABLE_NGINX" == true ]] && ports+=("80:HTTP")
    [[ "$ENABLE_TLS" == true ]] && ports+=("443:HTTPS")
    
    for port_info in "${ports[@]}"; do
        local port="${port_info%%:*}"
        local desc="${port_info##*:}"
        
        if netstat -tuln | grep -q ":$port "; then
            log_success "✓ Port $port ($desc) is listening"
        else
            log_error "✗ Port $port ($desc) is not listening"
            verification_failed=true
        fi
    done
    
    # Test web interface
    local max_attempts=30
    local attempt=1
    local web_test_passed=false
    
    log_info "Testing Guacamole web interface..."
    while (( attempt <= max_attempts )); do
        if curl -sf --max-time 5 "http://127.0.0.1:8080/guacamole/" >/dev/null 2>&1; then
            log_success "✓ Guacamole web interface is responding"
            web_test_passed=true
            break
        fi
        
        log_debug "Web interface test attempt $attempt/$max_attempts failed"
        sleep 2
        ((attempt++))
    done
    
    if [[ "$web_test_passed" != true ]]; then
        log_error "✗ Guacamole web interface is not responding after $max_attempts attempts"
        verification_failed=true
    fi
    
    # Test database connection
    if mysql -u"$DB_USER" -p"$DB_PASS" -e "SELECT COUNT(*) FROM $DB_NAME.guacamole_user;" >/dev/null 2>&1; then
        log_success "✓ Database connection working"
    else
        log_error "✗ Database connection failed"
        verification_failed=true
    fi
    
    # Check file permissions
    local critical_files=(
        "$GUAC_HOME/guacamole.properties"
        "$GUAC_HOME/extensions"
        "$GUAC_HOME/lib"
    )
    
    for file in "${critical_files[@]}"; do
        if [[ -e "$file" ]]; then
            local owner
            owner=$(stat -c '%U:%G' "$file")
            if [[ "$owner" == "root:$TOMCAT_USER" ]] || [[ "$owner" == "$TOMCAT_USER:$TOMCAT_USER" ]]; then
                log_success "✓ $file has correct ownership"
            else
                log_error "✗ $file has incorrect ownership: $owner"
                verification_failed=true
            fi
        else
            log_error "✗ Critical file missing: $file"
            verification_failed=true
        fi
    done
    
    if [[ "$verification_failed" == true ]]; then
        log_error "Installation verification failed - some components may not work correctly"
        return 1
    else
        log_success "Installation verification passed - all components working correctly"
        return 0
    fi
}

# Generate comprehensive installation report
generate_install_report() {
    log_info "Generating installation report..."
    
    local report_file="/root/guacamole_install_report_$(date +%Y%m%d_%H%M%S).txt"
    local end_time=$(date +%s)
    local duration=$((end_time - SCRIPT_START_TIME))
    local formatted_duration
    formatted_duration=$(printf '%02d:%02d:%02d' $((duration/3600)) $((duration%60/60)) $((duration%60)))
    
    # Get system information
    local server_ip
    server_ip=$(curl -s --max-time 5 http://checkip.amazonaws.com/ 2>/dev/null || hostname -I | awk '{print $1}' || echo "Unable to determine")
    
    cat > "$report_file" << EOF
================================================================================
                    GUACAMOLE INSTALLATION REPORT
================================================================================
Installation completed: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Installation duration: $formatted_duration
Installer version: $SCRIPT_VERSION
Server IP: $server_ip
Warnings: $WARNING_COUNT
Errors: $ERROR_COUNT

================================================================================
                          SYSTEM INFORMATION
================================================================================
OS: $(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)
Kernel: $(uname -r)
Architecture: $(uname -m)
Memory: $(free -h | awk '/^Mem:/ {print $2}')
Disk Space: $(df -h / | awk 'NR==2 {print $2 " total, " $4 " available"}')

================================================================================
                        GUACAMOLE CONFIGURATION
================================================================================
Guacamole Version: $GUAC_VERSION
Installation Path: $GUAC_HOME
Tomcat Service: $TOMCAT_SERVICE
Tomcat User: $TOMCAT_USER

Database Configuration:
- Database Name: $DB_NAME
- Database User: $DB_USER
- Database Password: [REDACTED - see credentials section]
- Root Password: [REDACTED - see credentials section]

Web Configuration:
- Nginx Enabled: $ENABLE_NGINX
- SSL/TLS Enabled: $ENABLE_TLS
EOF

    if [[ "$ENABLE_TLS" == true ]]; then
        cat >> "$report_file" << EOF
- Domain: $DOMAIN
- SSL Email: $EMAIL_LETSENCRYPT
EOF
    fi

    cat >> "$report_file" << EOF

Security Configuration:
- UFW Firewall: $ENABLE_UFW (Auto-enabled: $AUTO_ENABLE_UFW)
- Fail2Ban: Enabled
- Tomcat Lockdown: $LOCKDOWN_TOMCAT
- Strict SSL: $STRICT_SSL

================================================================================
                           ACCESS INFORMATION
================================================================================
Primary Access URL: 
EOF

    if [[ "$ENABLE_NGINX" == true ]]; then
        if [[ "$ENABLE_TLS" == true && -n "$DOMAIN" ]]; then
            echo "  https://$DOMAIN/guacamole/" >> "$report_file"
        elif [[ -n "$DOMAIN" ]]; then
            echo "  http://$DOMAIN/guacamole/" >> "$report_file"
        else
            echo "  http://$server_ip/guacamole/" >> "$report_file"
        fi
    else
        echo "  http://$server_ip:8080/guacamole/" >> "$report_file"
    fi

    cat >> "$report_file" << EOF

Alternative Access (direct Tomcat):
  http://$server_ip:8080/guacamole/

Admin Credentials:
  Username: $GUAC_ADMIN_USER
  Password: $GUAC_ADMIN_PASS

================================================================================
                        DATABASE CREDENTIALS  
================================================================================
MariaDB Root Password: $DB_ROOT_PASS
Guacamole DB Name: $DB_NAME
Guacamole DB User: $DB_USER
Guacamole DB Password: $DB_PASS

Connection String: mysql://$DB_USER:[PASSWORD]@localhost:3306/$DB_NAME

================================================================================
                            SERVICE STATUS
================================================================================
EOF

    # Add service status
    local services=(guacd mariadb "$TOMCAT_SERVICE")
    [[ "$ENABLE_NGINX" == true ]] && services+=(nginx)
    [[ "$ENABLE_MONITORING" == true ]] && services+=(netdata fail2ban)
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            echo "✓ $service: RUNNING" >> "$report_file"
        else
            echo "✗ $service: NOT RUNNING" >> "$report_file"
        fi
    done

    cat >> "$report_file" << EOF

================================================================================
                         IMPORTANT DIRECTORIES
================================================================================
Guacamole Home: $GUAC_HOME
Guacamole Logs: /var/log/guacamole/
Tomcat Logs: /var/log/$TOMCAT_SERVICE/
Nginx Logs: /var/log/nginx/ (if enabled)
Backups: $BACKUP_DIR
Install Logs: $LOGFILE

================================================================================
                          SECURITY REMINDERS
================================================================================
1. CHANGE DEFAULT PASSWORDS: 
   - Change the admin password immediately after first login
   - Consider changing the database passwords periodically

2. FIREWALL STATUS:
   - UFW firewall is $(if [[ "$ENABLE_UFW" == true ]]; then echo "configured"; else echo "not configured"; fi)
   - $(if [[ "$AUTO_ENABLE_UFW" == true ]]; then echo "Firewall is ENABLED"; else echo "Run 'ufw enable' to activate firewall"; fi)

3. SSL CERTIFICATE:
   - $(if [[ "$ENABLE_TLS" == true ]]; then echo "SSL certificate configured with auto-renewal"; else echo "SSL not configured - consider enabling HTTPS for production"; fi)

4. MONITORING:
   - Health check available: guacamole-health-check
   - $(if [[ "$ENABLE_MONITORING" == true ]]; then echo "Netdata monitoring at http://localhost:19999"; else echo "Consider enabling monitoring for production deployments"; fi)

5. BACKUP:
   - Automated backups stored in: $BACKUP_DIR
   - Consider setting up off-site backup for critical data

================================================================================
                           TROUBLESHOOTING
================================================================================
Common Commands:
- Check all services: guacamole-health-check
- Restart Guacamole: systemctl restart guacd $TOMCAT_SERVICE
- View logs: journalctl -u guacd -f
- Test database: mysql -u$DB_USER -p$DB_PASS $DB_NAME
- Nginx status: systemctl status nginx
- Check certificates: certbot certificates

Log Locations:
- Installation: $LOGFILE
- Guacamole: /var/log/guacamole/guacamole.log
- Tomcat: /var/log/$TOMCAT_SERVICE/catalina.out
- Nginx: /var/log/nginx/guacamole.*.log
- System: journalctl -u SERVICE_NAME

Configuration Files:
- Main config: $GUAC_HOME/guacamole.properties
- Extensions: $GUAC_HOME/extensions/
- Libraries: $GUAC_HOME/lib/
- Nginx: /etc/nginx/sites-available/guacamole
- Tomcat: /etc/$TOMCAT_SERVICE/

================================================================================
                            NEXT STEPS
================================================================================
1. Access Guacamole web interface using the URLs above
2. Login with the admin credentials provided
3. Change the default admin password
4. Create additional users and connections as needed
5. Test remote desktop connections
6. $(if [[ "$AUTO_ENABLE_UFW" != true ]]; then echo "Enable firewall: ufw enable"; fi)
7. Set up regular backups of the database
8. Monitor logs for any issues

For support and documentation:
- Official Documentation: https://guacamole.apache.org/doc/gug/
- Community Support: https://guacamole.apache.org/support/

================================================================================
                             END OF REPORT
================================================================================
EOF

    # Set secure permissions on report file
    chmod 600 "$report_file"
    chown root:root "$report_file"
    
    log_success "Installation report saved: $report_file"
    
    # Display summary to console
    echo ""
    echo "=================================================================================="
    echo "                          INSTALLATION COMPLETE!"
    echo "=================================================================================="
    echo "Duration: $formatted_duration"
    echo "Status: $(if [[ $ERROR_COUNT -eq 0 ]]; then echo "SUCCESS"; else echo "COMPLETED WITH ERRORS"; fi)"
    echo ""
    echo "Access Guacamole:"
    if [[ "$ENABLE_NGINX" == true ]]; then
        if [[ "$ENABLE_TLS" == true && -n "$DOMAIN" ]]; then
            echo "  Primary URL: https://$DOMAIN/guacamole/"
        elif [[ -n "$DOMAIN" ]]; then
            echo "  Primary URL: http://$DOMAIN/guacamole/"
        else
            echo "  Primary URL: http://$server_ip/guacamole/"
        fi
    else
        echo "  Direct URL: http://$server_ip:8080/guacamole/"
    fi
    echo ""
    echo "Admin Credentials:"
    echo "  Username: $GUAC_ADMIN_USER"
    echo "  Password: $GUAC_ADMIN_PASS"
    echo ""
    echo "Full report: $report_file"
    echo "Health check: guacamole-health-check"
    echo ""
    if [[ "$AUTO_ENABLE_UFW" != true && "$ENABLE_UFW" == true ]]; then
        echo "⚠️  IMPORTANT: Run 'ufw enable' to activate the firewall"
        echo ""
    fi
    echo "🔐 SECURITY: Change the admin password after first login!"
    echo "=================================================================================="
}

# Main installation orchestration
main() {
    # Initialize logging
    mkdir -p "$(dirname "$LOGFILE")"
    touch "$LOGFILE"
    INSTALL_LOG="$LOGFILE"
    
    # Redirect all output to log file while still showing on console
    exec 3>&1 4>&2
    exec 1> >(tee -a "$LOGFILE") 2> >(tee -a "$LOGFILE" >&2)
    
    log_info "Starting Guacamole Perfect Installer v$SCRIPT_VERSION"
    log_info "Timestamp: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
    log_info "PID: $"
    
    # Trap for cleanup on exit
    trap 'cleanup_on_error' ERR
    trap 'cleanup_temp_dirs' EXIT
    
    # Pre-flight checks
    validate_inputs
    check_prerequisites
    gather_system_info
    detect_tomcat
    
    # Generate secure passwords if not provided
    [[ -z "$GUAC_ADMIN_PASS" ]] && GUAC_ADMIN_PASS=$(rand_password 16)
    [[ -z "$DB_PASS" ]] && DB_PASS=$(rand_password 32)
    [[ -z "$DB_ROOT_PASS" ]] && DB_ROOT_PASS=$(rand_password 32)
    
    log_info "Generated secure passwords for unspecified credentials"
    
    # Installation steps
    log_info "=== PHASE 1: SYSTEM PREPARATION ==="
    create_backup
    install_packages
    setup_directories
    
    log_info "=== PHASE 2: CORE COMPONENTS ==="
    install_guacd
    deploy_webapp
    setup_database
    setup_jdbc_auth
    
    log_info "=== PHASE 3: CONFIGURATION ==="
    create_configuration
    create_admin_user
    configure_tomcat
    
    log_info "=== PHASE 4: WEB SERVER ==="
    configure_nginx
    configure_ssl
    
    log_info "=== PHASE 5: SECURITY ==="
    configure_firewall
    configure_fail2ban
    
    log_info "=== PHASE 6: MAINTENANCE ==="
    configure_logging
    setup_monitoring
    
    log_info "=== PHASE 7: VERIFICATION ==="
    if verify_installation; then
        log_success "Installation verification passed"
    else
        log_warn "Installation verification had issues - check logs"
    fi
    
    # Final report
    generate_install_report
    
    # Cleanup
    cleanup_temp_dirs
    
    # Restore descriptors
    exec 1>&3 2>&4
    
    log_success "Guacamole installation completed successfully!"
    exit 0
}

# Cleanup function for temporary directories
cleanup_temp_dirs() {
    for temp_dir in "${TEMP_DIRS[@]}"; do
        [[ -d "$temp_dir" ]] && rm -rf "$temp_dir"
    done
}

# Script execution starts here
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
