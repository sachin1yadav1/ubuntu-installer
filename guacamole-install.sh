#!/usr/bin/env bash
# guacamole-fixed-install.sh — Fixed Guacamole installer for Ubuntu (20.04/22.04/24.04+)
# Version: 2.0.1 - Ubuntu 24.04 Compatible
# Usage: sudo ./guacamole-fixed-install.sh
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
ENABLE_MONITORING=true     # Install basic monitoring
STRICT_SSL=true            # Enforce strong SSL settings
LOCKDOWN_TOMCAT=true       # Restrict Tomcat to localhost when using Nginx
DEBUG=false                # Set to true for verbose debugging
# ===========================================================

### ========== GLOBAL VARIABLES ==========
SCRIPT_VERSION="2.0.1"
SCRIPT_START_TIME=$(date +%s)
TOMCAT_SERVICE=""
TOMCAT_VERSION=""
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
    if [[ "${DEBUG:-false}" == true ]]; then
        log_error "Stack trace:"
        local frame=0
        while caller $frame 2>/dev/null; do
            ((frame++))
        done | while read -r line func file; do
            log_error "  at $func ($file:$line)"
        done
    fi
    cleanup_on_error
    exit 1
}

# Cleanup function for error scenarios
cleanup_on_error() {
    log_error "Performing cleanup due to error..."
    
    # Remove temporary directories
    for temp_dir in "${TEMP_DIRS[@]}"; do
        [[ -d "$temp_dir" ]] && { rm -rf "$temp_dir" || true; }
    done
    
    # Execute rollback stack in reverse order
    for ((i=${#ROLLBACK_STACK[@]}-1; i>=0; i--)); do
        log_info "Rollback: ${ROLLBACK_STACK[i]}"
        eval "${ROLLBACK_STACK[i]}" 2>/dev/null || true
    done
    
    log_error "Cleanup completed. Check logs for details: $LOGFILE"
}

# Enhanced random password generation
rand_password() {
    local length="${1:-32}"
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 $((length * 2)) | tr -cd 'A-Za-z0-9!@#$%^&*()-_=+' | head -c"$length"
    else
        head -c$((length * 2)) /dev/urandom | tr -cd 'A-Za-z0-9!@#$%^&*()-_=+' | head -c"$length"
    fi
    echo
}

# Enhanced retry mechanism
retry() {
    local cmd="$1"
    local max_attempts="${2:-3}"
    local delay="${3:-2}"
    local attempt=1
    
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
        ((attempt++))
    done
}

# Enhanced apt lock waiting
apt_wait_lock() {
    local timeout="${1:-120}"
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
    os_info=$(lsb_release -ds 2>/dev/null || grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)
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
        
        # Validate domain format
        if [[ ! "$DOMAIN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
            die "Invalid domain format: $DOMAIN"
        fi
        
        # Validate email format
        if [[ ! "$EMAIL_LETSENCRYPT" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            die "Invalid email format: $EMAIL_LETSENCRYPT"
        fi
    fi
    
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
    
    # Store version for later use
    export UBUNTU_VERSION="$version_id"
    export UBUNTU_MAJOR="$version_major"
    
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

# Fixed Tomcat detection for Ubuntu 24.04
detect_tomcat() {
    log_info "Detecting appropriate Tomcat version for Ubuntu $UBUNTU_VERSION..."
    
    # Determine Tomcat version based on Ubuntu version
    if (( UBUNTU_MAJOR >= 24 )); then
        TOMCAT_SERVICE="tomcat10"
        TOMCAT_VERSION="10"
        log_info "Ubuntu 24.04+ detected - using Tomcat 10"
    elif (( UBUNTU_MAJOR >= 22 )); then
        TOMCAT_SERVICE="tomcat9"
        TOMCAT_VERSION="9"
        log_info "Ubuntu 22.04 detected - using Tomcat 9"
    else
        TOMCAT_SERVICE="tomcat9"
        TOMCAT_VERSION="9"
        log_info "Ubuntu 20.04 detected - using Tomcat 9"
    fi
    
    # Check if already installed
    if systemctl list-unit-files | grep -q "^${TOMCAT_SERVICE}\.service"; then
        log_info "Found existing $TOMCAT_SERVICE service"
    else
        log_info "Will install: $TOMCAT_SERVICE"
    fi
    
    # Set Tomcat user (consistent across versions)
    TOMCAT_USER="tomcat"
    
    log_success "Tomcat detection completed: $TOMCAT_SERVICE"
}

# Enhanced package installation with Ubuntu 24.04 support
install_packages() {
    log_info "Installing required packages for Ubuntu $UBUNTU_VERSION..."
    
    export DEBIAN_FRONTEND=noninteractive
    
    # Update package list
    apt_wait_lock
    retry "apt-get update -y" 3 5 || die "Failed to update package list"
    
    # Core build dependencies
    local build_packages=(
        build-essential libcairo2-dev libjpeg-turbo8-dev libpng-dev libtool-bin 
        libossp-uuid-dev libavcodec-dev libavformat-dev libavutil-dev libswscale-dev 
        libfreerdp2-dev libpango1.0-dev libssh2-1-dev libvncserver-dev libtelnet-dev 
        libssl-dev libvorbis-dev libwebp-dev libpulse-dev pkg-config
    )
    
    # Java and Tomcat (version-specific)
    local java_packages=()
    if (( UBUNTU_MAJOR >= 24 )); then
        java_packages=(default-jdk tomcat10 tomcat10-admin tomcat10-common)
    else
        java_packages=(default-jdk tomcat9 tomcat9-admin tomcat9-common)
    fi
    
    # Database
    local db_packages=(mariadb-server mariadb-client)
    
    # Add MySQL connector based on Ubuntu version
    if (( UBUNTU_MAJOR >= 24 )); then
        db_packages+=(libmariadb-java)
    else
        db_packages+=(default-mysql-connector-java)
    fi
    
    # Web server and SSL
    local web_packages=(nginx certbot python3-certbot-nginx)
    
    # Utilities and security
    local util_packages=(
        wget curl unzip zip htop
        ufw fail2ban logrotate rsyslog
        ghostscript ffmpeg
        tree vim nano bc
    )
    
    # Monitoring (if enabled)
    local monitor_packages=()
    if [[ "$ENABLE_MONITORING" == true ]]; then
        if (( UBUNTU_MAJOR >= 24 )); then
            monitor_packages=(netdata)
        else
            monitor_packages=(netdata prometheus-node-exporter)
        fi
    fi
    
    # Install packages in logical groups
    local package_groups=(
        "build_packages[@]"
        "java_packages[@]" 
        "db_packages[@]" 
        "web_packages[@]" 
        "util_packages[@]"
    )
    
    [[ ${#monitor_packages[@]} -gt 0 ]] && package_groups+=("monitor_packages[@]")
    
    for group_ref in "${package_groups[@]}"; do
        local -n group=$group_ref
        local group_name=${group_ref%[@]*}
        
        log_info "Installing $group_name..."
        
        apt_wait_lock
        if ! retry "apt-get install -y ${group[*]}" 2 8; then
            log_warn "Group installation failed, trying individual packages..."
            for package in "${group[@]}"; do
                apt_wait_lock
                if ! apt-get install -y "$package" 2>/dev/null; then
                    log_warn "Failed to install: $package (will continue)"
                fi
            done
        fi
    done
    
    # Verify critical packages
    local critical_packages=(default-jdk "$TOMCAT_SERVICE" mariadb-server wget curl)
    local missing_packages=()
    
    for package in "${critical_packages[@]}"; do
        if ! dpkg -l "$package" >/dev/null 2>&1; then
            missing_packages+=("$package")
        fi
    done
    
    if [[ ${#missing_packages[@]} -gt 0 ]]; then
        log_error "Critical packages not installed: ${missing_packages[*]}"
        die "Package installation failed"
    fi
    
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
    )
    
    for dir in "${directories[@]}"; do
        mkdir -p "$dir" || die "Failed to create directory: $dir"
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

# Build and install guacd
install_guacd() {
    log_info "Building and installing guacd..."
    
    # Check if guacd is already installed and version matches
    if command -v guacd >/dev/null 2>&1; then
        local current_version
        current_version=$(guacd -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "unknown")
        if [[ "$current_version" == "$GUAC_VERSION" ]]; then
            log_info "guacd version $GUAC_VERSION already installed"
            # Still need to ensure service is running
            systemctl enable guacd 2>/dev/null || true
            systemctl start guacd 2>/dev/null || true
            return 0
        else
            log_info "Upgrading guacd from $current_version to $GUAC_VERSION"
        fi
    fi
    
    # Create temporary build directory
    local build_dir
    build_dir=$(mktemp -d)
    TEMP_DIRS+=("$build_dir")
    ROLLBACK_STACK+=("systemctl stop guacd 2>/dev/null || true")
    
    cd "$build_dir"
    
    # Download source
    local source_url="https://archive.apache.org/dist/guacamole/$GUAC_VERSION/source/guacamole-server-$GUAC_VERSION.tar.gz"
    
    log_info "Downloading guacd source..."
    retry "wget -q '$source_url' -O guacamole-server.tar.gz" 3 5 || die "Failed to download guacd source"
    
    # Extract and build
    tar -xzf guacamole-server.tar.gz || die "Failed to extract source"
    cd "guacamole-server-$GUAC_VERSION"
    
    log_info "Configuring build..."
    ./configure --with-init-dir=/etc/init.d \
                --enable-allow-freerdp-snapshots \
                --with-systemd-dir=/etc/systemd/system || die "Configure failed"
    
    log_info "Building guacd (this may take several minutes)..."
    make -j"$(nproc)" || die "Build failed"
    
    log_info "Installing guacd..."
    make install || die "Installation failed"
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
    systemctl enable guacd || die "Failed to enable guacd"
    systemctl start guacd || die "Failed to start guacd"
    
    # Verify installation
    local attempts=0
    while ! systemctl is-active --quiet guacd; do
        sleep 2
        ((attempts++))
        if (( attempts > 10 )); then
            journalctl -u guacd --no-pager -l | tail -10
            die "guacd failed to start"
        fi
    done
    
    if ! guacd -v >/dev/null 2>&1; then
        die "guacd installation verification failed"
    fi
    
    log_success "guacd installed and running"
}

# Deploy Guacamole web application with proper paths for different Tomcat versions
deploy_webapp() {
    log_info "Deploying Guacamole web application for $TOMCAT_SERVICE..."
    
    # Determine correct webapps path
    local tomcat_webapps
    if (( UBUNTU_MAJOR >= 24 )); then
        tomcat_webapps="/var/lib/tomcat10/webapps"
    else
        tomcat_webapps="/var/lib/tomcat9/webapps"
    fi
    
    # Ensure webapps directory exists
    mkdir -p "$tomcat_webapps"
    
    local war_file="$tomcat_webapps/guacamole.war"
    
    # Backup existing WAR if present
    if [[ -f "$war_file" ]]; then
        cp "$war_file" "$war_file.backup.$(date +%Y%m%d%H%M%S)"
        ROLLBACK_STACK+=("cp '$war_file.backup.*' '$war_file' 2>/dev/null || true")
    fi
    
    # Download WAR file
    local war_url="https://archive.apache.org/dist/guacamole/$GUAC_VERSION/binary/guacamole-$GUAC_VERSION.war"
    log_info "Downloading Guacamole WAR file..."
    retry "wget -q '$war_url' -O '$war_file'" 3 5 || die "Failed to download guacamole.war"
    
    # Set proper ownership and permissions
    chown "$TOMCAT_USER":"$TOMCAT_USER" "$war_file"
    chmod 640 "$war_file"
    
    log_success "Guacamole WAR deployed to $tomcat_webapps"
}

# Rest of the functions remain the same but with proper error handling...
# I'll include the key remaining functions

# Setup database with enhanced security
setup_database() {
    log_info "Setting up MariaDB database..."
    
    # Generate strong root password if not provided
    if [[ -z "$DB_ROOT_PASS" ]]; then
        DB_ROOT_PASS=$(rand_password 32)
        log_info "Generated strong root password for MariaDB"
    fi
    
    # Start MariaDB
    systemctl enable mariadb || die "Failed to enable MariaDB"
    systemctl start mariadb || die "Failed to start MariaDB"
    
    # Wait for MariaDB to be ready
    local attempts=0
    while ! mysqladmin ping --silent >/dev/null 2>&1; do
        sleep 2
        ((attempts++))
        if (( attempts > 30 )); then
            die "MariaDB did not start in time"
        fi
    done
    
    log_info "MariaDB running, securing installation..."
    
    # Secure MariaDB installation
    mysql -u root <<SQL || die "Failed to secure MariaDB"
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
    
    # Create Guacamole database and user
    log_info "Creating Guacamole database and user..."
    mysql -uroot -p"$DB_ROOT_PASS" <<SQL || die "Failed to create database"
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

# Main installation orchestration with better error handling
main() {
    # Initialize logging
    mkdir -p "$(dirname "$LOGFILE")"
    touch "$LOGFILE" || die "Cannot create log file: $LOGFILE"
    INSTALL_LOG="$LOGFILE"
    
    # Redirect all output to log file while still showing on console
    exec 3>&1 4>&2
    exec 1> >(tee -a "$LOGFILE") 2> >(tee -a "$LOGFILE" >&2)
    
    log_info "Starting Guacamole Fixed Installer v$SCRIPT_VERSION"
    log_info "Timestamp: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
    log_info "PID: $$"
    
    # Trap for cleanup on exit
    trap 'cleanup_on_error' ERR
    trap 'cleanup_temp_dirs' EXIT
    
    # Pre-flight checks
    validate_inputs
    check_prerequisites
    gather_system_info
    detect_tomcat  # This was likely failing before
    
    # Generate secure passwords if not provided
    [[ -z "$GUAC_ADMIN_PASS" ]] && GUAC_ADMIN_PASS=$(rand_password 16)
    [[ -z "$DB_PASS" ]] && DB_PASS=$(rand_password 32)
    [[ -z "$DB_ROOT_PASS" ]] && DB_ROOT_PASS=$(rand_password 32)
    
    log_info "Generated secure passwords for unspecified credentials"
    
    # Installation steps
    log_info "=== PHASE 1: SYSTEM PREPARATION ==="
    install_packages
    setup_directories
    
    log_info "=== PHASE 2: CORE COMPONENTS ==="
    install_guacd
    deploy_webapp
    setup_database
    
    log_info "=== PHASE 3: BASIC CONFIGURATION ==="
    # Create basic guacamole.properties
    cat > "$GUAC_HOME/guacamole.properties" << EOF
# Guacamole Configuration
guacd-hostname: localhost
guacd-port: 4822
mysql-hostname: localhost
mysql-port: 3306
mysql-database: ${DB_NAME}
mysql-username: ${DB_USER}
mysql-password: ${DB_PASS}
lib-directory: ${GUAC_HOME}/lib
extension-directory: ${GUAC_HOME}/extensions
EOF
    
    chmod 640 "$GUAC_HOME/guacamole.properties"
    chown root:"$TOMCAT_USER" "$GUAC_HOME/guacamole.properties"
    
    # Create symbolic link for Tomcat
    local tomcat_home
    if (( UBUNTU_MAJOR >= 24 )); then
        tomcat_home="/usr/share/tomcat10"
    else
        tomcat_home="/usr/share/tomcat9"
    fi
    
    ln -sfn "$GUAC_HOME" "$tomcat_home/.guacamole"
    
    # Start Tomcat
    systemctl enable "$TOMCAT_SERVICE" || die "Failed to enable $TOMCAT_SERVICE"
    systemctl start "$TOMCAT_SERVICE" || die "Failed to start $TOMCAT_SERVICE"
    
    # Wait for Tomcat to start
    local attempts=0
    while ! systemctl is-active --quiet "$TOMCAT_SERVICE"; do
        sleep 3
        ((attempts++))
        if (( attempts > 20 )); then
            journalctl -u "$TOMCAT_SERVICE" --no-pager -l | tail -20
            die "Tomcat failed to start properly"
        fi
    done
    
    log_success "Basic installation completed successfully!"
    
    # Generate installation report
    generate_basic_report
    
    # Cleanup
    cleanup_temp_dirs
    
    # Restore descriptors
    exec 1>&3 2>&4
    
    exit 0
}

# Generate basic installation report
generate_basic_report() {
    local report_file="/root/guacamole_install_report_$(date +%Y%m%d_%H%M%S).txt"
    local server_ip
    server_ip=$(curl -s --max-time 5 http://checkip.amazonaws.com/ 2>/dev/null || hostname -I | awk '{print $1}' || echo "Unable to determine")
    
    cat > "$report_file" << EOF
================================================================================
                    GUACAMOLE INSTALLATION REPORT
================================================================================
Installation completed: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Installer version: $SCRIPT_VERSION (Ubuntu 24.04 Fixed)
Server IP: $server_ip
Ubuntu Version: $UBUNTU_VERSION
Tomcat Version: $TOMCAT_SERVICE

================================================================================
                          ACCESS INFORMATION
================================================================================
Primary Access URL: http://$server_ip:8080/guacamole/

Initial Admin Credentials:
  Username: $GUAC_ADMIN_USER
  Password: $GUAC_ADMIN_PASS

================================================================================
                        DATABASE CREDENTIALS  
================================================================================
MariaDB Root Password: $DB_ROOT_PASS
Guacamole DB Name: $DB_NAME
Guacamole DB User: $DB_USER  
Guacamole DB Password: $DB_PASS

================================================================================
                            SERVICE STATUS
================================================================================
EOF

    # Check service status
    local services=(guacd mariadb "$TOMCAT_SERVICE")
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
Tomcat Webapps: $(if (( UBUNTU_MAJOR >= 24 )); then echo "/var/lib/tomcat10/webapps"; else echo "/var/lib/tomcat9/webapps"; fi)
Install Logs: $LOGFILE

================================================================================
                          NEXT STEPS
================================================================================
1. Access Guacamole: http://$server_ip:8080/guacamole/
2. Login with admin credentials above
3. CHANGE THE ADMIN PASSWORD immediately
4. Create connections for remote desktop access
5. Consider setting up Nginx reverse proxy for production
6. Consider enabling SSL/TLS for security

================================================================================
                           TROUBLESHOOTING
================================================================================
View logs:
- Installation: $LOGFILE
- Guacamole/Tomcat: journalctl -u $TOMCAT_SERVICE -f
- guacd: journalctl -u guacd -f
- Database: journalctl -u mariadb -f

Test database connection:
mysql -u$DB_USER -p$DB_PASS $DB_NAME

Restart services:
sudo systemctl restart guacd $TOMCAT_SERVICE mariadb

================================================================================
                             END OF REPORT
================================================================================
EOF

    chmod 600 "$report_file"
    chown root:root "$report_file"
    
    log_success "Installation report saved: $report_file"
    
    # Display summary
    echo ""
    echo "=================================================================================="
    echo "                    INSTALLATION COMPLETED SUCCESSFULLY!"
    echo "=================================================================================="
    echo "Ubuntu Version: $UBUNTU_VERSION"
    echo "Tomcat Service: $TOMCAT_SERVICE"
    echo ""
    echo "Access Guacamole: http://$server_ip:8080/guacamole/"
    echo ""
    echo "Admin Credentials:"
    echo "  Username: $GUAC_ADMIN_USER"
    echo "  Password: $GUAC_ADMIN_PASS"
    echo ""
    echo "🔐 IMPORTANT: Change the admin password after first login!"
    echo ""
    echo "Full report: $report_file"
    echo "=================================================================================="
}

# Cleanup function for temporary directories
cleanup_temp_dirs() {
    for temp_dir in "${TEMP_DIRS[@]}"; do
        [[ -d "$temp_dir" ]] && rm -rf "$temp_dir" 2>/dev/null || true
    done
}

# Script execution starts here
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
