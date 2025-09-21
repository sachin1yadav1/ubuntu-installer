# 🚀 Guacamole Installer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-20.04%2B-orange.svg)](https://ubuntu.com/)
[![Guacamole](https://img.shields.io/badge/Guacamole-1.5.3-blue.svg)](https://guacamole.apache.org/)
[![Security](https://img.shields.io/badge/Security-Production%20Ready-green.svg)](https://github.com)

A **production-grade, enterprise-ready** automated installer for Apache Guacamole with comprehensive security hardening, monitoring, and management features.

## ✨ Features

### 🔒 **Enterprise Security**
- **Strong Password Generation** - 32-character passwords with high entropy
- **SHA-256 Password Hashing** - Secure password storage with salt
- **MariaDB Hardening** - Complete security lockdown and optimization
- **UFW Firewall** - Intelligent rules with rate limiting
- **Fail2Ban Integration** - Automated intrusion prevention
- **SSL/TLS Automation** - Let's Encrypt with security headers
- **Security Headers** - CSP, HSTS, XSS protection, and more

### 🛡️ **Bulletproof Reliability**
- **Comprehensive Error Handling** - Automatic rollback on failures
- **Input Validation** - Validates all configurations before starting
- **Service Health Checks** - Verifies every component works correctly
- **Retry Mechanisms** - Exponential backoff for network operations
- **Graceful Cleanup** - No leftover files or partial installations

### 📊 **Production Features**
- **Multi-Version Support** - Ubuntu 20.04, 22.04, 24.04+
- **Auto Tomcat Detection** - Supports Tomcat 8, 9, 10
- **Database Optimization** - Connection pooling and performance tuning
- **Nginx Optimization** - Rate limiting, caching, compression
- **Log Management** - Automatic rotation and centralized logging
- **Backup System** - Automated backups with cleanup

### 🔧 **Advanced Configuration**
- **Monitoring Integration** - Netdata, health checks, alerts
- **SSL Certificate Management** - Auto-renewal and validation
- **Performance Tuning** - JVM optimization, resource allocation
- **Security Compliance** - Follows security best practices
- **Maintenance Tools** - Built-in diagnostic and repair tools

## 🏁 Quick Start

### Prerequisites
- Ubuntu 20.04, 22.04, or 24.04+ (64-bit)
- Root access (sudo)
- Internet connection
- 2GB+ RAM (4GB recommended)
- 5GB+ free disk space

### 1. Download the Script
```bash
# Download the installer
wget https://raw.githubusercontent.com/sachin1yadav1/ubuntu-installer/main/guacamole-install.sh

# Make it executable
chmod +x guacamole-install.sh
```

### 2. Configure (Optional)
Edit the configuration section at the top of the script:

```bash
nano guacamole-install.sh
```

**Key Configuration Options:**
```bash
GUAC_VERSION="1.5.3"           # Guacamole version
ENABLE_NGINX=true              # Reverse proxy (recommended)
ENABLE_TLS=true                # HTTPS with Let's Encrypt
DOMAIN="guac.example.com"      # Your domain name
EMAIL_LETSENCRYPT="admin@example.com"  # For SSL certificates
AUTO_ENABLE_UFW=true           # Automatically enable firewall
ENABLE_MONITORING=true         # System monitoring tools
```

### 3. Run the Installer
```bash
# Run with root privileges
sudo ./guacamole-install.sh
```

### 4. Access Guacamole
After installation completes, access your Guacamole instance:
- **HTTPS**: `https://your-domain.com/guacamole/`
- **HTTP**: `http://your-server-ip/guacamole/`
- **Direct**: `http://your-server-ip:8080/guacamole/`

Use the credentials provided in the installation report.

## 🔧 Configuration Reference

### Basic Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `GUAC_VERSION` | `1.5.3` | Guacamole version to install |
| `GUAC_HOME` | `/etc/guacamole` | Guacamole configuration directory |
| `GUAC_ADMIN_USER` | `admin` | Default admin username |
| `DB_NAME` | `guacamole_db` | Database name |
| `DB_USER` | `guacuser` | Database username |

### Web Server Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `ENABLE_NGINX` | `true` | Enable Nginx reverse proxy |
| `ENABLE_TLS` | `false` | Enable HTTPS with Let's Encrypt |
| `DOMAIN` | `""` | Domain name (required for TLS) |
| `EMAIL_LETSENCRYPT` | `""` | Email for SSL certificates |
| `STRICT_SSL` | `true` | Enforce strong SSL settings |

### Security Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `ENABLE_UFW` | `true` | Configure UFW firewall |
| `AUTO_ENABLE_UFW` | `false` | Automatically enable firewall |
| `LOCKDOWN_TOMCAT` | `true` | Restrict Tomcat to localhost |
| `ENABLE_2FA` | `false` | Enable TOTP extension (experimental) |

### System Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `ENABLE_MONITORING` | `true` | Install monitoring tools |
| `BACKUP_DIR` | `/var/backups/guacamole` | Backup directory |
| `MAX_BACKUP_COUNT` | `10` | Number of backups to keep |
| `LOGFILE` | `/var/log/guacamole_installer.log` | Installation log file |

## 🔐 Security Features

### Password Security
- **Automatic Generation**: Strong 32-character passwords
- **Secure Hashing**: SHA-256 with salt (not MD5)
- **Database Encryption**: Encrypted password storage
- **Credential Protection**: Secure file permissions (600)

### Network Security
- **Firewall Rules**: UFW with intelligent port management
- **Rate Limiting**: Nginx-based request limiting
- **SSL/TLS**: Modern cipher suites and security headers
- **Intrusion Prevention**: Fail2Ban with custom rules

### System Security
- **Service Isolation**: Proper user separation
- **File Permissions**: Restrictive file system permissions
- **Log Security**: Protected log files with rotation
- **Database Hardening**: MariaDB security best practices

## 📊 Monitoring & Maintenance

### Health Monitoring
```bash
# Check system status
guacamole-health-check

# View service logs
journalctl -u guacd -f
journalctl -u tomcat9 -f

# Check database connection
mysql -u guacuser -p guacamole_db
```

### Performance Monitoring
- **Netdata**: Available at `http://localhost:19999` (if enabled)
- **System Metrics**: CPU, memory, disk, network monitoring
- **Service Monitoring**: Guacamole-specific health checks
- **Log Analysis**: Centralized logging with rotation

### Backup Management
```bash
# Manual backup
tar -czf /var/backups/guacamole/manual-backup-$(date +%Y%m%d).tar.gz /etc/guacamole

# Database backup
mysqldump -u root -p guacamole_db > guacamole-db-backup.sql

# Restore from backup
mysql -u root -p guacamole_db < guacamole-db-backup.sql
```

## 🛠️ Troubleshooting

### Common Issues

#### Guacamole Not Loading
```bash
# Check services
systemctl status guacd
systemctl status tomcat9
systemctl status nginx

# Check logs
tail -f /var/log/guacamole/guacamole.log
tail -f /var/log/tomcat9/catalina.out
```

#### SSL Certificate Issues
```bash
# Check certificate status
certbot certificates

# Renew certificates
certbot renew --dry-run

# Test SSL configuration
nginx -t
```

#### Database Connection Problems
```bash
# Test database connection
mysql -u guacuser -p guacamole_db

# Check MariaDB status
systemctl status mariadb
tail -f /var/log/mysql/error.log
```

#### Firewall Issues
```bash
# Check UFW status
ufw status verbose

# Allow specific ports
ufw allow 80/tcp
ufw allow 443/tcp

# Reset UFW (careful!)
ufw --force reset
```

### Log Locations
| Component | Log Location |
|-----------|--------------|
| Installation | `/var/log/guacamole_installer.log` |
| Guacamole | `/var/log/guacamole/guacamole.log` |
| Tomcat | `/var/log/tomcat9/catalina.out` |
| Nginx | `/var/log/nginx/guacamole.*.log` |
| MariaDB | `/var/log/mysql/error.log` |
| UFW | `/var/log/ufw.log` |
| Fail2Ban | `/var/log/fail2ban.log` |

### Performance Tuning

#### JVM Optimization
```bash
# Edit Tomcat defaults
nano /etc/default/tomcat9

# Recommended JVM options
JAVA_OPTS="-Djava.awt.headless=true -Xmx2048M -XX:+UseConcMarkSweepGC"
```

#### Database Optimization
```bash
# Edit MariaDB configuration
nano /etc/mysql/mariadb.conf.d/50-server.cnf

# Key performance settings
innodb_buffer_pool_size = 512M
max_connections = 200
query_cache_size = 64M
```

#### Nginx Optimization
```bash
# Edit Nginx configuration
nano /etc/nginx/sites-available/guacamole

# Enable gzip compression
gzip on;
gzip_types text/css application/javascript application/json;

# Enable caching
location ~* \.(css|js|png|jpg|jpeg|gif|ico|svg)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
}
```

## 🔄 Updates & Upgrades

### Upgrading Guacamole
```bash
# 1. Backup current installation
cp -r /etc/guacamole /etc/guacamole.backup

# 2. Update version in script
nano guacamole-perfect-install.sh
# Change GUAC_VERSION="1.5.4"

# 3. Run installer (it will upgrade automatically)
sudo ./guacamole-perfect-install.sh
```

### System Updates
```bash
# Update system packages
apt update && apt upgrade -y

# Update SSL certificates
certbot renew

# Restart services if needed
systemctl restart guacd tomcat9 nginx
```

## 🏗️ Architecture Overview

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│                 │    │                  │    │                 │
│   Internet/     │    │     Nginx        │    │    Tomcat       │
│   Users         ├────┤   Reverse Proxy  ├────┤   (Guacamole    │
│                 │    │   SSL Termination│    │    Web App)     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                        │
                                │                        │
                       ┌────────▼────────┐    ┌──────────▼──────────┐
                       │                 │    │                     │
                       │   UFW Firewall  │    │       guacd         │
                       │   Fail2Ban      │    │   (Proxy Daemon)    │
                       │                 │    │                     │
                       └─────────────────┘    └──────────▲──────────┘
                                                         │
                              ┌──────────────────────────┼──────────────────────────┐
                              │                          │                          │
                    ┌─────────▼─────────┐    ┌─────────▼─────────┐    ┌─────────▼─────────┐
                    │                   │    │                   │    │                   │
                    │   RDP Servers     │    │   SSH Servers     │    │   VNC Servers     │
                    │                   │    │                   │    │                   │
                    └───────────────────┘    └───────────────────┘    └───────────────────┘

┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│                 │    │                  │    │                 │
│   MariaDB       │    │   Monitoring     │    │   Backup        │
│   Database      │    │   (Netdata)      │    │   System        │
│                 │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### Reporting Issues
1. Check existing [issues](https://github.com/sachin1yadav1/ubuntu-installer/issues)
2. Create a new issue with:
   - System information (OS version, hardware)
   - Installation log (`/var/log/guacamole_installer.log`)
   - Steps to reproduce
   - Expected vs actual behavior

### Feature Requests
1. Check [existing requests](https://github.com/sachin1yadav1/ubuntu-installer/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement)
2. Create a new enhancement request
3. Describe the use case and benefits

### Code Contributions
1. Fork the repository
2. Create a feature branch
3. Test thoroughly on multiple Ubuntu versions
4. Submit a pull request with detailed description

### Testing
Help test the installer on different configurations:
- Various Ubuntu versions (20.04, 22.04, 24.04)
- Different hardware configurations
- Various network setups
- SSL certificate scenarios

## 📋 Changelog

### Version 1.0.0 (Latest)
- **NEW**: Complete rewrite for production environments
- **NEW**: SHA-256 password hashing with salt
- **NEW**: Comprehensive error handling and rollback
- **NEW**: Automatic Tomcat version detection
- **NEW**: Advanced Nginx configuration with security headers
- **NEW**: Fail2Ban integration for intrusion prevention
- **NEW**: Health monitoring and diagnostic tools
- **NEW**: Backup system with automatic cleanup
- **NEW**: SSL/TLS configuration with Let's Encrypt
- **NEW**: Database security and optimization
- **NEW**: Logging and error reporting
- **NEW**: Multiple Ubuntu version compatibility
- **NEW**: Edge cases in network configuration



## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Apache Guacamole Team** - For creating this amazing remote desktop gateway
- **Ubuntu Community** - For the excellent Linux distribution
- **Let's Encrypt** - For free SSL certificates
- **Contributors** - Everyone who has contributed to improving this installer

## 📞 Support

### Documentation
- **Apache Guacamole**: https://guacamole.apache.org/doc/gug/
- **Ubuntu Server Guide**: https://ubuntu.com/server/docs
- **Nginx Documentation**: https://nginx.org/en/docs/
- **MariaDB Documentation**: https://mariadb.org/documentation/

### Community Support
- **GitHub Issues**: [Report bugs and request features](https://github.com/sachin1yadav1/ubuntu-installer/issues)
- **Guacamole Mailing List**: https://guacamole.apache.org/support/
- **Ubuntu Forums**: https://ubuntuforums.org/

### Professional Support
For enterprise deployments and professional support, consider:
- Custom installation and configuration
- Security audits and hardening
- Performance optimization
- 24/7 monitoring and maintenance

---

## 🚀 Quick Commands Reference

```bash
# Installation
sudo ./guacamole-install.sh

# Health Check
guacamole-health-check

# View Logs
journalctl -u guacd -f
tail -f /var/log/guacamole/guacamole.log

# Service Management
systemctl restart guacd tomcat9 nginx
systemctl status guacd tomcat9 nginx

# Database Access
mysql -u guacuser -p guacamole_db

# SSL Certificate Management
certbot certificates
certbot renew

# Firewall Management
ufw status
ufw enable/disable

# Backup
tar -czf backup.tar.gz /etc/guacamole
```

**⭐ If this installer helped you, please give it a star on GitHub!**

---

*Made with ❤️ for the Guacamole community*
