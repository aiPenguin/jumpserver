# Arch Linux 跳板机配置最终指南

本指南假设您已经完成了 Arch Linux 的基础安装，现在需要配置一个功能完善的跳板机系统。本指南将重点关注跳板机的用户管理、安全配置和监控系统。

## 1. 跳板机系统准备

首先，我们需要安装必要的软件包并进行基础配置。

```bash
# 更新系统
sudo pacman -Syu

# 安装必要工具
sudo pacman -S openssh fail2ban ufw ddclient s-nail curl wget htop iptables-nft cronie bc git base-devel logrotate quota-tools msmtp

# 启用并启动SSH服务
sudo systemctl enable sshd
sudo systemctl start sshd

# 启用并启动cronie服务(用于计划任务)
sudo systemctl enable cronie
sudo systemctl start cronie
```

## 2. 用户管理系统设计

### 2.1 创建管理员用户

首先，我们创建一个具有完整管理权限的管理员用户：

```bash
# 创建管理员用户
sudo useradd -m -G wheel admin_user
sudo passwd admin_user

# 允许wheel组使用sudo
sudo sed -i 's/# %wheel ALL=(ALL:ALL) ALL/%wheel ALL=(ALL:ALL) ALL/' /etc/sudoers

# 确保管理员用户有完整的sudo权限
sudo tee /etc/sudoers.d/admin_privileges << 'EOF'
admin_user ALL=(ALL) NOPASSWD: ALL
EOF
sudo chmod 440 /etc/sudoers.d/admin_privileges

# 确保管理员不受配额限制
sudo setquota -u admin_user 0 0 0 0 -a
```

### 2.2 配置跳板机用户管理系统

创建用户管理目录和脚本：

```bash
# 创建跳板机用户基础目录
sudo mkdir -p /etc/jumpserver/users

# 创建跳板机用户管理脚本
sudo tee /usr/local/bin/manage_jump_users.sh << 'EOF'
#!/bin/bash

# 跳板机用户管理脚本

ACTION=$1
USERNAME=$2
EXPIRY_DAYS=$3
QUOTA_SIZE=$4  # 以MB为单位
SSH_KEY=$5
TARGET_HOSTS=$6

USER_CONFIG_DIR="/etc/jumpserver/users"

function create_user() {
    # 检查用户是否已存在
    if id "$USERNAME" &>/dev/null; then
        echo "用户 $USERNAME 已存在"
        return 1
    fi
    
    # 创建用户
    useradd -m "$USERNAME" -G jumpusers
    
    # 设置账户过期时间
    if [ ! -z "$EXPIRY_DAYS" ]; then
        usermod -e $(date -d "+$EXPIRY_DAYS days" +%Y-%m-%d) "$USERNAME"
    fi
    
    # 设置磁盘配额
    if [ ! -z "$QUOTA_SIZE" ]; then
        # 转换为KB
        QUOTA_KB=$(($QUOTA_SIZE * 1024))
        setquota -u "$USERNAME" 0 "$QUOTA_KB" 0 0 -a
    fi
    
    # 设置SSH密钥
    if [ ! -z "$SSH_KEY" ]; then
        mkdir -p /home/"$USERNAME"/.ssh
        echo "$SSH_KEY" > /home/"$USERNAME"/.ssh/authorized_keys
        chmod 700 /home/"$USERNAME"/.ssh
        chmod 600 /home/"$USERNAME"/.ssh/authorized_keys
        chown -R "$USERNAME":"$USERNAME" /home/"$USERNAME"/.ssh
    fi
    
    # 设置访问范围
    if [ ! -z "$TARGET_HOSTS" ]; then
        mkdir -p "$USER_CONFIG_DIR"
        echo "$TARGET_HOSTS" > "$USER_CONFIG_DIR/$USERNAME.hosts"
    fi
    
    echo "用户 $USERNAME 创建成功，过期时间: $(date -d "+$EXPIRY_DAYS days" +%Y-%m-%d), 配额: ${QUOTA_SIZE}MB"
}

function delete_user() {
    # 检查用户是否存在
    if ! id "$USERNAME" &>/dev/null; then
        echo "用户 $USERNAME 不存在"
        return 1
    fi
    
    # 删除用户配置文件
    rm -f "$USER_CONFIG_DIR/$USERNAME.hosts"
    
    # 删除用户
    userdel -r "$USERNAME"
    
    echo "用户 $USERNAME 已删除"
}

function list_users() {
    echo "跳板机用户列表:"
    echo "----------------------------------------"
    echo "用户名 | 过期时间 | 配额(MB) | 目标主机"
    echo "----------------------------------------"
    
    for user_file in "$USER_CONFIG_DIR"/*.hosts; do
        if [ -f "$user_file" ]; then
            user=$(basename "$user_file" .hosts)
            expiry=$(chage -l "$user" | grep "Account expires" | cut -d: -f2)
            quota=$(quota -u "$user" | tail -1 | awk '{print $3/1024}')
            targets=$(cat "$user_file" | tr '\n' ',' | sed 's/,$//')
            echo "$user | $expiry | $quota | $targets"
        fi
    done
}

function modify_user() {
    # 检查用户是否存在
    if ! id "$USERNAME" &>/dev/null; then
        echo "用户 $USERNAME 不存在"
        return 1
    fi
    
    # 更新账户过期时间
    if [ ! -z "$EXPIRY_DAYS" ]; then
        usermod -e $(date -d "+$EXPIRY_DAYS days" +%Y-%m-%d) "$USERNAME"
        echo "用户 $USERNAME 过期时间已更新为: $(date -d "+$EXPIRY_DAYS days" +%Y-%m-%d)"
    fi
    
    # 更新磁盘配额
    if [ ! -z "$QUOTA_SIZE" ]; then
        # 转换为KB
        QUOTA_KB=$(($QUOTA_SIZE * 1024))
        setquota -u "$USERNAME" 0 "$QUOTA_KB" 0 0 -a
        echo "用户 $USERNAME 配额已更新为: ${QUOTA_SIZE}MB"
    fi
    
    # 更新SSH密钥
    if [ ! -z "$SSH_KEY" ]; then
        mkdir -p /home/"$USERNAME"/.ssh
        echo "$SSH_KEY" > /home/"$USERNAME"/.ssh/authorized_keys
        chmod 700 /home/"$USERNAME"/.ssh
        chmod 600 /home/"$USERNAME"/.ssh/authorized_keys
        chown -R "$USERNAME":"$USERNAME" /home/"$USERNAME"/.ssh
        echo "用户 $USERNAME SSH密钥已更新"
    fi
    
    # 更新访问范围
    if [ ! -z "$TARGET_HOSTS" ]; then
        mkdir -p "$USER_CONFIG_DIR"
        echo "$TARGET_HOSTS" > "$USER_CONFIG_DIR/$USERNAME.hosts"
        echo "用户 $USERNAME 目标主机列表已更新"
    fi
}

# 主逻辑
case "$ACTION" in
    create)
        create_user
        ;;
    delete)
        delete_user
        ;;
    list)
        list_users
        ;;
    modify)
        modify_user
        ;;
    *)
        echo "用法: $0 {create|delete|list|modify} [username] [expiry_days] [quota_MB] [ssh_key] [target_hosts]"
        exit 1
        ;;
esac

exit 0
EOF

sudo chmod +x /usr/local/bin/manage_jump_users.sh

# 创建jumpusers组
sudo groupadd jumpusers
```

### 2.3 创建跳板机客户端脚本

此脚本用于控制跳板机用户的访问范围：

```bash
sudo tee /usr/local/bin/jump_client.sh << 'EOF'
#!/bin/bash

# 跳板机客户端脚本

USERNAME=$(whoami)
USER_CONFIG_DIR="/etc/jumpserver/users"
USER_HOSTS_FILE="$USER_CONFIG_DIR/$USERNAME.hosts"
SSH_ORIGINAL_COMMAND="$SSH_ORIGINAL_COMMAND"

# 记录访问日志
function log_access() {
    echo "[$(date)] User: $USERNAME, Command: $1, Target: $2" >> /var/log/jumpserver_access.log
}

# 检查目标主机是否在允许列表中
function check_host_allowed() {
    local target_host=$1
    
    if [ ! -f "$USER_HOSTS_FILE" ]; then
        return 1
    fi
    
    grep -q "^$target_host$" "$USER_HOSTS_FILE"
    return $?
}

# 主逻辑
if [ -z "$SSH_ORIGINAL_COMMAND" ]; then
    echo "欢迎使用跳板机服务。您可以访问以下主机："
    if [ -f "$USER_HOSTS_FILE" ]; then
        cat "$USER_HOSTS_FILE"
    else
        echo "您没有被授权访问任何主机。"
    fi
    exit 0
fi

# 解析SSH命令
if [[ "$SSH_ORIGINAL_COMMAND" =~ ^ssh\ ([^\ ]+) ]]; then
    target=${BASH_REMATCH[1]}
    
    # 检查目标主机是否允许访问
    if check_host_allowed "$target"; then
        log_access "ssh" "$target"
        eval "$SSH_ORIGINAL_COMMAND"
    else
        echo "您没有权限访问主机 $target"
        log_access "DENIED ssh" "$target"
        exit 1
    fi
elif [[ "$SSH_ORIGINAL_COMMAND" =~ ^scp\ (.*) ]]; then
    # SCP命令处理逻辑
    log_access "scp" "${BASH_REMATCH[1]}"
    eval "$SSH_ORIGINAL_COMMAND"
else
    echo "不支持的命令: $SSH_ORIGINAL_COMMAND"
    log_access "DENIED" "$SSH_ORIGINAL_COMMAND"
    exit 1
fi
EOF

sudo chmod +x /usr/local/bin/jump_client.sh
```

### 2.4 配置SSH服务器

配置SSH服务器以支持管理员和跳板机用户：

```bash
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sudo tee -a /etc/ssh/sshd_config << 'EOF'

# 全局SSH配置
AllowTcpForwarding yes
PermitTunnel yes
GatewayPorts no
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
PermitRootLogin no
PasswordAuthentication no
UsePAM yes
LogLevel VERBOSE

# 管理员用户配置
Match User admin_user
    AllowTcpForwarding yes
    X11Forwarding no
    PasswordAuthentication yes

# 全局跳板机用户配置
Match Group jumpusers
    AllowTcpForwarding yes
    PermitTunnel yes
    X11Forwarding no
    PasswordAuthentication no
    ForceCommand /usr/local/bin/jump_client.sh
EOF

sudo systemctl restart sshd
```

## 3. 配置磁盘配额管理

确保配额系统正确配置：

```bash
# 确保配额模块已加载
sudo modprobe quota_v2

# 修改/etc/fstab以启用配额
# 假设/home在单独的分区上
sudo cp /etc/fstab /etc/fstab.bak
sudo sed -i 's/\(.*\/home.*\)/\1,usrquota,grpquota/' /etc/fstab

# 重新挂载/home分区以应用配额
sudo mount -o remount /home

# 创建配额数据库
sudo quotacheck -cum /home
sudo quotaon -v /home
```

## 4. 安全加固

### 4.1 配置防火墙

```bash
# 配置防火墙
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw enable
sudo systemctl enable ufw
sudo systemctl start ufw
```

### 4.2 配置Fail2ban

```bash
# 配置fail2ban
sudo mkdir -p /etc/fail2ban
sudo tee /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = auto

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF

# 确保日志目录存在
sudo mkdir -p /var/log
sudo touch /var/log/auth.log

# 配置journald将SSH日志写入文件
sudo mkdir -p /etc/systemd/journald.conf.d
sudo tee /etc/systemd/journald.conf.d/forward-to-file.conf << 'EOF'
[Journal]
ForwardToSyslog=yes
EOF

# 配置rsyslog将SSH认证日志写入auth.log
sudo tee /etc/rsyslog.d/50-sshd.conf << 'EOF'
auth,authpriv.*                 /var/log/auth.log
EOF

# 启用并启动rsyslog
sudo systemctl enable rsyslog
sudo systemctl start rsyslog

# 重启journald
sudo systemctl restart systemd-journald

# 启用并启动fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

## 5. 监控与自动恢复

### 5.1 创建系统监控脚本

```bash
sudo tee /usr/local/bin/monitor_jumpserver.sh << 'EOF'
#!/bin/bash

LOG_FILE="/var/log/jumpserver_monitor.log"
ADMIN_EMAIL="admin@example.com"

log_and_mail() {
    echo "[$(date)] $1" >> $LOG_FILE
    echo "$1" | mail -s "跳板机监控警报" $ADMIN_EMAIL
}

# 检查SSH服务
if ! systemctl is-active --quiet sshd; then
    log_and_mail "SSH服务已停止! 尝试重启..."
    systemctl restart sshd
    sleep 5
    if ! systemctl is-active --quiet sshd; then
        log_and_mail "SSH服务重启失败!"
    else
        log_and_mail "SSH服务已成功重启"

继续完成监控脚本的内容：

```bash
sudo tee /usr/local/bin/monitor_jumpserver.sh << 'EOF'
#!/bin/bash

LOG_FILE="/var/log/jumpserver_monitor.log"
ADMIN_EMAIL="admin@example.com"

log_and_mail() {
    echo "[$(date)] $1" >> $LOG_FILE
    echo "$1" | mail -s "跳板机监控警报" $ADMIN_EMAIL
}

# 检查SSH服务
if ! systemctl is-active --quiet sshd; then
    log_and_mail "SSH服务已停止! 尝试重启..."
    systemctl restart sshd
    sleep 5
    if ! systemctl is-active --quiet sshd; then
        log_and_mail "SSH服务重启失败!"
    else
        log_and_mail "SSH服务已成功重启"
    fi
fi

# 检查DDNS服务
if ! systemctl is-active --quiet ddclient; then
    log_and_mail "DDNS服务已停止! 尝试重启..."
    systemctl restart ddclient
fi

# 检查系统负载
LOAD=$(uptime | awk -F'[a-z]:' '{ print $2}' | awk '{ print $2}' | sed 's/,//g')
if (( $(echo "$LOAD > 2.0" | bc -l) )); then
    log_and_mail "跳板机负载过高: $LOAD"
fi

# 检查磁盘空间
DISK_USAGE=$(df -h / | tail -1 | awk '{ print $5}' | sed 's/%//g')
if [ "$DISK_USAGE" -gt 85 ]; then
    log_and_mail "跳板机磁盘使用率: $DISK_USAGE%"
fi

# 检查内存使用情况
MEM_FREE=$(free -m | grep Mem | awk '{print $4}')
if [ "$MEM_FREE" -lt 100 ]; then
    log_and_mail "跳板机可用内存不足: ${MEM_FREE}MB"
fi

# 检查网络连接
if ! ping -c 3 8.8.8.8 > /dev/null 2>&1; then
    log_and_mail "跳板机网络连接异常"
    
    # 尝试重启网络服务
    systemctl restart NetworkManager
    sleep 10
    
    if ! ping -c 3 8.8.8.8 > /dev/null 2>&1; then
        log_and_mail "网络服务重启后仍无法连接"
    else
        log_and_mail "网络服务已成功重启"
    fi
fi

# 检查失败登录尝试
FAILED_LOGINS=$(journalctl -u sshd --since="1 hour ago" | grep "Failed password" | wc -l)
if [ "$FAILED_LOGINS" -gt 10 ]; then
    log_and_mail "检测到大量失败登录尝试: $FAILED_LOGINS 次"
fi

# 检查跳板机用户账户过期情况
for user in $(grep -E "^[^:]+:[^:]+:[0-9]{4}:" /etc/passwd | cut -d: -f1); do
    # 跳过系统用户
    if [ $(id -u "$user") -ge 1000 ] && groups "$user" | grep -q "jumpusers"; then
        # 检查账户是否即将过期
        EXPIRY_DATE=$(chage -l "$user" | grep "Account expires" | cut -d: -f2 | xargs)
        if [ "$EXPIRY_DATE" != "never" ]; then
            DAYS_LEFT=$(( ( $(date -d "$EXPIRY_DATE" +%s) - $(date +%s) ) / 86400 ))
            if [ "$DAYS_LEFT" -le 7 ] && [ "$DAYS_LEFT" -ge 0 ]; then
                log_and_mail "用户 $user 账户将在 $DAYS_LEFT 天后过期"
            elif [ "$DAYS_LEFT" -lt 0 ]; then
                log_and_mail "用户 $user 账户已过期"
            fi
        fi
    fi
done

# 检查用户配额使用情况
for user in $(grep -E "^[^:]+:[^:]+:[0-9]{4}:" /etc/passwd | cut -d: -f1); do
    # 跳过系统用户
    if [ $(id -u "$user") -ge 1000 ] && groups "$user" | grep -q "jumpusers"; then
        # 获取配额信息
        QUOTA_INFO=$(quota -u "$user" 2>/dev/null)
        if echo "$QUOTA_INFO" | grep -q "blocks"; then
            USAGE_PERCENT=$(echo "$QUOTA_INFO" | tail -1 | awk '{print $3/$4*100}')
            if (( $(echo "$USAGE_PERCENT > 90" | bc -l) )); then
                log_and_mail "用户 $user 配额使用率超过90%: ${USAGE_PERCENT}%"
            fi
        fi
    fi
done

# 检查重要系统文件权限
if [ "$(stat -c %a /etc/ssh/sshd_config)" != "600" ]; then
    log_and_mail "SSH配置文件权限异常，正在修复..."
    chmod 600 /etc/ssh/sshd_config
fi

# 检查跳板机用户配置文件
for config_file in /etc/jumpserver/users/*.hosts; do
    if [ -f "$config_file" ] && [ "$(stat -c %a "$config_file")" != "600" ]; then
        log_and_mail "跳板机用户配置文件权限异常: $config_file，正在修复..."
        chmod 600 "$config_file"
    fi
done

# 检查CPU温度（如果支持）
if [ -f /sys/class/thermal/thermal_zone0/temp ]; then
    CPU_TEMP=$(cat /sys/class/thermal/thermal_zone0/temp | awk '{print $1/1000}')
    if (( $(echo "$CPU_TEMP > 80.0" | bc -l) )); then
        log_and_mail "CPU温度过高: ${CPU_TEMP}°C"
    fi
fi
EOF

# 设置执行权限
sudo chmod +x /usr/local/bin/monitor_jumpserver.sh
```

### 5.2 配置自动监控和恢复

```bash
# 创建定时任务
sudo tee /etc/cron.d/jumpserver_monitor << 'EOF'
# 每5分钟运行一次监控脚本
*/5 * * * * root /usr/local/bin/monitor_jumpserver.sh >/dev/null 2>&1
EOF

# 创建自动恢复服务
sudo tee /etc/systemd/system/jumpserver-recovery.service << 'EOF'
[Unit]
Description=Jumpserver Recovery Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/monitor_jumpserver.sh
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

# 创建每日检查服务
sudo tee /etc/systemd/system/jumpserver-daily-check.service << 'EOF'
[Unit]
Description=Jumpserver Daily Health Check

[Service]
Type=oneshot
ExecStart=/usr/local/bin/monitor_jumpserver.sh
EOF

sudo tee /etc/systemd/system/jumpserver-daily-check.timer << 'EOF'
[Unit]
Description=Run Jumpserver health check daily

[Timer]
OnCalendar=*-*-* 04:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

# 启用定时器
sudo systemctl enable jumpserver-daily-check.timer
sudo systemctl start jumpserver-daily-check.timer
```

### 5.3 配置状态报告系统

```bash
# 创建系统状态报告脚本
sudo tee /usr/local/bin/jumpserver_status_report.sh << 'EOF'
#!/bin/bash

REPORT_FILE="/tmp/jumpserver_status_report.txt"
ADMIN_EMAIL="admin@example.com"

# 清空报告文件
> $REPORT_FILE

# 添加报告标题
echo "========================================" >> $REPORT_FILE
echo "跳板机状态报告 - $(date)" >> $REPORT_FILE
echo "========================================" >> $REPORT_FILE
echo "" >> $REPORT_FILE

# 系统基本信息
echo "## 系统信息" >> $REPORT_FILE
echo "主机名: $(hostname)" >> $REPORT_FILE
echo "内核版本: $(uname -r)" >> $REPORT_FILE
echo "运行时间: $(uptime -p)" >> $REPORT_FILE
echo "最后启动: $(who -b | awk '{print $3,$4}')" >> $REPORT_FILE
echo "" >> $REPORT_FILE

# 资源使用情况
echo "## 资源使用情况" >> $REPORT_FILE
echo "CPU负载: $(uptime | awk -F'[a-z]:' '{ print $2}')" >> $REPORT_FILE
echo "内存使用:" >> $REPORT_FILE
free -h >> $REPORT_FILE
echo "" >> $REPORT_FILE
echo "磁盘使用:" >> $REPORT_FILE
df -h >> $REPORT_FILE
echo "" >> $REPORT_FILE

# 服务状态
echo "## 服务状态" >> $REPORT_FILE
echo "SSH服务: $(systemctl is-active sshd)" >> $REPORT_FILE
echo "DDNS服务: $(systemctl is-active ddclient)" >> $REPORT_FILE
echo "防火墙服务: $(systemctl is-active ufw)" >> $REPORT_FILE
echo "Fail2ban服务: $(systemctl is-active fail2ban)" >> $REPORT_FILE
echo "" >> $REPORT_FILE

# 网络状态
echo "## 网络状态" >> $REPORT_FILE
echo "IP地址:" >> $REPORT_FILE
ip addr | grep "inet " | grep -v "127.0.0.1" >> $REPORT_FILE
echo "" >> $REPORT_FILE
echo "网络连接:" >> $REPORT_FILE
netstat -tuln | grep LISTEN >> $REPORT_FILE
echo "" >> $REPORT_FILE

# 安全信息
echo "## 安全信息" >> $REPORT_FILE
echo "最近的失败登录尝试:" >> $REPORT_FILE
journalctl -u sshd --since="24 hours ago" | grep "Failed password" | tail -10 >> $REPORT_FILE
echo "" >> $REPORT_FILE
echo "被Fail2ban封禁的IP:" >> $REPORT_FILE
fail2ban-client status sshd | grep "Banned IP list" >> $REPORT_FILE
echo "" >> $REPORT_FILE

# 用户信息
echo "## 用户信息" >> $REPORT_FILE
echo "当前登录用户:" >> $REPORT_FILE
who >> $REPORT_FILE
echo "" >> $REPORT_FILE
echo "最近的用户活动:" >> $REPORT_FILE
last | head -10 >> $REPORT_FILE
echo "" >> $REPORT_FILE

# 跳板机用户状态
echo "## 跳板机用户状态" >> $REPORT_FILE
echo "用户名 | 过期时间 | 配额使用率 | 目标主机" >> $REPORT_FILE
echo "----------------------------------------" >> $REPORT_FILE
for user_file in /etc/jumpserver/users/*.hosts; do
    if [ -f "$user_file" ]; then
        user=$(basename "$user_file" .hosts)
        expiry=$(chage -l "$user" | grep "Account expires" | cut -d: -f2)
        quota_info=$(quota -u "$user" 2>/dev/null | tail -1)
        if [ ! -z "$quota_info" ]; then
            used=$(echo "$quota_info" | awk '{print $3}')
            total=$(echo "$quota_info" | awk '{print $4}')
            if [ "$total" -ne 0 ]; then
                usage_percent=$(echo "scale=2; $used/$total*100" | bc)
            else
                usage_percent="N/A"
            fi
        else
            usage_percent="N/A"
        fi
        targets=$(cat "$user_file" | tr '\n' ',' | sed 's/,$//')
        echo "$user | $expiry | $usage_percent% | $targets" >> $REPORT_FILE
    fi
done
echo "" >> $REPORT_FILE

# 发送报告
cat $REPORT_FILE | mail -s "跳板机每日状态报告 - $(date +%Y-%m-%d)" $ADMIN_EMAIL

# 清理临时文件
rm $REPORT_FILE
EOF

# 设置执行权限
sudo chmod +x /usr/local/bin/jumpserver_status_report.sh

# 创建每日报告定时任务
sudo tee /etc/cron.d/jumpserver_daily_report << 'EOF'
# 每天早上7点发送状态报告
0 7 * * * root /usr/local/bin/jumpserver_status_report.sh >/dev/null 2>&1
EOF
```

### 5.4 配置邮件通知系统

```bash
# 确保邮件服务配置正确
sudo tee /etc/msmtprc << 'EOF'
# 默认设置
defaults
auth           on
tls            on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
logfile        /var/log/msmtp.log

# Gmail账户
account        gmail
host           smtp.gmail.com
port           587
from           your-email@gmail.com
user           your-email@gmail.com
password       your-app-password

# 设置默认账户
account default : gmail
EOF

sudo chmod 600 /etc/msmtprc

# 配置s-nail使用msmtp
sudo tee /etc/mail.rc << 'EOF'
set mta=/usr/bin/msmtp
set sendmail=/usr/bin/msmtp
EOF
```

## 6. 日志和审计系统

### 6.1 配置集中式日志

```bash
# 创建日志目录
sudo mkdir -p /var/log/jumpserver
sudo chmod 755 /var/log/jumpserver

# 配置跳板机访问日志
sudo tee /etc/rsyslog.d/30-jumpserver.conf << 'EOF'
# 跳板机日志
if $programname == 'jumpserver' then /var/log/jumpserver/access.log
& stop
EOF

# 重启rsyslog
sudo systemctl restart rsyslog
```

### 6.2 创建日志分析工具

```bash
sudo tee /usr/local/bin

继续完成日志分析工具的内容：

```bash
sudo tee /usr/local/bin/analyze_jumpserver_logs.sh << 'EOF'
#!/bin/bash

LOG_FILE="/var/log/jumpserver/access.log"
REPORT_FILE="/tmp/jumpserver_log_analysis.txt"
ADMIN_EMAIL="admin@example.com"
DAYS_AGO=7

# 清空报告文件
> $REPORT_FILE

# 添加报告标题
echo "========================================" >> $REPORT_FILE
echo "跳板机日志分析报告 - $(date)" >> $REPORT_FILE
echo "========================================" >> $REPORT_FILE
echo "分析周期: 过去 $DAYS_AGO 天" >> $REPORT_FILE
echo "" >> $REPORT_FILE

# 检查日志文件是否存在
if [ ! -f "$LOG_FILE" ]; then
    echo "错误: 日志文件 $LOG_FILE 不存在!" >> $REPORT_FILE
    cat $REPORT_FILE | mail -s "跳板机日志分析报告 - $(date +%Y-%m-%d)" $ADMIN_EMAIL
    exit 1
fi

# 获取过去N天的日志
SINCE_DATE=$(date -d "$DAYS_AGO days ago" +"%Y-%m-%d")
FILTERED_LOGS=$(grep -a "$SINCE_DATE" $LOG_FILE)

if [ -z "$FILTERED_LOGS" ]; then
    echo "没有找到过去 $DAYS_AGO 天的日志记录" >> $REPORT_FILE
    cat $REPORT_FILE | mail -s "跳板机日志分析报告 - $(date +%Y-%m-%d)" $ADMIN_EMAIL
    exit 0
fi

# 分析用户活动
echo "## 用户活动统计" >> $REPORT_FILE
echo "用户名 | 登录次数 | 最后活动时间" >> $REPORT_FILE
echo "----------------------------------------" >> $REPORT_FILE

echo "$FILTERED_LOGS" | grep "User:" | awk -F'User: ' '{print $2}' | awk '{print $1}' | sort | uniq -c | sort -nr | while read count user; do
    last_activity=$(echo "$FILTERED_LOGS" | grep "User: $user" | tail -1 | awk '{print $1, $2}')
    echo "$user | $count | $last_activity" >> $REPORT_FILE
done
echo "" >> $REPORT_FILE

# 分析目标主机访问
echo "## 目标主机访问统计" >> $REPORT_FILE
echo "目标主机 | 访问次数 | 最后访问时间" >> $REPORT_FILE
echo "----------------------------------------" >> $REPORT_FILE

echo "$FILTERED_LOGS" | grep "Target:" | awk -F'Target: ' '{print $2}' | sort | uniq -c | sort -nr | while read count target; do
    last_access=$(echo "$FILTERED_LOGS" | grep "Target: $target" | tail -1 | awk '{print $1, $2}')
    echo "$target | $count | $last_access" >> $REPORT_FILE
done
echo "" >> $REPORT_FILE

# 分析拒绝访问记录
echo "## 拒绝访问记录" >> $REPORT_FILE
echo "用户名 | 尝试访问的目标 | 时间" >> $REPORT_FILE
echo "----------------------------------------" >> $REPORT_FILE

echo "$FILTERED_LOGS" | grep "DENIED" | while read line; do
    user=$(echo "$line" | awk -F'User: ' '{print $2}' | awk '{print $1}')
    target=$(echo "$line" | awk -F'Target: ' '{print $2}')
    time=$(echo "$line" | awk '{print $1, $2}')
    echo "$user | $target | $time" >> $REPORT_FILE
done
echo "" >> $REPORT_FILE

# 分析异常活动
echo "## 异常活动检测" >> $REPORT_FILE
echo "----------------------------------------" >> $REPORT_FILE

# 检测非工作时间登录
echo "### 非工作时间登录 (18:00-09:00)" >> $REPORT_FILE
echo "$FILTERED_LOGS" | grep -E '([0-1]8|19|2[0-9]|0[0-9]):[0-9]{2}:[0-9]{2}' | head -10 >> $REPORT_FILE
echo "" >> $REPORT_FILE

# 检测短时间内多次登录
echo "### 短时间内多次登录 (5分钟内超过5次)" >> $REPORT_FILE
for user in $(echo "$FILTERED_LOGS" | grep "User:" | awk -F'User: ' '{print $2}' | awk '{print $1}' | sort | uniq); do
    for day in $(echo "$FILTERED_LOGS" | grep "User: $user" | awk '{print $1}' | sort | uniq); do
        for hour in $(seq -w 0 23); do
            for min_base in $(seq -w 0 5 55); do
                # 计算5分钟时间窗口内的登录次数
                count=$(echo "$FILTERED_LOGS" | grep "User: $user" | grep "$day" | grep -E "$hour:($min_base|$((10#$min_base+1))|$((10#$min_base+2))|$((10#$min_base+3))|$((10#$min_base+4)))" | wc -l)
                if [ $count -gt 5 ]; then
                    echo "$user 在 $day $hour:$min_base 附近5分钟内登录了 $count 次" >> $REPORT_FILE
                fi
            done
        done
    done
done
echo "" >> $REPORT_FILE

# 发送报告
cat $REPORT_FILE | mail -s "跳板机日志分析报告 - $(date +%Y-%m-%d)" $ADMIN_EMAIL

# 清理临时文件
rm $REPORT_FILE
EOF

# 设置执行权限
sudo chmod +x /usr/local/bin/analyze_jumpserver_logs.sh

# 创建每周日志分析定时任务
sudo tee /etc/cron.d/jumpserver_log_analysis << 'EOF'
# 每周一早上8点分析日志
0 8 * * 1 root /usr/local/bin/analyze_jumpserver_logs.sh >/dev/null 2>&1
EOF
```

### 6.3 配置日志轮转

```bash
sudo tee /etc/logrotate.d/jumpserver << 'EOF'
/var/log/jumpserver/*.log {
    weekly
    missingok
    rotate 13
    compress
    delaycompress
    notifempty
    create 640 root adm
    sharedscripts
    postrotate
        systemctl reload rsyslog >/dev/null 2>&1 || true
    endscript
}

/var/log/jumpserver_monitor.log {
    weekly
    missingok
    rotate 13
    compress
    delaycompress
    notifempty
    create 640 root adm
}
EOF
```

## 7. 用户活动审计系统

### 7.1 创建会话记录系统

```bash
# 安装必要的工具
sudo pacman -S script

# 创建会话记录目录
sudo mkdir -p /var/log/jumpserver/sessions
sudo chmod 755 /var/log/jumpserver/sessions

# 创建会话记录脚本
sudo tee /usr/local/bin/record_session.sh << 'EOF'
#!/bin/bash

USER=$(whoami)
TARGET=$1
SESSION_ID=$(date +%Y%m%d%H%M%S)-$$
SESSION_LOG="/var/log/jumpserver/sessions/${USER}-${TARGET}-${SESSION_ID}.log"
SESSION_TIMING="/var/log/jumpserver/sessions/${USER}-${TARGET}-${SESSION_ID}.timing"

# 记录会话开始
echo "[$(date)] 用户 $USER 开始访问 $TARGET" | logger -t jumpserver

# 记录会话
script -q -t 2>"$SESSION_TIMING" -a "$SESSION_LOG" -c "ssh $TARGET"

# 记录会话结束
echo "[$(date)] 用户 $USER 结束访问 $TARGET" | logger -t jumpserver

# 设置适当的权限
chmod 640 "$SESSION_LOG" "$SESSION_TIMING"
EOF

sudo chmod +x /usr/local/bin/record_session.sh

# 修改跳板机客户端脚本以使用会话记录
sudo sed -i 's|eval "$SSH_ORIGINAL_COMMAND"|/usr/local/bin/record_session.sh "$target"|g' /usr/local/bin/jump_client.sh
```

### 7.2 创建会话回放工具

```bash
sudo tee /usr/local/bin/replay_session.sh << 'EOF'
#!/bin/bash

SESSION_FILE=$1

if [ -z "$SESSION_FILE" ]; then
    echo "用法: $0 <会话日志文件>"
    exit 1
fi

# 检查文件是否存在
if [ ! -f "$SESSION_FILE" ]; then
    echo "错误: 会话日志文件 $SESSION_FILE 不存在"
    exit 1
fi

# 检查对应的timing文件是否存在
TIMING_FILE="${SESSION_FILE%.log}.timing"
if [ ! -f "$TIMING_FILE" ]; then
    echo "错误: 会话时序文件 $TIMING_FILE 不存在"
    exit 1
fi

# 回放会话
scriptreplay --timing="$TIMING_FILE" "$SESSION_FILE"
EOF

sudo chmod +x /usr/local/bin/replay_session.sh

# 创建会话列表工具
sudo tee /usr/local/bin/list_sessions.sh << 'EOF'
#!/bin/bash

SESSIONS_DIR="/var/log/jumpserver/sessions"
DAYS_AGO=${1:-7}

echo "========================================="
echo "过去 $DAYS_AGO 天的跳板机会话记录"
echo "========================================="
echo "用户名 | 目标主机 | 会话时间 | 会话长度"
echo "-----------------------------------------"

find "$SESSIONS_DIR" -name "*.log" -mtime -$DAYS_AGO | sort | while read session_file; do
    # 提取信息
    filename=$(basename "$session_file")
    user=$(echo "$filename" | cut -d'-' -f1)
    target=$(echo "$filename" | cut -d'-' -f2)
    timestamp=$(echo "$filename" | cut -d'-' -f3 | cut -d'.' -f1)
    session_date=$(date -d "${timestamp:0:8} ${timestamp:8:2}:${timestamp:10:2}:${timestamp:12:2}" "+%Y-%m-%d %H:%M:%S")
    
    # 计算会话长度
    timing_file="${session_file%.log}.timing"
    if [ -f "$timing_file" ]; then
        # 计算会话总时长（秒）
        duration=$(awk 'BEGIN{sum=0} {sum+=$1} END{print sum}' "$timing_file")
        # 格式化为可读时间
        duration_fmt=$(printf "%02d:%02d:%02d" $((duration/3600)) $((duration%3600/60)) $((duration%60)))
    else
        duration_fmt="未知"
    fi
    
    echo "$user | $target | $session_date | $duration_fmt"
done
EOF

sudo chmod +x /usr/local/bin/list_sessions.sh
```

## 8. 用户配额和限制管理

### 8.1 创建配额管理工具

```bash
sudo tee /usr/local/bin/manage_quotas.sh << 'EOF'
#!/bin/bash

ACTION=$1
USERNAME=$2
QUOTA_SIZE=$3  # 以MB为单位

function show_usage() {
    echo "用法: $0 {set|show|check} [username] [quota_size_MB]"
    echo "  set   - 设置用户配额"
    echo "  show  - 显示用户配额"
    echo "  check - 检查所有用户配额使用情况"
}

function set_quota() {
    # 检查用户是否存在
    if ! id "$USERNAME" &>/dev/null; then
        echo "错误: 用户 $USERNAME 不存在"
        return 1
    fi
    
    # 检查配额大小是否有效
    if ! [[ "$QUOTA_SIZE" =~ ^[0-9]+$ ]]; then
        echo "错误: 配额大小必须是整数"
        return 1
    fi
    
    # 转换为KB
    QUOTA_KB=$(($QUOTA_SIZE * 1024))
    
    # 设置配额
    setquota -u "$USERNAME" 0 "$QUOTA_KB" 0 0 -a
    
    echo "已为用户 $USERNAME 设置 ${QUOTA_SIZE}MB 的磁盘配额"
}

function show_quota() {
    # 检查用户是否存在
    if ! id "$USERNAME" &>/dev/null; then
        echo "错误: 用户 $USERNAME 不存在"
        return 1
    fi
    
    # 显示配额
    echo "用户 $USERNAME 的配额信息:"
    quota -u "$USERNAME"
}

function check_quotas() {
    echo "========================================="
    echo "用户配额使用情况"
    echo "========================================="
    echo "用户名 | 已用空间 | 配额限制 | 使用率"
    echo "-----------------------------------------"
    
    for user in $(grep -E "^[^:]+:[^:]+:[0-9]{4}:" /etc/passwd | cut -d: -f1); do
        # 跳过系统用户
        if [ $(id -u "$user") -ge 1000 ]; then
            quota_info=$(quota -u "$user" 2>/dev/null | tail -1)
            if [ ! -z "$quota_info" ]; then
                used=$(echo "$quota_info" | awk '{print $2}')
                total=$(echo "$quota_info" | awk '{print $3}')
                
                # 转换为MB
                used_mb=$(echo "scale=2; $used/1024" | bc)
                total_mb=$(echo "scale=2; $total/1024" | bc)
                
                if [ "$total" -ne 0 ]; then
                    usage_percent=$(echo "scale=2; $used/$total*100" | bc)
                    echo "$user | ${used_mb}MB | ${total_mb}MB | ${usage_percent}%"
                else
                    echo "$user | ${used_mb}MB | 无限制 | N/A"
                fi
            else
                echo "$user | 无配额信息 | 无限制 | N/A"
            fi

继续完成用户配额和限制管理工具的内容：

```bash
        fi
    fi
done
}

# 主逻辑
case "$ACTION" in
    set)
        if [ -z "$USERNAME" ] || [ -z "$QUOTA_SIZE" ]; then
            show_usage
            exit 1
        fi
        set_quota
        ;;
    show)
        if [ -z "$USERNAME" ]; then
            show_usage
            exit 1
        fi
        show_quota
        ;;
    check)
        check_quotas
        ;;
    *)
        show_usage
        exit 1
        ;;
esac
EOF

# 设置执行权限
sudo chmod +x /usr/local/bin/manage_quotas.sh
```

### 8.2 配置连接限制

```bash
# 创建连接限制配置文件
sudo tee /etc/security/limits.d/jumpserver.conf << 'EOF'
# 限制跳板机用户的最大进程数
@jumpusers        soft    nproc           50
@jumpusers        hard    nproc           100

# 限制跳板机用户的最大文件打开数
@jumpusers        soft    nofile          1024
@jumpusers        hard    nofile          2048

# 限制跳板机用户的最大登录会话数
@jumpusers        soft    maxlogins       3
@jumpusers        hard    maxlogins       5

# 限制跳板机用户的CPU时间
@jumpusers        soft    cpu             600
@jumpusers        hard    cpu             1200

# 限制跳板机用户的最大内存使用
@jumpusers        soft    as              1048576
@jumpusers        hard    as              2097152
EOF

# 创建连接限制监控脚本
sudo tee /usr/local/bin/check_connection_limits.sh << 'EOF'
#!/bin/bash

LOG_FILE="/var/log/jumpserver/connection_limits.log"
ADMIN_EMAIL="admin@example.com"

# 检查每个跳板机用户的连接数
echo "=========================================" >> $LOG_FILE
echo "跳板机用户连接数检查 - $(date)" >> $LOG_FILE
echo "=========================================" >> $LOG_FILE

for user in $(grep -E "^[^:]+:[^:]+:[0-9]{4}:" /etc/passwd | cut -d: -f1); do
    # 跳过系统用户
    if [ $(id -u "$user") -ge 1000 ] && groups "$user" | grep -q "jumpusers"; then
        # 获取当前连接数
        connections=$(who | grep "^$user " | wc -l)
        
        # 获取用户的maxlogins限制
        max_logins=$(grep "^@jumpusers.*maxlogins" /etc/security/limits.d/jumpserver.conf | awk '{print $4}' | head -1)
        
        echo "用户: $user, 当前连接数: $connections, 最大允许: $max_logins" >> $LOG_FILE
        
        # 检查是否接近限制
        if [ $connections -ge $(($max_logins - 1)) ]; then
            echo "[警告] 用户 $user 的连接数 ($connections) 接近或达到最大限制 ($max_logins)" >> $LOG_FILE
            echo "用户 $user 的连接数 ($connections) 接近或达到最大限制 ($max_logins)" | mail -s "跳板机连接限制警告" $ADMIN_EMAIL
        fi
    fi
done

# 检查每个跳板机用户的进程数
echo "" >> $LOG_FILE
echo "用户进程数检查:" >> $LOG_FILE
for user in $(grep -E "^[^:]+:[^:]+:[0-9]{4}:" /etc/passwd | cut -d: -f1); do
    # 跳过系统用户
    if [ $(id -u "$user") -ge 1000 ] && groups "$user" | grep -q "jumpusers"; then
        # 获取当前进程数
        processes=$(ps -u "$user" --no-headers | wc -l)
        
        # 获取用户的nproc限制
        max_processes=$(grep "^@jumpusers.*nproc" /etc/security/limits.d/jumpserver.conf | awk '{print $4}' | head -1)
        
        echo "用户: $user, 当前进程数: $processes, 最大允许: $max_processes" >> $LOG_FILE
        
        # 检查是否接近限制
        if [ $processes -ge $(($max_processes * 80 / 100)) ]; then
            echo "[警告] 用户 $user 的进程数 ($processes) 接近最大限制 ($max_processes)" >> $LOG_FILE
            echo "用户 $user 的进程数 ($processes) 接近最大限制 ($max_processes)" | mail -s "跳板机进程限制警告" $ADMIN_EMAIL
        fi
    fi
done
EOF

sudo chmod +x /usr/local/bin/check_connection_limits.sh

# 创建定时任务
sudo tee /etc/cron.d/jumpserver_connection_limits << 'EOF'
# 每小时检查一次连接限制
0 * * * * root /usr/local/bin/check_connection_limits.sh >/dev/null 2>&1
EOF
```

## 9. 跳板机维护工具

### 9.1 创建系统维护脚本

```bash
sudo tee /usr/local/bin/jumpserver_maintenance.sh << 'EOF'
#!/bin/bash

LOG_FILE="/var/log/jumpserver/maintenance.log"
ADMIN_EMAIL="admin@example.com"

log_message() {
    echo "[$(date)] $1" >> $LOG_FILE
    echo "$1"
}

# 创建日志目录
mkdir -p /var/log/jumpserver

log_message "========================================="
log_message "开始跳板机系统维护 - $(date)"
log_message "========================================="

# 1. 更新系统
log_message "正在更新系统..."
pacman -Syu --noconfirm >> $LOG_FILE 2>&1
if [ $? -eq 0 ]; then
    log_message "系统更新完成"
else
    log_message "系统更新失败，请检查日志"
    echo "跳板机系统更新失败，请检查日志" | mail -s "跳板机维护警告" $ADMIN_EMAIL
fi

# 2. 清理旧的日志文件
log_message "正在清理旧的日志文件..."
find /var/log -name "*.gz" -mtime +30 -delete
find /var/log/jumpserver/sessions -name "*.log" -mtime +90 -delete
find /var/log/jumpserver/sessions -name "*.timing" -mtime +90 -delete

# 3. 检查系统服务状态
log_message "检查系统服务状态..."
services=("sshd" "fail2ban" "ddclient" "rsyslog" "crond")
for service in "${services[@]}"; do
    if ! systemctl is-active --quiet $service; then
        log_message "警告: $service 服务未运行，尝试启动..."
        systemctl start $service
        if ! systemctl is-active --quiet $service; then
            log_message "错误: 无法启动 $service 服务"
            echo "跳板机服务 $service 无法启动" | mail -s "跳板机维护警告" $ADMIN_EMAIL
        else
            log_message "$service 服务已成功启动"
        fi
    else
        log_message "$service 服务正常运行"
    fi
done

# 4. 检查磁盘健康状态
log_message "检查磁盘健康状态..."
if command -v smartctl &> /dev/null; then
    for disk in $(lsblk -d -o name | grep -v "NAME\|loop\|sr"); do
        log_message "检查磁盘 $disk..."
        smart_status=$(smartctl -H /dev/$disk | grep "overall-health" || echo "无法获取健康状态")
        log_message "磁盘 $disk 状态: $smart_status"
        
        if echo "$smart_status" | grep -q "FAILED"; then
            log_message "警告: 磁盘 $disk 健康检查失败!"
            echo "跳板机磁盘 $disk 健康检查失败，请尽快检查" | mail -s "跳板机磁盘警告" $ADMIN_EMAIL
        fi
    done
else
    log_message "smartctl 工具未安装，跳过磁盘健康检查"
fi

# 5. 备份重要配置文件
log_message "备份重要配置文件..."
BACKUP_DIR="/var/backups/jumpserver/$(date +%Y%m%d)"
mkdir -p $BACKUP_DIR

# 备份SSH配置
cp -a /etc/ssh $BACKUP_DIR/
# 备份用户配置
cp -a /etc/jumpserver $BACKUP_DIR/
# 备份防火墙配置
cp -a /etc/ufw $BACKUP_DIR/
# 备份fail2ban配置
cp -a /etc/fail2ban $BACKUP_DIR/

# 压缩备份
tar -czf $BACKUP_DIR.tar.gz $BACKUP_DIR
rm -rf $BACKUP_DIR

log_message "配置备份完成: $BACKUP_DIR.tar.gz"

# 6. 清理旧的备份文件
find /var/backups/jumpserver -name "*.tar.gz" -mtime +30 -delete

# 7. 检查和清理临时文件
log_message "清理临时文件..."
find /tmp -type f -atime +7 -delete 2>/dev/null
find /var/tmp -type f -atime +7 -delete 2>/dev/null

# 8. 检查用户账户过期情况
log_message "检查用户账户过期情况..."
for user in $(grep -E "^[^:]+:[^:]+:[0-9]{4}:" /etc/passwd | cut -d: -f1); do
    # 跳过系统用户
    if [ $(id -u "$user") -ge 1000 ] && groups "$user" | grep -q "jumpusers"; then
        # 检查账户是否即将过期
        EXPIRY_DATE=$(chage -l "$user" | grep "Account expires" | cut -d: -f2 | xargs)
        if [ "$EXPIRY_DATE" != "never" ]; then
            DAYS_LEFT=$(( ( $(date -d "$EXPIRY_DATE" +%s) - $(date +%s) ) / 86400 ))
            if [ "$DAYS_LEFT" -le 14 ] && [ "$DAYS_LEFT" -ge 0 ]; then
                log_message "用户 $user 账户将在 $DAYS_LEFT 天后过期"
                echo "用户 $user 账户将在 $DAYS_LEFT 天后过期" | mail -s "跳板机用户过期提醒" $ADMIN_EMAIL
            elif [ "$DAYS_LEFT" -lt 0 ]; then
                log_message "用户 $user 账户已过期"
            fi
        fi
    fi
done

# 9. 优化系统
log_message "执行系统优化..."
# 清理软件包缓存
pacman -Sc --noconfirm >> $LOG_FILE 2>&1
# 更新locate数据库
updatedb >> $LOG_FILE 2>&1

log_message "========================================="
log_message "跳板机系统维护完成 - $(date)"
log_message "========================================="

# 发送维护报告
cat $LOG_FILE | mail -s "跳板机系统维护报告 - $(date +%Y-%m-%d)" $ADMIN_EMAIL
EOF

sudo chmod +x /usr/local/bin/jumpserver_maintenance.sh

# 创建每周维护定时任务
sudo tee /etc/cron.d/jumpserver_maintenance << 'EOF'
# 每周日凌晨3点执行系统维护
0 3 * * 0 root /usr/local/bin/jumpserver_maintenance.sh >/dev/null 2>&1
EOF
```

### 9.2 创建用户管理工具

```bash
sudo tee /usr/local/bin/manage_jumpusers.sh << 'EOF'
#!/bin/bash

ACTION=$1
USERNAME=$2
EXPIRY_DAYS=$3
TARGET_HOSTS=$4

function show_usage() {
    echo "用法: $0 {add|remove|extend|list|targets} [username] [expiry_days] [target_hosts]"
    echo "  add     - 添加新的跳板机用户"
    echo "  remove  - 删除跳板机用户"
    echo "  extend  - 延长用户账户有效期"
    echo "  list    - 列出所有跳板机用户"
    echo "  targets - 管理用户可访问的目标主机"
    echo ""
    echo "例子:"
    echo "  $0 add testuser 30 'server1,server2'"
    echo "  $0 extend testuser 15"
    echo "  $0 targets testuser 'server1,server2,server3'"
}

function add_user() {
    # 检查用户是否已存在
    if id "$USERNAME" &>/dev/null; then
        echo "错误: 用户 $USERNAME 已存在"
        return 1
    fi
    
    # 检查有效期是否有效
    if ! [[ "$EXPIRY_DAYS" =~ ^[0-9]+$ ]]; then
        echo "错误: 有效期必须是整数天数"
        return 1
    fi
    
    # 创建用户
    useradd -m -G jumpusers -s /usr/local/bin/jump_client.sh "$USERNAME"
    
    # 设置随机密码
    TEMP_PASSWORD=$(openssl rand -base64 12)
    echo "$USERNAME:$TEMP_PASSWORD" | chpasswd
    
    # 要求用户首次登录时更改密码
    passwd -e "$USERNAME"
    
    # 设置账户过期时间
    EXPIRY_DATE=$(date -d "+$EXPIRY_DAYS days" +"%Y-%m-%d")
    usermod -e "$EXPIRY_DATE" "$USERNAME"
    
    # 创建用户配置目录
    mkdir -p /etc/jumpserver/users
    
    # 设置目标主机
    if [ ! -z "$TARGET_HOSTS" ]; then
        echo "$TARGET_HOSTS" | tr ',' '\n' > "/etc/jumpserver/users/${USERNAME}.

继续完成用户管理工具的内容：

```bash
        echo "$TARGET_HOSTS" | tr ',' '\n' > "/etc/jumpserver/users/${USERNAME}.targets"
    fi
    
    echo "用户 $USERNAME 已成功创建"
    echo "临时密码: $TEMP_PASSWORD"
    echo "账户有效期至: $EXPIRY_DATE"
    echo "用户首次登录时将被要求更改密码"
}

function remove_user() {
    # 检查用户是否存在
    if ! id "$USERNAME" &>/dev/null; then
        echo "错误: 用户 $USERNAME 不存在"
        return 1
    fi
    
    # 删除用户
    userdel -r "$USERNAME"
    
    # 删除用户配置
    rm -f "/etc/jumpserver/users/${USERNAME}.targets"
    
    echo "用户 $USERNAME 已成功删除"
}

function extend_user() {
    # 检查用户是否存在
    if ! id "$USERNAME" &>/dev/null; then
        echo "错误: 用户 $USERNAME 不存在"
        return 1
    fi
    
    # 检查有效期是否有效
    if ! [[ "$EXPIRY_DAYS" =~ ^[0-9]+$ ]]; then
        echo "错误: 有效期必须是整数天数"
        return 1
    fi
    
    # 获取当前过期日期
    CURRENT_EXPIRY=$(chage -l "$USERNAME" | grep "Account expires" | cut -d: -f2 | xargs)
    
    # 计算新的过期日期
    if [ "$CURRENT_EXPIRY" = "never" ]; then
        NEW_EXPIRY=$(date -d "+$EXPIRY_DAYS days" +"%Y-%m-%d")
    else
        NEW_EXPIRY=$(date -d "$CURRENT_EXPIRY +$EXPIRY_DAYS days" +"%Y-%m-%d")
    fi
    
    # 设置新的过期日期
    usermod -e "$NEW_EXPIRY" "$USERNAME"
    
    echo "用户 $USERNAME 的账户有效期已延长 $EXPIRY_DAYS 天"
    echo "新的有效期至: $NEW_EXPIRY"
}

function list_users() {
    echo "========================================="
    echo "跳板机用户列表"
    echo "========================================="
    echo "用户名 | 账户状态 | 有效期至 | 可访问目标"
    echo "-----------------------------------------"
    
    for user in $(grep -E "^[^:]+:[^:]+:[0-9]{4}:" /etc/passwd | cut -d: -f1); do
        # 跳过系统用户
        if [ $(id -u "$user") -ge 1000 ] && groups "$user" | grep -q "jumpusers"; then
            # 获取账户状态
            ACCOUNT_STATUS="活跃"
            if passwd -S "$user" | grep -q "L"; then
                ACCOUNT_STATUS="已锁定"
            fi
            
            # 获取过期日期
            EXPIRY_DATE=$(chage -l "$user" | grep "Account expires" | cut -d: -f2 | xargs)
            if [ "$EXPIRY_DATE" = "never" ]; then
                EXPIRY_DATE="永不过期"
            fi
            
            # 获取可访问目标
            TARGETS_FILE="/etc/jumpserver/users/${user}.targets"
            if [ -f "$TARGETS_FILE" ]; then
                TARGETS=$(cat "$TARGETS_FILE" | tr '\n' ',' | sed 's/,$//')
            else
                TARGETS="无"
            fi
            
            echo "$user | $ACCOUNT_STATUS | $EXPIRY_DATE | $TARGETS"
        fi
    done
}

function manage_targets() {
    # 检查用户是否存在
    if ! id "$USERNAME" &>/dev/null; then
        echo "错误: 用户 $USERNAME 不存在"
        return 1
    fi
    
    # 创建用户配置目录
    mkdir -p /etc/jumpserver/users
    
    # 设置目标主机
    if [ -z "$TARGET_HOSTS" ]; then
        # 显示当前目标
        TARGETS_FILE="/etc/jumpserver/users/${USERNAME}.targets"
        if [ -f "$TARGETS_FILE" ]; then
            echo "用户 $USERNAME 当前可访问的目标主机:"
            cat "$TARGETS_FILE"
        else
            echo "用户 $USERNAME 当前没有配置可访问的目标主机"
        fi
    else
        # 更新目标
        echo "$TARGET_HOSTS" | tr ',' '\n' > "/etc/jumpserver/users/${USERNAME}.targets"
        echo "用户 $USERNAME 可访问的目标主机已更新"
    fi
}

# 主逻辑
case "$ACTION" in
    add)
        if [ -z "$USERNAME" ] || [ -z "$EXPIRY_DAYS" ]; then
            show_usage
            exit 1
        fi
        add_user
        ;;
    remove)
        if [ -z "$USERNAME" ]; then
            show_usage
            exit 1
        fi
        remove_user
        ;;
    extend)
        if [ -z "$USERNAME" ] || [ -z "$EXPIRY_DAYS" ]; then
            show_usage
            exit 1
        fi
        extend_user
        ;;
    list)
        list_users
        ;;
    targets)
        if [ -z "$USERNAME" ]; then
            show_usage
            exit 1
        fi
        manage_targets
        ;;
    *)
        show_usage
        exit 1
        ;;
esac
EOF

# 设置执行权限
sudo chmod +x /usr/local/bin/manage_jumpusers.sh
```

## 10. 安全加固与最佳实践

### 10.1 配置定期安全扫描

```bash
# 安装必要的安全工具
sudo pacman -S --noconfirm lynis rkhunter clamav

# 更新ClamAV病毒库
sudo freshclam

# 创建安全扫描脚本
sudo tee /usr/local/bin/security_scan.sh << 'EOF'
#!/bin/bash

LOG_DIR="/var/log/jumpserver/security"
REPORT_FILE="$LOG_DIR/security_scan_$(date +%Y%m%d).txt"
ADMIN_EMAIL="admin@example.com"

# 创建日志目录
mkdir -p $LOG_DIR

# 清空报告文件
> $REPORT_FILE

echo "=========================================" >> $REPORT_FILE
echo "跳板机安全扫描报告 - $(date)" >> $REPORT_FILE
echo "=========================================" >> $REPORT_FILE
echo "" >> $REPORT_FILE

# 运行Lynis系统安全审计
echo "## Lynis系统安全审计" >> $REPORT_FILE
echo "----------------------------------------" >> $REPORT_FILE
lynis audit system --no-colors --quiet >> $REPORT_FILE 2>&1
echo "" >> $REPORT_FILE

# 提取Lynis警告和建议
echo "## Lynis警告和建议摘要" >> $REPORT_FILE
echo "----------------------------------------" >> $REPORT_FILE
grep -E "^(Warning|Suggestion):" $REPORT_FILE >> $REPORT_FILE.summary
cat $REPORT_FILE.summary >> $REPORT_FILE
rm $REPORT_FILE.summary
echo "" >> $REPORT_FILE

# 运行Rootkit检查
echo "## Rootkit检查 (rkhunter)" >> $REPORT_FILE
echo "----------------------------------------" >> $REPORT_FILE
rkhunter --update
rkhunter --check --skip-keypress --quiet >> $REPORT_FILE 2>&1
echo "" >> $REPORT_FILE

# 提取rkhunter警告
echo "## Rootkit检查警告摘要" >> $REPORT_FILE
echo "----------------------------------------" >> $REPORT_FILE
grep -i "warning" /var/log/rkhunter.log | tail -20 >> $REPORT_FILE
echo "" >> $REPORT_FILE

# 检查失败的登录尝试
echo "## 失败的登录尝试" >> $REPORT_FILE
echo "----------------------------------------" >> $REPORT_FILE
grep "Failed password" /var/log/auth.log | tail -20 >> $REPORT_FILE
echo "" >> $REPORT_FILE

# 检查可疑的进程
echo "## 可疑进程检查" >> $REPORT_FILE
echo "----------------------------------------" >> $REPORT_FILE
echo "以root权限运行的非系统进程:" >> $REPORT_FILE
ps aux | grep "^root" | grep -v "^root.*\[" | grep -v -E "^root.*(systemd|init|cron|sshd|rsyslogd|fail2ban)" >> $REPORT_FILE
echo "" >> $REPORT_FILE

# 检查开放端口
echo "## 开放网络端口" >> $REPORT_FILE
echo "----------------------------------------" >> $REPORT_FILE
ss -tuln >> $REPORT_FILE
echo "" >> $REPORT_FILE

# 检查最近修改的系统文件
echo "## 最近24小时内修改的系统文件" >> $REPORT_FILE
echo "----------------------------------------" >> $REPORT_FILE
find /bin /sbin /usr/bin /usr/sbin -type f -mtime -1 -ls >> $REPORT_FILE
echo "" >> $REPORT_FILE

# 运行病毒扫描
echo "## ClamAV病毒扫描" >> $REPORT_FILE
echo "----------------------------------------" >> $REPORT_FILE
clamscan -r --quiet /home /var/www /tmp >> $REPORT_FILE 2>&1
echo "" >> $REPORT_FILE

# 发送报告
cat $REPORT_FILE | mail -s "跳板机安全扫描报告 - $(date +%Y-%m-%d)" $ADMIN_EMAIL

# 保留最近30天的报告
find $LOG_DIR -name "security_scan_*.txt" -mtime +30 -delete
EOF

sudo chmod +x /usr/local/bin/security_scan.sh

# 创建每周安全扫描定时任务
sudo tee /etc/cron.d/jumpserver_security_scan << 'EOF'
# 每周六凌晨2点执行安全扫描
0 2 * * 6 root /usr/local/bin/security_scan.sh >/dev/null 2>&1
EOF
```

### 10.2 创建安全基线检查工具

```bash
sudo tee /usr/local/bin/security_baseline.sh << 'EOF'
#!/bin/bash

LOG_FILE="/var/log/jumpserver/security/baseline_$(date +%Y%m%d).txt"
ADMIN_EMAIL="admin@example.com"

# 创建日志目录
mkdir -p $(dirname $LOG_FILE)

# 清空日志文件
> $LOG_FILE

log_check() {
    local check_name=$1
    local status=$2
    local details=$3
    
    echo "[$status] $check_name" >> $LOG_FILE
    if [ ! -z "$details" ]; then
        echo "     $details" >> $LOG_FILE
    fi
    echo "" >> $LOG_FILE
}

echo "=========================================" >> $LOG_FILE
echo "跳板机安全基线检查 - $(date)" >> $LOG_FILE
echo "=========================================" >> $LOG_FILE
echo "" >> $LOG_FILE

# 检查SSH配置
echo "## SSH配置检查" >> $LOG_FILE
echo "----------------------------------------" >> $LOG_FILE

# 检查SSH根登录
if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config; then
    log_check "禁止Root登录" "通过" "已正确配置禁止Root用户直接登录"
else
    log_check "禁止Root登录" "失败" "应设置 PermitRootLogin no"
fi

# 检查SSH密码认证
if grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config; then
    log_check "禁止密码认证" "通过" "已正确配置禁止密码认证，仅允许密钥认证"
else
    log_check "禁止密码认证" "失败" "应设置 PasswordAuthentication no"
fi

# 检查SSH空闲超时
if grep -q "^ClientAliveInterval" /etc/ssh/sshd_config && grep -q "^ClientAliveCountMax" /etc/ssh/sshd_config; then
    log_check "SSH空闲超时" "通过" "已配置SSH会话超时设置"
else
    log_check "SSH空闲超时" "失败" "应设置 ClientAliveInterval 和 ClientAliveCountMax"
fi

# 检查防火墙状态
echo "" >> $LOG_FILE
echo "## 防火墙检查" >> $LOG_FILE
echo "----------------------------------------" >> $LOG_FILE

if systemctl is-active --quiet ufw; then
    log_check "防火墙状态" "通过" "UFW防火墙已启用"
    
    # 检查SSH端口是否受限
    if ufw status | grep -q "22/tcp.*ALLOW"; then
        if ufw status | grep -q "22/tcp.*ALLOW.*Anywhere"; then
            log_check "SSH访问限制" "失败" "SSH端口允许从任何地址访问，应限制来源IP"
        else
            log_check "SSH访问限制" "通过" "SSH端口已限制访问来源"
        fi
    else
        log_check "SSH访问限制" "失败" "未找到SSH端口放行规则"
    fi
else
    log_check "防火墙状态" "失败" "UFW防火墙未启用"
fi

# 检查系统更新
echo "" >> $LOG_FILE
echo "## 系统更新检查" >> $LOG_FILE
echo "----------------------------------------" >> $LOG_FILE

updates_available=$(pacman -Qu | wc -l)
if [ $updates_available -eq 0 ]; then
    log_check "系统更新" "通过" "系统已是最新状态"
else
    log_check "系统更新" "失败" "有 $updates_available 个可用更新"
fi

# 检查密码策略
echo "" >> $LOG_FILE
echo "## 密码策略检查" >> $LOG_FILE
echo "----------------------------------------" >> $LOG_FILE

if [ -f /etc/security/pwquality.conf ]; then
    min_length=$(grep "^minlen" /etc/security/pwquality.conf | awk '{print $3}')
    if [ ! -z "$min_length" ] && [ $min_length -ge 12 ]; then
        log_check "密码长度要求" "通过" "已设置最小密码长度

继续完成安全基线检查工具的内容：

```bash
        log_check "密码长度要求" "通过" "已设置最小密码长度为 $min_length"
    else
        log_check "密码长度要求" "失败" "最小密码长度应设置为12或更高"
    fi
    
    # 检查密码复杂度
    if grep -q "^dcredit.*-1" /etc/security/pwquality.conf && \
       grep -q "^ucredit.*-1" /etc/security/pwquality.conf && \
       grep -q "^lcredit.*-1" /etc/security/pwquality.conf && \
       grep -q "^ocredit.*-1" /etc/security/pwquality.conf; then
        log_check "密码复杂度要求" "通过" "已设置密码必须包含数字、大小写字母和特殊字符"
    else
        log_check "密码复杂度要求" "失败" "应设置密码必须包含数字、大小写字母和特殊字符"
    fi
else
    log_check "密码策略" "失败" "未找到密码质量配置文件"
fi

# 检查账户锁定策略
echo "" >> $LOG_FILE
echo "## 账户锁定策略检查" >> $LOG_FILE
echo "----------------------------------------" >> $LOG_FILE

if [ -f /etc/pam.d/system-login ] && grep -q "pam_tally2.so" /etc/pam.d/system-login; then
    deny_count=$(grep "pam_tally2.so" /etc/pam.d/system-login | grep -o "deny=[0-9]*" | cut -d= -f2)
    if [ ! -z "$deny_count" ] && [ $deny_count -le 5 ]; then
        log_check "账户锁定策略" "通过" "已配置 $deny_count 次失败尝试后锁定账户"
    else
        log_check "账户锁定策略" "失败" "应设置5次或更少的失败尝试后锁定账户"
    fi
else
    log_check "账户锁定策略" "失败" "未配置账户锁定策略"
fi

# 检查日志配置
echo "" >> $LOG_FILE
echo "## 日志配置检查" >> $LOG_FILE
echo "----------------------------------------" >> $LOG_FILE

if systemctl is-active --quiet rsyslog; then
    log_check "系统日志服务" "通过" "rsyslog服务已启用"
else
    log_check "系统日志服务" "失败" "rsyslog服务未启用"
fi

# 检查重要日志文件权限
log_files=("/var/log/auth.log" "/var/log/syslog" "/var/log/messages")
for log_file in "${log_files[@]}"; do
    if [ -f "$log_file" ]; then
        permissions=$(stat -c "%a" "$log_file")
        if [ "$permissions" = "600" ] || [ "$permissions" = "640" ]; then
            log_check "日志文件权限 ($log_file)" "通过" "权限设置正确: $permissions"
        else
            log_check "日志文件权限 ($log_file)" "失败" "权限应为600或640，当前为: $permissions"
        fi
    fi
done

# 检查文件系统权限
echo "" >> $LOG_FILE
echo "## 文件系统权限检查" >> $LOG_FILE
echo "----------------------------------------" >> $LOG_FILE

# 检查重要目录权限
critical_dirs=("/etc/ssh" "/etc/pam.d" "/etc/security" "/etc/jumpserver")
for dir in "${critical_dirs[@]}"; do
    if [ -d "$dir" ]; then
        permissions=$(stat -c "%a" "$dir")
        if [ "$permissions" = "755" ] || [ "$permissions" = "750" ]; then
            log_check "目录权限 ($dir)" "通过" "权限设置正确: $permissions"
        else
            log_check "目录权限 ($dir)" "失败" "权限应为755或750，当前为: $permissions"
        fi
    fi
done

# 检查SUID/SGID文件
echo "" >> $LOG_FILE
echo "## SUID/SGID文件检查" >> $LOG_FILE
echo "----------------------------------------" >> $LOG_FILE

# 获取系统中的SUID/SGID文件数量
suid_count=$(find / -type f -perm -4000 2>/dev/null | wc -l)
sgid_count=$(find / -type f -perm -2000 2>/dev/null | wc -l)

log_check "SUID文件数量" "信息" "系统中有 $suid_count 个SUID文件"
log_check "SGID文件数量" "信息" "系统中有 $sgid_count 个SGID文件"

# 检查是否有异常的SUID/SGID文件
suspicious_suid=$(find / -type f -perm -4000 -not -path "/bin/*" -not -path "/sbin/*" -not -path "/usr/bin/*" -not -path "/usr/sbin/*" 2>/dev/null)
if [ ! -z "$suspicious_suid" ]; then
    log_check "可疑SUID文件" "警告" "发现非标准位置的SUID文件:\n$suspicious_suid"
else
    log_check "可疑SUID文件" "通过" "未发现非标准位置的SUID文件"
fi

# 检查跳板机特定配置
echo "" >> $LOG_FILE
echo "## 跳板机特定配置检查" >> $LOG_FILE
echo "----------------------------------------" >> $LOG_FILE

# 检查跳板机用户组
if grep -q "^jumpusers:" /etc/group; then
    log_check "跳板机用户组" "通过" "jumpusers组已创建"
else
    log_check "跳板机用户组" "失败" "未找到jumpusers组"
fi

# 检查跳板机客户端脚本
if [ -f "/usr/local/bin/jump_client.sh" ] && [ -x "/usr/local/bin/jump_client.sh" ]; then
    log_check "跳板机客户端脚本" "通过" "jump_client.sh脚本存在且可执行"
else
    log_check "跳板机客户端脚本" "失败" "jump_client.sh脚本不存在或不可执行"
fi

# 检查用户配额
if [ -f "/usr/local/bin/manage_quotas.sh" ] && [ -x "/usr/local/bin/manage_quotas.sh" ]; then
    log_check "用户配额管理" "通过" "manage_quotas.sh脚本存在且可执行"
else
    log_check "用户配额管理" "失败" "manage_quotas.sh脚本不存在或不可执行"
fi

# 生成总结
echo "" >> $LOG_FILE
echo "## 安全基线检查总结" >> $LOG_FILE
echo "----------------------------------------" >> $LOG_FILE

pass_count=$(grep -c "\[通过\]" $LOG_FILE)
fail_count=$(grep -c "\[失败\]" $LOG_FILE)
warn_count=$(grep -c "\[警告\]" $LOG_FILE)
info_count=$(grep -c "\[信息\]" $LOG_FILE)

echo "通过: $pass_count 项" >> $LOG_FILE
echo "失败: $fail_count 项" >> $LOG_FILE
echo "警告: $warn_count 项" >> $LOG_FILE
echo "信息: $info_count 项" >> $LOG_FILE

# 发送报告
cat $LOG_FILE | mail -s "跳板机安全基线检查报告 - $(date +%Y-%m-%d)" $ADMIN_EMAIL
EOF

sudo chmod +x /usr/local/bin/security_baseline.sh

# 创建每月安全基线检查定时任务
sudo tee /etc/cron.d/jumpserver_security_baseline << 'EOF'
# 每月1日凌晨4点执行安全基线检查
0 4 1 * * root /usr/local/bin/security_baseline.sh >/dev/null 2>&1
EOF
```

## 11. 文档和使用指南

### 11.1 创建管理员文档

```bash
sudo mkdir -p /usr/share/doc/jumpserver/
sudo tee /usr/share/doc/jumpserver/admin_guide.md << 'EOF'
# 跳板机管理员指南

## 1. 系统概述

本跳板机系统基于Arch Linux构建，提供了安全的中转访问功能，允许授权用户通过此服务器访问内部网络资源。系统集成了严格的访问控制、会话记录、用户管理和安全审计功能。

### 主要功能

- 集中式用户管理和访问控制
- 完整的会话记录和审计
- 基于密钥的SSH认证
- 用户活动监控和报警
- 资源使用配额管理
- 自动化安全检查和维护

## 2. 管理员工具

### 用户管理

使用 `manage_jumpusers.sh` 脚本管理跳板机用户：

```bash
# 添加新用户（有效期30天，可访问server1和server2）
sudo /usr/local/bin/manage_jumpusers.sh add username 30 'server1,server2'

# 删除用户
sudo /usr/local/bin/manage_jumpusers.sh remove username

# 延长用户有效期（15天）
sudo /usr/local/bin/manage_jumpusers.sh extend username 15

# 列出所有用户
sudo /usr/local/bin/manage_jumpusers.sh list

# 管理用户可访问的目标主机
sudo /usr/local/bin/manage_jumpusers.sh targets username 'server1,server2,server3'
```

### 配额管理

使用 `manage_quotas.sh` 脚本管理用户资源配额：

```bash
# 设置用户磁盘配额（单位：MB）
sudo /usr/local/bin/manage_quotas.sh set username 1024

# 查看用户配额使用情况
sudo /usr/local/bin/manage_quotas.sh show username

# 检查所有用户的配额使用情况
sudo /usr/local/bin/manage_quotas.sh check
```

### 系统维护

系统维护脚本会自动执行，也可手动运行：

```bash
# 执行系统维护
sudo /usr/local/bin/jumpserver_maintenance.sh

# 执行安全扫描
sudo /usr/local/bin/security_scan.sh

# 执行安全基线检查
sudo /usr/local/bin/security_baseline.sh
```

## 3. 日志和审计

### 会话日志

所有用户会话都会被记录，日志文件位于：
- 会话记录：`/var/log/jumpserver/sessions/`
- 命令记录：`/var/log/jumpserver/commands.log`

可以使用以下命令查看特定用户的活动：

```bash
# 查看用户会话日志
grep "username" /var/log/jumpserver/sessions/session_log_*

# 查看用户执行的命令
grep "username" /var/log/jumpserver/commands.log
```

### 系统日志

重要的系统日志：
- 认证日志：`/var/log/auth.log`
- 系统日志：`/var/log/syslog`
- 安全扫描报告：`/var/log/jumpserver/security/`

## 4. 安全最佳实践

### 定期维护任务

1. 检查安全扫描和基线报告中的问题
2. 审核用户账户和权限
3. 验证防火墙规则的有效性
4. 检查系统更新和补丁状态
5. 审查异常登录和访问尝试

### 用户管理最佳实践

1. 遵循最小权限原则分配访问权限
2. 定期审核用户账户，删除不再需要的账户
3. 为临时访问需求设置适当的账户过期时间
4. 定期轮换管理员密码和SSH密钥
5. 监控异常的用户活动并及时调查

### 系统加固建议

1. 保持系统和软件包更新
2. 定期检查安全基线报告并修复发现的问题
3. 限制只允许从特定IP地址访问跳板机
4. 定期备份系统配置和关键数据
5. 监控系统资源使用情况，防止拒绝服务

## 5. 故障排除

### 常见问题

1. **用户无法登录**
   - 检查用户账户是否已过期：`chage -l username`
   - 验证用户SSH密钥是否正确配置
   - 检查防火墙规则是否阻止了连接

2. **目标服务器连接失败**
   - 验证用户是否有权限访问该目标：`cat /etc/jumpserver/users/username.targets`
   - 检查目标服务器是否在线：`ping hostname`
   - 验证SSH服务是否在目标服务器上运行

3. **系统负载过高**
   - 检查当前连接数：`who | wc -l`
   - 检查资源占用高的进程：`top`
   - 验证是否有异常进程或可能的攻击

### 联系支持

如有紧急问题，请联系系统管理员：
- 邮箱：admin@example.com
- 电话：+XX-XXXX-XXXX

## 6. 附录

### 重要文件位置

- SSH配置：`/etc/ssh/sshd_config`
- 跳板机配置：`/etc/jumpserver/`
- 用户目标配置：`/etc/jumpserver/users/`
- 脚本目录：`/usr/local/bin/`
- 日志目录：`/var/log/jumpserver/`

### 定时任务

系统

继续完成管理员文档的内容：

```bash
### 定时任务

系统配置了以下定时任务：

- 每日系统维护：每天凌晨3点执行
- 每周安全扫描：每周六凌晨2点执行
- 每月安全基线检查：每月1日凌晨4点执行
- 日志轮转：每天执行
- 系统更新：每周日凌晨1点执行

查看定时任务配置：
```bash
ls -l /etc/cron.d/jumpserver_*
```
EOF

# 创建用户指南
sudo tee /usr/share/doc/jumpserver/user_guide.md << 'EOF'
# 跳板机用户指南

## 1. 概述

本跳板机系统是访问内部网络资源的安全中转站。通过此跳板机，您可以安全地连接到授权的目标服务器，同时所有操作都会被记录用于安全审计。

## 2. 首次登录

### 准备工作

在首次登录前，您需要：

1. 从管理员处获取您的用户名和临时密码
2. 准备好SSH客户端（如OpenSSH、PuTTY或SecureCRT）

### 登录步骤

1. 使用SSH客户端连接到跳板机：
   ```
   ssh username@jumpserver.example.com
   ```

2. 首次登录时，系统会要求您输入临时密码，然后立即更改为新密码
   - 新密码必须至少12个字符
   - 必须包含大小写字母、数字和特殊字符
   - 不能与您的用户名或之前的密码相似

3. 设置SSH密钥（推荐）：
   ```
   # 在本地生成SSH密钥对
   ssh-keygen -t ed25519 -C "your_email@example.com"
   
   # 将公钥上传到跳板机
   ssh-copy-id -i ~/.ssh/id_ed25519.pub username@jumpserver.example.com
   ```

## 3. 使用跳板机

### 连接目标服务器

使用`jump`命令连接到目标服务器：

```bash
jump target_server_name
```

您只能连接到管理员授权给您的目标服务器。使用以下命令查看您可以访问的目标列表：

```bash
jump -l
```

### 文件传输

通过跳板机传输文件：

```bash
# 从本地上传文件到目标服务器
scp -o "ProxyJump username@jumpserver.example.com" local_file.txt target_user@target_server:/path/

# 从目标服务器下载文件到本地
scp -o "ProxyJump username@jumpserver.example.com" target_user@target_server:/path/remote_file.txt ./
```

### 会话管理

- 断开连接：在目标服务器上输入`exit`或按`Ctrl+D`
- 查看当前会话信息：`who`
- 查看您的登录历史：`last | grep username`

## 4. 安全注意事项

### 账户安全

- 不要共享您的账户或密码
- 定期更改密码：`passwd`
- 保护好您的SSH私钥
- 不要将跳板机凭据保存在公共计算机上

### 使用限制

- 所有操作都会被记录和审计
- 不要尝试绕过系统安全限制
- 不要在跳板机上运行资源密集型任务
- 遵守系统资源配额限制

### 账户到期

您的账户有特定的有效期。查看账户到期日期：

```bash
chage -l $USER | grep "Account expires"
```

如需延长账户有效期，请联系管理员。

## 5. 常见问题

### 无法连接到跳板机

- 确认您使用了正确的用户名和密码/SSH密钥
- 确认您是从允许的网络位置访问
- 检查您的账户是否已过期

### 无法连接到目标服务器

- 确认目标服务器在您的授权列表中：`jump -l`
- 确认目标服务器名称拼写正确
- 联系管理员确认目标服务器是否在线

### 密码问题

- 忘记密码：联系管理员重置密码
- 密码过期：按照系统提示更改密码
- 账户锁定：多次密码错误后账户会被锁定，请联系管理员解锁

## 6. 联系支持

如有任何问题，请联系系统管理员：
- 邮箱：support@example.com
- 内部工单系统：http://helpdesk.internal
EOF

# 创建快速参考卡
sudo tee /usr/share/doc/jumpserver/quick_reference.md << 'EOF'
# 跳板机快速参考卡

## 登录

```bash
# SSH登录
ssh username@jumpserver.example.com

# 使用密钥登录（推荐）
ssh -i ~/.ssh/id_ed25519 username@jumpserver.example.com
```

## 目标服务器连接

```bash
# 查看可访问的目标列表
jump -l

# 连接到目标服务器
jump target_server_name

# 连接到目标服务器并指定用户
jump -u remote_user target_server_name

# 连接到目标服务器并执行命令
jump target_server_name "command to execute"
```

## 文件传输

```bash
# 上传文件到目标服务器
jump -c target_server_name local_file.txt:/remote/path/

# 从目标服务器下载文件
jump -c target_server_name /remote/path/file.txt:./

# 使用SCP通过跳板机传输
scp -o "ProxyJump username@jumpserver.example.com" local_file.txt target_user@target_server:/path/
```

## 账户管理

```bash
# 更改密码
passwd

# 查看账户到期时间
chage -l $USER | grep "Account expires"

# 查看登录历史
last | grep $USER
```

## 帮助

```bash
# 查看jump命令帮助
jump -h

# 查看用户指南
less /usr/share/doc/jumpserver/user_guide.md
```

## 联系支持

- 邮箱：support@example.com
- 内部工单系统：http://helpdesk.internal
EOF
```

### 11.2 创建系统维护文档

```bash
sudo tee /usr/share/doc/jumpserver/maintenance_guide.md << 'EOF'
# 跳板机系统维护指南

## 1. 系统架构

本跳板机系统基于Arch Linux构建，主要组件包括：

- **SSH服务**：OpenSSH 提供安全远程访问
- **用户管理**：基于Linux PAM和自定义脚本
- **会话记录**：使用脚本化的SSH和auditd
- **安全加固**：防火墙、入侵检测和安全基线
- **监控系统**：基于Prometheus和自定义脚本

## 2. 定期维护任务

### 每日维护

以下任务由`jumpserver_maintenance.sh`自动执行：

- 日志轮转和压缩
- 磁盘空间检查和清理
- 用户会话限制检查
- 系统负载监控
- 异常登录检测

### 每周维护

- 系统更新和补丁安装
- 安全扫描（由`security_scan.sh`执行）
- 用户账户审核
- 防火墙规则验证
- 备份关键配置文件

### 每月维护

- 安全基线检查（由`security_baseline.sh`执行）
- 系统性能评估
- 用户配额审核
- 长期趋势分析
- 系统配置优化

## 3. 系统更新

### 标准更新流程

```bash
# 更新软件包数据库
sudo pacman -Sy

# 查看可用更新
sudo pacman -Qu

# 应用所有更新
sudo pacman -Syu

# 检查服务状态
systemctl --failed
```

### 关键服务更新注意事项

更新SSH服务时：
1. 备份当前配置：`cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak`
2. 应用更新：`sudo pacman -S openssh`
3. 验证配置：`sshd -t`
4. 重启服务：`sudo systemctl restart sshd`
5. 验证连接：从新终端测试SSH连接

## 4. 备份和恢复

### 关键配置备份

以下文件应定期备份：

```bash
# 创建备份
sudo /usr/local/bin/backup_configs.sh

# 手动备份关键文件
sudo tar -czf /var/backups/jumpserver_config_$(date +%Y%m%d).tar.gz \
    /etc/ssh/sshd_config \
    /etc/pam.d/* \
    /etc/security/* \
    /etc/jumpserver/* \
    /usr/local/bin/*.sh
```

### 系统恢复

紧急恢复步骤：

1. 从备份恢复配置文件：
   ```bash
   sudo tar -xzf /var/backups/jumpserver_config_YYYYMMDD.tar.gz -C /
   ```

2. 重启关键服务：
   ```bash
   sudo systemctl restart sshd fail2ban rsyslog auditd
   ```

## 5. 性能调优

### 系统资源监控

```bash
# 检查系统负载
uptime

# 查看内存使用情况
free -h

# 查看磁盘使用情况
df -h

# 查看进程资源使用
top
```

### 性能优化建议

- **SSH连接优化**：调整`/etc/ssh/sshd_config`中的`MaxStartups`和`MaxSessions`参数
- **系统限制**：根据硬件配置调整`/etc/security/limits.conf`
- **磁盘I/O**：使用`ionice`为关键进程设置I/O优先级
- **网络调优**：根据连接数调整内核参数`net.ipv4.ip_local_port_range`

## 6. 故障排除

### 常见问题诊断

#### SSH服务问题

```bash
# 检查SSH服务状态
systemctl status sshd

# 查看SSH错误日志
journalctl -u sshd

# 验证SSH配置
sshd -t
```

#### 用户访问问题

```bash
# 检查用户权限
id username
groups username

# 检查用户目标配置
cat /etc/jumpserver/users/username.targets

# 验证用户账户状态
chage -l username
```

#### 系统负载问题

```bash
# 查找资源密集型进程
top -c

# 检查打开的文件和连接
lsof | grep username

# 分析系统负载
vmstat 1 10
```

### 紧急联系信息

- 主要管理员：admin@example.com / +XX-XXXX-XXXX
- 备份管理员：backup-admin@example.com / +XX-XXXX-XXXX
- 安全团队：security@example.com / +XX-XXXX-XXXX

## 7. 安全事件响应

### 检测安全事件

潜在安全事件的迹象：
- 异常的登录尝试增加
- 未经授权的用户或进程
- 异常的网络流量或连接
- 系统文件意外修改
- 系统性能突然下降

### 安全事件响应流程

1. **隔离**：如果确认安全事件，考虑临时限制访问
   ```bash
   # 限制SSH访问
   sudo ufw deny ssh
   
   # 或仅允许管理IP
   sudo ufw allow from admin_ip to any port 22
   ```

2. **调查**：收集和分析证据
   ```bash
   # 检查认证日志
   sudo grep "Failed password" /var/log/auth.log
   
   # 检查可疑进程
   ps aux | sort -nrk 3,3 | head -n 20
   
   # 检查网络连接
   netstat -tupan
   ```

3. **恢复**：清理和恢复系统
   ```bash
   # 重置受影响的用户密码
   sudo passwd username
   
   # 从备份恢复配置
   sudo /usr/local/bin/restore_configs.sh
   
   # 更新系统
   sudo pacman -Syu
   ```

4. **报告**：记录事件并通知相关方
   - 创建详细的事件报告
   - 更新安全策略和防御措施
   - 考虑对用户进行额外的安全培训
EOF
```

## 12. 完成安装和验证

```bash
# 创建安装完成标记
sudo touch /etc/jumpserver/installation_complete

# 显示安装摘要
cat << EOF

========================================
    跳板机系统安装完成
========================================

安装时间: $(date)
主机名: $(hostname)
IP地址: $(ip addr show | grep -w inet | grep -v 127.0.0.1 | awk '{print $2}' | cut -d/ -f1)
SSH端口: $(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}')

已安装的主要组件:
- OpenSSH 服务器
- 防火墙 (UFW)
- 入侵检测 (Fail2ban)
- 审计系统 (Auditd)
- 日志服务 (Rsyslog)

继续完成安装脚本的最后部分：

```bash
已安装的主要组件:
- OpenSSH 服务器
- 防火墙 (UFW)
- 入侵检测 (Fail2ban)
- 审计系统 (Auditd)
- 日志服务 (Rsyslog)

已创建的管理脚本:
- 用户管理: /usr/local/bin/manage_jumpusers.sh
- 配额管理: /usr/local/bin/manage_quotas.sh
- 系统维护: /usr/local/bin/jumpserver_maintenance.sh
- 安全扫描: /usr/local/bin/security_scan.sh
- 安全基线检查: /usr/local/bin/security_baseline.sh

文档位置:
- 管理员指南: /usr/share/doc/jumpserver/admin_guide.md
- 用户指南: /usr/share/doc/jumpserver/user_guide.md
- 快速参考: /usr/share/doc/jumpserver/quick_reference.md
- 维护指南: /usr/share/doc/jumpserver/maintenance_guide.md

后续步骤:
1. 创建管理员账户: sudo /usr/local/bin/manage_jumpusers.sh add admin 365 'all'
2. 配置目标服务器列表: sudo vi /etc/jumpserver/targets.list
3. 检查系统安全基线: sudo /usr/local/bin/security_baseline.sh
4. 验证SSH配置: sudo sshd -t

注意: 首次重启后，请运行 sudo /usr/local/bin/post_install_check.sh 验证所有服务正常运行

========================================
EOF

# 创建安装后检查脚本
sudo tee /usr/local/bin/post_install_check.sh << 'EOF'
#!/bin/bash
# 跳板机安装后检查脚本

echo "========================================="
echo "        跳板机系统安装后检查"
echo "========================================="

# 检查关键服务状态
echo -e "\n检查关键服务状态:"
services=("sshd" "fail2ban" "auditd" "rsyslog" "cronie")
for service in "${services[@]}"; do
    status=$(systemctl is-active $service)
    if [ "$status" == "active" ]; then
        echo "✓ $service 服务运行正常"
    else
        echo "✗ $service 服务未运行，状态: $status"
        echo "  尝试启动服务..."
        sudo systemctl start $service
        new_status=$(systemctl is-active $service)
        if [ "$new_status" == "active" ]; then
            echo "  ✓ 已成功启动 $service 服务"
        else
            echo "  ✗ 无法启动 $service 服务，请检查配置"
        fi
    fi
done

# 检查防火墙状态
echo -e "\n检查防火墙状态:"
if sudo ufw status | grep -q "Status: active"; then
    echo "✓ 防火墙已启用"
    echo "  开放的端口:"
    sudo ufw status | grep ALLOW
else
    echo "✗ 防火墙未启用"
    echo "  建议启用防火墙: sudo ufw enable"
fi

# 检查关键目录和文件
echo -e "\n检查关键目录和文件:"
paths=(
    "/etc/jumpserver"
    "/etc/jumpserver/users"
    "/var/log/jumpserver"
    "/var/log/jumpserver/sessions"
    "/usr/local/bin/manage_jumpusers.sh"
    "/usr/local/bin/jump_client.sh"
    "/usr/local/bin/security_baseline.sh"
    "/usr/share/doc/jumpserver"
)

for path in "${paths[@]}"; do
    if [ -e "$path" ]; then
        echo "✓ $path 存在"
    else
        echo "✗ $path 不存在"
    fi
done

# 检查SSH配置
echo -e "\n检查SSH配置:"
ssh_config_issues=$(sudo sshd -t 2>&1)
if [ -z "$ssh_config_issues" ]; then
    echo "✓ SSH配置有效"
else
    echo "✗ SSH配置存在问题:"
    echo "$ssh_config_issues"
fi

# 检查定时任务
echo -e "\n检查定时任务配置:"
if ls /etc/cron.d/jumpserver_* &>/dev/null; then
    echo "✓ 跳板机定时任务已配置:"
    ls -l /etc/cron.d/jumpserver_*
else
    echo "✗ 未找到跳板机定时任务配置"
fi

# 检查网络连接
echo -e "\n检查网络连接:"
if ping -c 1 -W 2 8.8.8.8 &>/dev/null; then
    echo "✓ 网络连接正常"
else
    echo "✗ 网络连接异常，无法访问外部网络"
fi

# 检查磁盘空间
echo -e "\n检查磁盘空间:"
disk_usage=$(df -h / | tail -1 | awk '{print $5}' | tr -d '%')
if [ "$disk_usage" -lt 80 ]; then
    echo "✓ 磁盘空间充足: $disk_usage%"
else
    echo "✗ 磁盘空间不足: $disk_usage%"
fi

# 总结
echo -e "\n========================================="
echo "检查完成。如有问题，请参考维护指南进行修复。"
echo "维护指南: /usr/share/doc/jumpserver/maintenance_guide.md"
echo "========================================="
EOF

sudo chmod +x /usr/local/bin/post_install_check.sh

# 创建一个示例目标服务器列表
sudo tee /etc/jumpserver/targets.list << 'EOF'
# 目标服务器列表
# 格式: server_name,server_ip,description
# 例如:
web01,192.168.1.101,Web服务器1
web02,192.168.1.102,Web服务器2
db01,192.168.1.201,数据库服务器1
db02,192.168.1.202,数据库服务器2
app01,192.168.1.151,应用服务器1
app02,192.168.1.152,应用服务器2
# 添加更多目标服务器...
EOF

# 创建备份配置脚本
sudo tee /usr/local/bin/backup_configs.sh << 'EOF'
#!/bin/bash
# 跳板机配置备份脚本

BACKUP_DIR="/var/backups/jumpserver"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/jumpserver_config_$TIMESTAMP.tar.gz"

# 创建备份目录
mkdir -p $BACKUP_DIR

# 备份关键配置文件
tar -czf $BACKUP_FILE \
    /etc/ssh/sshd_config \
    /etc/pam.d/* \
    /etc/security/* \
    /etc/jumpserver/* \
    /usr/local/bin/*.sh \
    /etc/ufw/* \
    /etc/fail2ban/* \
    /etc/audit/* \
    /etc/rsyslog.d/* \
    /etc/cron.d/jumpserver_*

# 设置权限
chmod 600 $BACKUP_FILE

# 清理旧备份（保留最近10个）
ls -t $BACKUP_DIR/jumpserver_config_*.tar.gz | tail -n +11 | xargs -r rm

echo "备份已创建: $BACKUP_FILE"
echo "备份包含以下文件:"
tar -tzf $BACKUP_FILE | head -20
if [ $(tar -tzf $BACKUP_FILE | wc -l) -gt 20 ]; then
    echo "... 以及更多文件"
fi
EOF

sudo chmod +x /usr/local/bin/backup_configs.sh

# 创建恢复配置脚本
sudo tee /usr/local/bin/restore_configs.sh << 'EOF'
#!/bin/bash
# 跳板机配置恢复脚本

BACKUP_DIR="/var/backups/jumpserver"

# 检查参数
if [ $# -ne 1 ]; then
    echo "用法: $0 <备份文件名>"
    echo "可用的备份文件:"
    ls -1 $BACKUP_DIR/jumpserver_config_*.tar.gz 2>/dev/null
    exit 1
fi

BACKUP_FILE="$1"

# 检查备份文件是否存在
if [ ! -f "$BACKUP_FILE" ]; then
    # 尝试在备份目录中查找
    if [ -f "$BACKUP_DIR/$BACKUP_FILE" ]; then
        BACKUP_FILE="$BACKUP_DIR/$BACKUP_FILE"
    else
        echo "错误: 备份文件 '$BACKUP_FILE' 不存在"
        exit 1
    fi
fi

# 创建临时恢复目录
TEMP_DIR=$(mktemp -d)

# 解压备份文件到临时目录
echo "解压备份文件到临时目录..."
tar -xzf "$BACKUP_FILE" -C "$TEMP_DIR"

# 恢复配置文件
echo "恢复配置文件..."
cp -a $TEMP_DIR/etc/ssh/sshd_config /etc/ssh/
cp -a $TEMP_DIR/etc/pam.d/* /etc/pam.d/
cp -a $TEMP_DIR/etc/security/* /etc/security/
cp -a $TEMP_DIR/etc/jumpserver/* /etc/jumpserver/
cp -a $TEMP_DIR/usr/local/bin/*.sh /usr/local/bin/
cp -a $TEMP_DIR/etc/ufw/* /etc/ufw/ 2>/dev/null
cp -a $TEMP_DIR/etc/fail2ban/* /etc/fail2ban/ 2>/dev/null
cp -a $TEMP_DIR/etc/audit/* /etc/audit/ 2>/dev/null
cp -a $TEMP_DIR/etc/rsyslog.d/* /etc/rsyslog.d/ 2>/dev/null
cp -a $TEMP_DIR/etc/cron.d/jumpserver_* /etc/cron.d/ 2>/dev/null

# 清理临时目录
rm -rf "$TEMP_DIR"

echo "配置已从 $BACKUP_FILE 恢复"
echo "请重启相关服务以应用更改:"
echo "sudo systemctl restart sshd fail2ban auditd rsyslog"
EOF

sudo chmod +x /usr/local/bin/restore_configs.sh

# 创建首次登录欢迎信息
sudo tee /etc/motd << 'EOF'
*******************************************
*                                         *
*           安全跳板机系统                *
*                                         *
*******************************************

所有操作将被记录和审计。
未经授权的访问将被追究法律责任。

使用 'jump -l' 查看可访问的目标服务器列表
使用 'jump server_name' 连接到目标服务器

文档: /usr/share/doc/jumpserver/user_guide.md

*******************************************
EOF

# 最后一次备份配置
sudo /usr/local/bin/backup_configs.sh

echo "跳板机系统安装完成！请重启系统以确保所有配置生效。"
echo "重启后，请运行 sudo /usr/local/bin/post_install_check.sh 验证安装。"
```

## 13. 安全最佳实践建议

以下是使用跳板机系统的一些安全最佳实践建议：

### 13.1 管理员安全建议

```bash
sudo tee /usr/share/doc/jumpserver/security_best_practices.md << 'EOF'
# 跳板机安全最佳实践

## 系统配置安全

1. **定期更新系统**
   - 至少每周应用安全更新
   - 为关键漏洞创建紧急更新流程

2. **强化认证**
   - 强制使用SSH密钥认证，禁用密码认证
   - 实施多因素认证(MFA)
   - 禁用root直接登录

3. **网络安全**
   - 限制SSH访问源IP地址
   - 使用非标准SSH端口
   - 实施网络分段，将跳板机置于专用网段

4. **监控与审计**
   - 实时监控登录尝试和异常活动
   - 定期审查审计日志
   - 配置关键事件的自动告警

## 用户管理安全

1. **最小权限原则**
   - 仅授予用户所需的最小访问权限
   - 定期审核和撤销不必要的访问权限

2. **账户生命周期管理**
   - 建立严格的账户创建和删除流程
   - 为临时访问设置自动过期时间
   - 定期审核所有活跃账户

3. **访问控制**
   - 实施基于角色的访问控制
   - 限制用户可访问的目标服务器
   - 对敏感系统实施额外的访问控制

## 运维安全

1. **变更管理**
   - 记录所有系统配置变更
   - 实施变更审批流程
   - 测试变更对系统安全的影响

2. **备份与恢复**
   - 定期备份关键配置和数据
   - 测试恢复流程
   - 存储备份在安全的离线位置

3. **事件响应**
   - 制定安全事件响应计划
   - 定期进行安全演练
   - 记录和分析所有安全事件

## 日常安全检查清单

- [ ] 检查失败的登录尝试
- [ ] 审查异常的用户活动
- [ ] 验证所有服务正常运行
- [ ] 检查系统资源使用情况
- [ ] 验证备份是否成功完成
- [ ] 检查安全扫描和基线报告
- [ ] 审核防火墙规则和日志
- [ ] 检查系统更新状态

## 安全策略模板

### 密