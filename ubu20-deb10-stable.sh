#!/bin/bash

# Color definitions
Green="\e[92;1m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
OK="${Green}--->${FONT}"
ERROR="${RED}[ERROR]${FONT}"
GRAY="\e[1;30m"
NC='\e[0m'
red='\e[1;31m'
green='\e[0;32m'

# ===================
clear

# Exporting IP Address Information
export IP=$(curl -sS icanhazip.com)

# Clear previous data
clear && clear && clear
clear; clear; clear

# Banner
echo -e "${YELLOW}------------------------------------------------------------${NC}"
echo -e "EDIT BY : ${green}Lite  ${NC}${YELLOW}(${NC} ${green} Vermillion${NC}${YELLOW})${NC}"
echo -e "${YELLOW}------------------------------------------------------------${NC}"
echo ""
sleep 2

###### IZIN SC 

# Checking OS Architecture
if [[ $(uname -m | awk '{print $1}') == "x86_64" ]]; then
    echo -e "${OK} Your Architecture Is Supported ( ${green}$(uname -m)${NC} )"
else
    echo -e "${ERROR} Your Architecture Is Not Supported ( ${YELLOW}$(uname -m)${NC} )"
    exit 1
fi

# Checking System
os_name=$(grep -w ID /etc/os-release | head -n1 | sed 's/ID=//g' | sed 's/"//g')
pretty_name=$(grep -w PRETTY_NAME /etc/os-release | head -n1 | sed 's/PRETTY_NAME=//g' | sed 's/"//g')

if [[ "$os_name" == "ubuntu" || "$os_name" == "debian" ]]; then
    echo -e "${OK} Your OS Is Supported ( ${green}$pretty_name${NC} )"
else
    echo -e "${ERROR} Your OS Is Not Supported ( ${YELLOW}$pretty_name${NC} )"
    exit 1
fi

# IP Address Validation
if [[ -z "$IP" ]]; then
    echo -e "${ERROR} IP Address ( ${YELLOW}Not Detected${NC} )"
else
    echo -e "${OK} IP Address ( ${green}$IP${NC} )"
fi

# Validate Successful
echo ""
read -p "$(echo -e "Press ${GRAY}[ ${NC}${green}Enter${NC} ${GRAY}]${NC} To Start Installation") "
echo ""
clear

# Check if the script is run as root
if [[ "${EUID}" -ne 0 ]]; then
    echo "You need to run this script as root"
    exit 1
fi

# Check if the system is OpenVZ
if [[ "$(systemd-detect-virt)" == "openvz" ]]; then
    echo "OpenVZ is not supported"
    exit 1
fi

# Installing dependencies
apt install ruby -y
gem install lolcat
apt install wondershaper -y
clear

# Define repository URL
REPO="https://raw.githubusercontent.com/vermiliion/v3/main/"

# Function to print time taken for installation
secs_to_human() {
    echo "Installation time: $((${1} / 3600)) hours $(((${1} / 60) % 60)) minutes $((${1} % 60)) seconds"
}

### Status Functions
function print_ok() {
    echo -e "${OK} ${BLUE} $1 ${FONT}"
}

function print_install() {
    echo -e "${green}------------------------------------------------------------${FONT}"
    echo -e "${YELLOW} $1 ${FONT}"
    echo -e "${green}------------------------------------------------------------${FONT}"
    sleep 1
}

function print_error() {
    echo -e "${ERROR} ${REDBG} $1 ${FONT}"
}

function print_success() {
    if [[ $? -eq 0 ]]; then
        echo -e "${green}------------------------------------------------------------${FONT}"
        echo -e "${Green} $1 successfully installed"
        echo -e "${green}------------------------------------------------------------${FONT}"
        sleep 2
    fi
}

### Check if the script is run as root
function is_root() {
    if [[ "$UID" -eq 0 ]]; then
        print_ok "Root user detected, starting installation process"
    else
        print_error "The current user is not the root user. Please switch to the root user and run the script again"
        exit 1
    fi
}

### Installation function
function directory_install() {
    echo "Membuat direktori xray..."

    # Create directories for xray configuration and logs
    mkdir -p /etc/xray
    curl -s ifconfig.me > /etc/xray/ipvps
    touch /etc/xray/domain
    mkdir -p /var/log/xray

    # Set permissions for log files
    chown www-data.www-data /var/log/xray
    chmod +x /var/log/xray
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log

    # Create additional directory
    mkdir -p /var/lib/kyt >/dev/null 2>&1

    # RAM Information Calculation
    mem_used=0
    mem_total=0

    # Read and process memory information from /proc/meminfo
    while IFS=":" read -r a b; do
        case $a in
            "MemTotal") ((mem_used+=${b/kB})); mem_total="${b/kB}" ;;
            "Shmem") ((mem_used+=${b/kB})) ;;
            "MemFree" | "Buffers" | "Cached" | "SReclaimable")
                mem_used="$((mem_used-=${b/kB}))"
            ;;
        esac
    done < /proc/meminfo

    # Convert memory usage from kB to MB
    Ram_Usage="$((mem_used / 1024))"
    Ram_Total="$((mem_total / 1024))"

    # Export system and network information as environment variables
    export tanggal=$(date -d "0 days" +"%d-%m-%Y - %X")
    export OS_Name=$(grep -w PRETTY_NAME /etc/os-release | head -n1 | sed 's/PRETTY_NAME=//g' | sed 's/"//g')
    export Kernel=$(uname -r)
    export Arch=$(uname -m)
    export IP=$(curl -s https://ipinfo.io/ip/)
}


function first_setup(){
    timedatectl set-timezone Asia/Makassar
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    print_success "Directory Xray"
    
    # Check for Ubuntu or Debian and install the appropriate version of HAProxy
    OS_ID=$(grep -w ID /etc/os-release | head -n1 | cut -d '=' -f 2 | tr -d '"')
    if [[ $OS_ID == "ubuntu" ]]; then
        echo "Setup Dependencies for $(grep -w PRETTY_NAME /etc/os-release | head -n1 | cut -d '=' -f 2 | tr -d '"')"
        sudo apt update -y
        sudo apt-get install --no-install-recommends software-properties-common -y
        sudo add-apt-repository ppa:vbernat/haproxy-2.0 -y
        sudo apt-get -y install haproxy=2.0.*
    elif [[ $OS_ID == "debian" ]]; then
        echo "Setup Dependencies for $(grep -w PRETTY_NAME /etc/os-release | head -n1 | cut -d '=' -f 2 | tr -d '"')"
        curl https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg
        echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] http://haproxy.debian.net buster-backports-1.8 main" >/etc/apt/sources.list.d/haproxy.list
        sudo apt-get update
        sudo apt-get -y install haproxy=1.8.*
    else
        echo "Your OS Is Not Supported ($(grep -w PRETTY_NAME /etc/os-release | head -n1 | cut -d '=' -f 2 | tr -d '"'))"
        exit 1
    fi
}

function nginx_install() {
    OS_ID=$(grep -w ID /etc/os-release | head -n1 | cut -d '=' -f 2 | tr -d '"')
    
    if [[ $OS_ID == "ubuntu" ]]; then
        print_install "Setup Nginx for $(grep -w PRETTY_NAME /etc/os-release | head -n1 | cut -d '=' -f 2 | tr -d '"')"
        sudo apt-get install nginx -y
    elif [[ $OS_ID == "debian" ]]; then
        print_install "Setup Nginx for $(grep -w PRETTY_NAME /etc/os-release | head -n1 | cut -d '=' -f 2 | tr -d '"')"
        sudo apt -y install nginx
    else
        echo "Your OS Is Not Supported ($(grep -w PRETTY_NAME /etc/os-release | head -n1 | cut -d '=' -f 2 | tr -d '"'))"
    fi
}

function base_package() {
    clear
    print_install "Installing Required Packages"
    
    apt install zip pwgen openssl netcat socat cron bash-completion figlet -y
    apt update -y && apt upgrade -y && apt dist-upgrade -y
    systemctl enable chronyd && systemctl restart chronyd
    systemctl enable chrony && systemctl restart chrony
    chronyc sourcestats -v && chronyc tracking -v
    apt install ntpdate -y && ntpdate pool.ntp.org
    apt install sudo -y && sudo apt-get clean all
    sudo apt-get autoremove -y && sudo apt-get install -y debconf-utils
    sudo apt-get remove --purge exim4 -y && sudo apt-get remove --purge ufw firewalld -y
    sudo apt-get install -y --no-install-recommends software-properties-common
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    sudo apt-get install -y all-required-packages

    print_success "Required Packages Installed"
}

function pasang_domain() {
    local valid=false
    while [ $valid == false ]; do
        clear
        echo -e "------------------------------------------------------------"
        echo -e "Please Choose an Option to Setup Domain:"
        echo -e "------------------------------------------------------------"
        echo -e "1) Use Your Own Domain"
        echo -e "2) Use a Random Domain"
        echo -e "------------------------------------------------------------"
        read -p "   Please select (1-2): " host
        
        if [[ $host == "1" ]]; then
            read -p "   Enter Your Subdomain: " host1
            echo $host1 > /etc/xray/domain && echo $host1 > /root/domain
            valid=true
            echo "Domain saved successfully!"
        elif [[ $host == "2" ]]; then
            wget ${REPO}files/cf && chmod +x cf && ./cf
            host2=$(cat /etc/xray/domain)
            echo $host2 > /etc/xray/domain && echo $host2 > /root/domain
            valid=true
            rm -f /root/cf
            echo "Random domain saved successfully!"
        else
            echo "Invalid option. Please choose 1 or 2."
            sleep 2
        fi
    done
}

function restart_system() {
    MYIP=$(curl -sS ipv4.icanhazip.com)
    echo "Loading..."
    clear
    izinsc="https://raw.githubusercontent.com/vermiliion/izin/main/ip"
    username=$(curl -s $izinsc | grep $MYIP | awk '{print $2}')
    expx=$(curl -s $izinsc | grep $MYIP | awk '{print $3}')
    echo "$username" >/usr/bin/user && echo "$expx" >/usr/bin/e
    
    ISP=$(curl -s ipinfo.io/org | cut -d " " -f 2-10)
    CITY=$(curl -s ipinfo.io/city)
    today=$(date +"%Y-%m-%d")
    d1=$(date -d "$valid" +%s)
    d2=$(date -d "$today" +%s)
    certificate=$(((d1 - d2) / 86400))

    Exp1=$(curl -s $izinsc | grep $MYIP | awk '{print $4}')
    if [[ "$today" < "$Exp1" ]]; then
        sts="(Active)"
    else
        sts="(Expired)"
    fi

    CHATID="5092269467"
    KEY="6918231835:AAFANlNjXrz-kxXmXskeY7TRUDMdM1lS6Bs"
    URL="https://api.telegram.org/bot$KEY/sendMessage"
    TIMEZONE=$(date +%H:%M:%S)
    TEXT="
<code>━━━━━━━━━━━━━━━━━━━━━━━━━━</code>
<b>🌐 VPS Server Notification</b>
<code>━━━━━━━━━━━━━━━━━━━━━━━━━━</code>

<b>👤 User:</b> <code>$username</code>
<b>🌍 Domain:</b> <code>$domain</code>
<b>🔗 IP VPS:</b> <code>$MYIP</code>
<b>💻 ISP:</b> <code>$ISP</code>
<b>📍 Location:</b> <code>$CITY</code>
<b>⏳ Expiry Date:</b> <code>$exp</code>
<b>🕒 Timezone:</b> <code>$TIMEZONE</code>

<code>━━━━━━━━━━━━━━━━━━━━━━━━━━━</code>
<b>🚀 Script Status:</b> <i>Active/Expired</i>
<code>━━━━━━━━━━━━━━━━━━━━━━━━━━━</code>

<i>📬 For support or inquiries, contact:</i> @Lite_Vermilion

    curl -s --max-time 10 -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
}

clear
# Pasang SSL
# Function to install SSL certificate
function pasang_ssl() {
    clear
    print_install "Installing SSL for Domain"

    # Remove old certificate files
    rm -rf /etc/xray/xray.key
    rm -rf /etc/xray/xray.crt

    domain=$(cat /root/domain)
    STOPWEBSERVER=$(lsof -i:80 | awk 'NR==2 {print $1}')
    
    # Prepare directory and stop web services
    rm -rf /root/.acme.sh
    mkdir /root/.acme.sh
    systemctl stop $STOPWEBSERVER
    systemctl stop nginx

    # Install and configure acme.sh for Let's Encrypt
    curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt

    # Issue certificate and install
    /root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
    ~/.acme.sh/acme.sh --installcert -d $domain \
        --fullchainpath /etc/xray/xray.crt \
        --keypath /etc/xray/xray.key --ecc

    # Set permissions
    chmod 777 /etc/xray/xray.key
    print_success "SSL Certificate installed"
}

# Function to create necessary folders for Xray and services
function make_folder_xray() {
    # Remove old database files
    rm -rf /etc/vmess/.vmess.db
    rm -rf /etc/vless/.vless.db
    rm -rf /etc/trojan/.trojan.db
    rm -rf /etc/shadowsocks/.shadowsocks.db
    rm -rf /etc/ssh/.ssh.db
    rm -rf /etc/bot/.bot.db
    rm -rf /etc/user-create/user.log

    # Create necessary directories
    mkdir -p /etc/{bot,xray,vmess,vless,trojan,shadowsocks,ssh,user-create}
    mkdir -p /usr/bin/xray/
    mkdir -p /var/log/xray/
    mkdir -p /var/www/html
    mkdir -p /etc/kyt/limit/{vmess,vless,trojan,ssh}/ip
    mkdir -p /etc/limit/{vmess,vless,trojan,ssh}

    # Set permissions and create required files
    chmod +x /var/log/xray
    touch /etc/xray/domain
    touch /var/log/xray/{access.log,error.log}
    touch /etc/{vmess/.vmess.db,vless/.vless.db,trojan/.trojan.db,shadowsocks/.shadowsocks.db,ssh/.ssh.db,bot/.bot.db}
    touch /etc/user-create/user.log

    # Log message for creating accounts
    echo "& Plugin Account" >> /etc/{vmess/.vmess.db,vless/.vless.db,trojan/.trojan.db,shadowsocks/.shadowsocks.db,ssh/.ssh.db}
    echo "echo -e 'VPS Config User Account'" >> /etc/user-create/user.log
}

# Function to install Xray Core
function install_xray() {
    clear
    print_install "Installing Xray Core (Latest Version)"

    domainSock_dir="/run/xray"
    ! [ -d $domainSock_dir ] && mkdir $domainSock_dir
    chown www-data:www-data $domainSock_dir

    # Get the latest version of Xray Core
    latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version $latest_version

    # Download and apply configurations
    wget -O /etc/xray/config.json "${REPO}config/config.json" >/dev/null 2>&1
    wget -O /etc/systemd/system/runn.service "${REPO}files/runn.service" >/dev/null 2>&1

    domain=$(cat /etc/xray/domain)
    IPVS=$(cat /etc/xray/ipvps)
    print_success "Xray Core installed successfully"

    # Setup Nginx and HAProxy configurations
    clear
    curl -s ipinfo.io/city
    curl -s ipinfo.io/org | cut -d " " -f 2-10
    print_install "Configuring Packet"

    wget -O /etc/haproxy/haproxy.cfg "${REPO}config/haproxy.cfg" >/dev/null 2>&1
    wget -O /etc/nginx/conf.d/xray.conf "${REPO}config/xray.conf" >/dev/null 2>&1

    # Replace placeholders with domain
    sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf

    # Configure nginx
    curl ${REPO}config/nginx.conf > /etc/nginx/nginx.conf

    cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem

    # Set permissions and create systemd service
    chmod +x /etc/systemd/system/runn.service

    cat >/etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
Documentation=https://github.com
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

    print_success "Packet configuration complete"
}

# Function to setup SSH password and configurations
function ssh() {
    clear
    print_install "Setting up SSH Password"

    wget -O /etc/pam.d/common-password "${REPO}files/password"
    chmod +x /etc/pam.d/common-password

    # Set keyboard configuration
    DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration

    debconf-set-selections <<< "keyboard-configuration keyboard-configuration/layout select English"
    debconf-set-selections <<< "keyboard-configuration keyboard-configuration/model select Generic 105-key (Intl) PC"

    # Setup /etc/rc.local for system services
    cat > /etc/systemd/system/rc-local.service <<-EOF
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local

[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99

[Install]
WantedBy=multi-user.target
EOF

    # Configure rc.local
    cat > /etc/rc.local <<-EOF
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
EOF

    chmod +x /etc/rc.local
    systemctl enable rc-local
    systemctl start rc-local.service

    # Disable IPv6
    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
    sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

    # Set timezone and locale
    ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
    sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config

    print_success "SSH Password setup complete"
}

function udp_mini() {
    clear
    print_install "Memasang Service Limit IP & Quota"
    wget -q https://raw.githubusercontent.com/vermiliion/v3/main/config/fv-tunnel && chmod +x fv-tunnel && ./fv-tunnel

    # Install UDP Mini
    mkdir -p /usr/local/kyt/
    wget -q -O /usr/local/kyt/udp-mini "${REPO}files/udp-mini"
    chmod +x /usr/local/kyt/udp-mini
    for i in {1..3}; do
        wget -q -O /etc/systemd/system/udp-mini-${i}.service "${REPO}files/udp-mini-${i}.service"
        systemctl disable udp-mini-${i}
        systemctl stop udp-mini-${i}
        systemctl enable udp-mini-${i}
        systemctl start udp-mini-${i}
    done
    print_success "Limit IP Service"
}

function ssh_slow() {
    clear
    print_install "Memasang modul SlowDNS Server"
    wget -q -O /tmp/nameserver "${REPO}files/nameserver" >/dev/null 2>&1
    chmod +x /tmp/nameserver
    bash /tmp/nameserver | tee /root/install.log
    print_success "SlowDNS"
}

function ins_SSHD() {
    clear
    print_install "Memasang SSHD"
    wget -q -O /etc/ssh/sshd_config "${REPO}files/sshd" >/dev/null 2>&1
    chmod 700 /etc/ssh/sshd_config
    systemctl restart ssh
    systemctl status ssh
    print_success "SSHD"
}

function ins_dropbear() {
    clear
    print_install "Menginstall Dropbear"
    apt-get install dropbear -y >/dev/null 2>&1
    wget -q -O /etc/default/dropbear "${REPO}config/dropbear.conf"
    chmod +x /etc/default/dropbear
    systemctl restart dropbear
    systemctl status dropbear
    print_success "Dropbear"
}

function ins_vnstat() {
    clear
    print_install "Menginstall Vnstat"
    apt -y install vnstat libsqlite3-dev >/dev/null 2>&1
    wget https://humdi.net/vnstat/vnstat-2.6.tar.gz
    tar zxvf vnstat-2.6.tar.gz
    cd vnstat-2.6
    ./configure --prefix=/usr --sysconfdir=/etc && make && make install
    cd
    vnstat -u -i $NET
    sed -i 's/Interface "eth0"/Interface "'$NET'"/g' /etc/vnstat.conf
    chown vnstat:vnstat /var/lib/vnstat -R
    systemctl enable vnstat
    systemctl restart vnstat
    systemctl status vnstat
    rm -f /root/vnstat-2.6.tar.gz
    rm -rf /root/vnstat-2.6
    print_success "Vnstat"
}

function ins_openvpn() {
    clear
    print_install "Menginstall OpenVPN"
    wget ${REPO}files/openvpn && chmod +x openvpn && ./openvpn
    systemctl restart openvpn
    print_success "OpenVPN"
}

function ins_backup() {
    clear
    print_install "Memasang Backup Server"
    apt install rclone -y
    printf "q\n" | rclone config
    wget -O /root/.config/rclone/rclone.conf "https://raw.githubusercontent.com/vermiliion/v3/main/config/rclone.conf"
    
    # Install wondershaper
    cd /bin
    git clone https://github.com/magnific0/wondershaper.git
    cd wondershaper
    sudo make install
    cd
    rm -rf wondershaper

    echo > /home/limit

    # Install msmtp for email
    apt install msmtp-mta ca-certificates bsd-mailx -y
    cat <<EOF >>/etc/msmtprc
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
account default
host smtp.gmail.com
port 587
auth on
user backupsmtp93@gmail.com
from backupsmtp93@gmail.com
password sdallofkbpuhbtoa
logfile ~/.msmtp.log
EOF

    chown -R www-data:www-data /etc/msmtprc
    wget -q -O /etc/ipserver "${REPO}files/ipserver" && bash /etc/ipserver
    print_success "Backup Server"
}

function ins_swap(){
    clear
    print_install "Installing 1G Swap"

    gotop_latest=$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)
    gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v${gotop_latest}_linux_amd64.deb"
    curl -sL "$gotop_link" -o /tmp/gotop.deb
    dpkg -i /tmp/gotop.deb >/dev/null 2>&1
    
    # Create 1G swap file
    dd if=/dev/zero of=/swapfile bs=1024 count=1048576
    mkswap /swapfile
    chown root:root /swapfile
    chmod 0600 /swapfile
    swapon /swapfile
    sed -i '$ i\/swapfile swap swap defaults 0 0' /etc/fstab

    # Synchronize time
    chronyd -q 'server 0.id.pool.ntp.org iburst'
    chronyc sourcestats -v
    chronyc tracking -v
    
    # Install BBR script
    wget "${REPO}files/bbr.sh" && chmod +x bbr.sh && ./bbr.sh

    print_success "1G Swap installed"
}

function ins_fail2ban(){
    clear
    print_install "Installing Fail2ban"
    
    # Uncomment these lines if needed
    # apt -y install fail2ban >/dev/null 2>&1
    # sudo systemctl enable --now fail2ban
    # /etc/init.d/fail2ban restart
    # /etc/init.d/fail2ban status

    # Install DDOS Flate
    if [ -d '/usr/local/ddos' ]; then
        echo "Please uninstall the previous version first."
        exit 0
    else
        mkdir /usr/local/ddos
    fi

    clear

    # Configure SSH banner
    echo "Banner /etc/kyt.txt" >>/etc/ssh/sshd_config
    sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/kyt.txt"@g' /etc/default/dropbear

    # Change banner file
    wget -O /etc/kyt.txt "${REPO}files/issue.net"
    
    print_success "Fail2ban installed"
}

function ins_epro(){
    clear
    print_install "Installing ePro WebSocket Proxy"

    wget -O /usr/bin/ws "${REPO}files/ws" >/dev/null 2>&1
    wget -O /usr/bin/tun.conf "${REPO}config/tun.conf" >/dev/null 2>&1
    wget -O /etc/systemd/system/ws.service "${REPO}files/ws.service" >/dev/null 2>&1
    chmod +x /etc/systemd/system/ws.service /usr/bin/ws
    chmod 644 /usr/bin/tun.conf

    systemctl disable ws
    systemctl stop ws
    systemctl enable ws
    systemctl restart ws

    # Update xray geo data
    wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
    wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
    
    wget -O /usr/sbin/ftvpn "${REPO}files/ftvpn" >/dev/null 2>&1
    chmod +x /usr/sbin/ftvpn

    # Configure iptables for BitTorrent blocking
    iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
    iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
    iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
    iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
    iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
    iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
    iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
    iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP

    iptables-save > /etc/iptables.up.rules
    iptables-restore -t < /etc/iptables.up.rules
    netfilter-persistent save
    netfilter-persistent reload

    # Clean up unnecessary files
    apt autoclean -y >/dev/null 2>&1
    apt autoremove -y >/dev/null 2>&1
    
    print_success "ePro WebSocket Proxy installed"
}

function ins_restart(){
    clear
    print_install "Restarting all services"

    # Restart services
    /etc/init.d/nginx restart
    /etc/init.d/openvpn restart
    /etc/init.d/ssh restart
    /etc/init.d/dropbear restart
    /etc/init.d/fail2ban restart
    /etc/init.d/vnstat restart
    systemctl restart haproxy
    /etc/init.d/cron restart

    # Enable and start services
    systemctl daemon-reload
    systemctl enable --now nginx
    systemctl enable --now xray
    systemctl enable --now rc-local
    systemctl enable --now dropbear
    systemctl enable --now openvpn
    systemctl enable --now cron
    systemctl enable --now haproxy
    systemctl enable --now netfilter-persistent
    systemctl enable --now ws
    systemctl enable --now fail2ban

    # Clear history and remove temporary files
    history -c
    echo "unset HISTFILE" >> /etc/profile
    cd
    rm -f /root/openvpn /root/key.pem /root/cert.pem
    
    print_success "All services restarted"
}

function menu(){
    clear
    print_install "Installing Packet Menu"
    
    wget -q "${REPO}menu/menu.zip" || { echo "Failed to download menu.zip"; return 1; }
    unzip -q menu.zip
    sed -i 's/\r$//' /usr/local/sbin/*
    chmod +x menu/*
    mv menu/* /usr/local/sbin
    rm -rf menu
    rm -f menu.zip
}

# Create Default Menu 
function profile(){
    clear
    cat > /root/.profile <<EOF
# ~/.profile: executed by Bourne-compatible login shells.
if [ "\$BASH" ]; then
    if [ -f ~/.bashrc ]; then
        . ~/.bashrc
    fi
fi
mesg n || true
menu
EOF

    cat > /etc/cron.d/xp_all <<-END
        SHELL=/bin/sh
        PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
        2 0 * * * root /usr/local/sbin/xp
    END
    
    cat > /etc/cron.d/logclean <<-END
        SHELL=/bin/sh
        PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
        */20 * * * * root /usr/local/sbin/clearlog
    END
    
    chmod 644 /root/.profile

    cat > /etc/cron.d/daily_reboot <<-END
        SHELL=/bin/sh
        PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
        0 5 * * * root /sbin/reboot
    END
    
    cat > /etc/cron.d/limit_ip <<-END
        SHELL=/bin/sh
        PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
        */2 * * * * root /usr/local/sbin/limit-ip
    END
    
    cat > /etc/cron.d/limit_ip2 <<-END
        SHELL=/bin/sh
        PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
        */2 * * * * root /usr/bin/limit-ip
    END
    
    echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" > /etc/cron.d/log.nginx
    echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >> /etc/cron.d/log.xray

    service cron restart
    
    cat > /home/daily_reboot <<-END
        5
    END

    cat > /etc/systemd/system/rc-local.service <<EOF
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
EOF

    echo "/bin/false" >> /etc/shells
    echo "/usr/sbin/nologin" >> /etc/shells

    cat > /etc/rc.local <<EOF
#!/bin/sh -e
# rc.local
# By default this script does nothing.
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent
exit 0
EOF

    chmod +x /etc/rc.local

    AUTOREB=$(cat /home/daily_reboot)
    SETT=11
    if [ "$AUTOREB" -gt "$SETT" ]; then
        TIME_DATE="PM"
    else
        TIME_DATE="AM"
    fi
    
    print_success "Menu Packet installed"
}

# Restart services after installation
function enable_services(){
    clear
    print_install "Enabling Services"
    
    systemctl daemon-reload
    systemctl start netfilter-persistent
    systemctl enable --now rc-local
    systemctl enable --now cron
    systemctl enable --now netfilter-persistent
    systemctl restart nginx
    systemctl restart xray
    systemctl restart cron
    systemctl restart haproxy
    
    print_success "Services enabled"
    clear
}

# Installation Script Function
function instal(){
    clear
    is_root
    print_install "Starting Installation"
    directory_install
    first_setup
    nginx_install
    base_package
    make_folder_xray
    pasang_domain
    password_default
    pasang_ssl
    install_xray
    ssh
    udp_mini
    ssh_slow
    ins_SSHD
    ins_dropbear
    ins_vnstat
    ins_openvpn
    ins_backup
    ins_swap
    ins_Fail2ban
    ins_epro
    ins_restart
    menu
    profile
    enable_services
    restart_system
}

# Execute Installation
instal

echo ""
history -c
rm -rf /root/menu
rm -rf /root/*.zip
rm -rf /root/*.sh
rm -rf /root/domain

# Set the hostname
sudo hostnamectl set-hostname "$username"

echo -e "${green} Script successfully installed"
echo ""

read -p "$(echo -e "Press ${YELLOW}[ ${NC}${YELLOW}Enter${NC} ${YELLOW}]${NC} to reboot") "
reboot
