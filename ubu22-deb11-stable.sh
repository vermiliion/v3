#!/bin/bash

# Definisi Warna
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

# Ekspor IP Address Information
export IP=$(curl -sS icanhazip.com)

# Bersihkan layar
clear

# Banner
echo -e "${YELLOW}_____________________________________${NC}"
echo -e "  EDIT BY : ${green}LITE  ${NC}${YELLOW}(${NC} ${green} TUNNELING-NETWORK${NC}${YELLOW})${NC}"
echo -e "${YELLOW}_____________________________________${NC}"
echo ""
sleep 2

###### IZIN SC 

# Memeriksa Arsitektur OS
if [[ $(uname -m | awk '{print $1}') == "x86_64" ]]; then
    echo -e "${OK} Your Architecture Is Supported ( ${green}$(uname -m)${NC} )"
else
    echo -e "${ERROR} Your Architecture Is Not Supported ( ${YELLOW}$(uname -m)${NC} )"
    exit 1
fi

# Memeriksa Sistem Operasi
OS_ID=$(grep -w ID /etc/os-release | head -n1 | cut -d'=' -f2 | tr -d '"')
OS_PRETTY_NAME=$(grep -w PRETTY_NAME /etc/os-release | head -n1 | cut -d'=' -f2 | tr -d '"')

if [[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" ]]; then
    echo -e "${OK} Your OS Is Supported ( ${green}$OS_PRETTY_NAME${NC} )"
else
    echo -e "${ERROR} Your OS Is Not Supported ( ${YELLOW}$OS_PRETTY_NAME${NC} )"
    exit 1
fi

# Validasi Alamat IP
if [[ -z "$IP" ]]; then
    echo -e "${ERROR} IP Address ( ${YELLOW}Not Detected${NC} )"
    exit 1
else
    echo -e "${OK} IP Address ( ${green}$IP${NC} )"
fi

# Validasi Sukses
echo ""
read -p "$(echo -e "Press ${GRAY}[ ${NC}${green}Enter${NC} ${GRAY}]${NC} For Starting Installation") "
echo ""
clear

# Memeriksa apakah menjalankan sebagai root
if [ "${EUID}" -ne 0 ]; then
    echo "You need to run this script as root"
    exit 1
fi

# Memeriksa apakah menggunakan OpenVZ
if [ "$(systemd-detect-virt)" == "openvz" ]; then
    echo "OpenVZ is not supported"
    exit 1
fi

# Reset Warna
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'

# IZIN SCRIPT
MYIP=$(curl -sS ipv4.icanhazip.com)
echo -e "\e[32mloading...\e[0m"
clear

# Instalasi Awal
apt update -y
apt install -y ruby lolcat wondershaper

clear

# REPO    
REPO="https://raw.githubusercontent.com/vermiliion/v3/main/"

####
start=$(date +%s)

secs_to_human() {
    echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"
}

### Status
function print_ok() {
    echo -e "${OK} ${BLUE} $1 ${FONT}"
}

function print_install() {
    echo -e "${green} ☉━━━━━━━━━━━━━━━━━━━━━━━☉ ${FONT}"
    echo -e "${YELLOW} # $1 ${FONT}"
    echo -e "${green} ☉━━━━━━━━━━━━━━━━━━━━━━━☉ ${FONT}"
    sleep 1
}

function print_error() {
    echo -e "${ERROR} ${REDBG} $1 ${FONT}"
}

function print_success() {
    if [[ $? -eq 0 ]]; then
        echo -e "${green} ☉━━━━━━━━━━━━━━━━━━━━━━━☉ ${FONT}"
        echo -e "${Green} # $1 berhasil dipasang"
        echo -e "${green} ☉━━━━━━━━━━━━━━━━━━━━━━━☉ ${FONT}"
        sleep 2
    fi
}

### Cek root
function is_root() {
    if [[ 0 == "$UID" ]]; then
        print_ok "Root user Start installation process"
    else
        print_error "The current user is not the root user, please switch to the root user and run the script again"
    fi
}

# Buat direktori xray
print_install "Membuat direktori xray"
mkdir -p /etc/xray
curl -s ifconfig.me > /etc/xray/ipvps
touch /etc/xray/domain
mkdir -p /var/log/xray
chown www-data:www-data /var/log/xray
chmod 755 /var/log/xray
touch /var/log/xray/access.log
touch /var/log/xray/error.log
mkdir -p /var/lib/kyt >/dev/null 2>&1

# Informasi Ram
while IFS=":" read -r a b; do
    case $a in
        "MemTotal") ((mem_used+=${b/kB})); mem_total="${b/kB}" ;;
        "Shmem") ((mem_used+=${b/kB}))  ;;
        "MemFree" | "Buffers" | "Cached" | "SReclaimable")
            mem_used="$((mem_used-=${b/kB}))"
            ;;
    esac
done < /proc/meminfo
Ram_Usage="$((mem_used / 1024))"
Ram_Total="$((mem_total / 1024))"
export tanggal=$(date +"%d-%m-%Y - %X")
export OS_Name=$(grep -w PRETTY_NAME /etc/os-release | head -n1 | cut -d'=' -f2 | tr -d '"')
export Kernel=$(uname -r)
export Arch=$(uname -m)
export IP=$(curl -s https://ipinfo.io/ip/)

# Change Environment System
function first_setup(){
    timedatectl set-timezone Asia/Makassar
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    print_success "Directory Xray"

    if [[ "$(grep -w ID /etc/os-release | head -n1 | cut -d'=' -f2 | tr -d '"')" == "ubuntu" ]]; then
        echo "Setup Dependencies $OS_PRETTY_NAME"
        apt update -y
        apt-get install --no-install-recommends software-properties-common -y
        add-apt-repository ppa:vbernat/haproxy-2.4 -y
        apt-get -y install haproxy=2.4.*
    elif [[ "$(grep -w ID /etc/os-release | head -n1 | cut -d'=' -f2 | tr -d '"')" == "debian" ]]; then
        echo "Setup Dependencies For OS Is $OS_PRETTY_NAME"
        curl https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg
        echo deb "[signed-by=/usr/share/keyrings/haproxy.debian.net.gpg]" \
            http://haproxy.debian.net bullseye-backports-2.2 main \
            >/etc/apt/sources.list.d/haproxy.list
        apt-get update -y
        apt-get -y install haproxy=2.2.*
    else
        echo -e " Your OS Is Not Supported ($OS_PRETTY_NAME)"
        exit 1
    fi
}

# GEO PROJECT
clear
function nginx_install() {
    # Memeriksa Sistem
    OS_ID=$(grep -w ID /etc/os-release | head -n1 | cut -d'=' -f2 | tr -d '"')
    OS_PRETTY_NAME=$(grep -w PRETTY_NAME /etc/os-release | head -n1 | cut -d'=' -f2 | tr -d '"')

    if [[ "$OS_ID" == "ubuntu" ]]; then
        print_install "Setup nginx For OS Is $OS_PRETTY_NAME"
        apt-get install -y nginx
    elif [[ "$OS_ID" == "debian" ]]; then
        print_success "Setup nginx For OS Is $OS_PRETTY_NAME"
        apt -y install nginx
    else
        echo -e " Your OS Is Not Supported ( ${YELLOW}$OS_PRETTY_NAME${FONT} )"
    fi
}

# Update and remove packages
function base_package() {
    clear
    ########
    print_install "Menginstall Paket yang Dibutuhkan"
    apt install -y zip pwgen openssl netcat socat cron bash-completion figlet
    apt update -y
    apt upgrade -y
    apt dist-upgrade -y
    systemctl enable chronyd
    systemctl restart chronyd
    systemctl enable chrony
    systemctl restart chrony
    chronyc sourcestats -v
    chronyc tracking -v
    apt install -y ntpdate sudo
    apt-get clean all
    apt-get autoremove -y
    apt-get install -y debconf-utils
    apt-get remove --purge -y exim4 ufw firewalld
    apt-get install -y --no-install-recommends software-properties-common
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    apt-get install -y speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make libnss3-tools libevent-dev bc rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev sed dirmngr libxml-parser-perl build-essential gcc g++ python htop lsof tar wget curl ruby zip unzip p7zip-full python3-pip libc6 util-linux msmtp-mta ca-certificates bsd-mailx iptables iptables-persistent netfilter-persistent net-tools openssl ca-certificates gnupg gnupg2 lsb-release shc make cmake git screen socat xz-utils apt-transport-https gnupg1 dnsutils cron bash-completion ntpdate chrony jq openvpn easy-rsa
    print_success "Paket yang Dibutuhkan"
}

clear
# Fungsi input domain
function pasang_domain() {
    echo -e ""
    clear
    echo -e "   .----------------------------------."
    echo -e "   |\e[1;32mPlease Select a Domain Type Below \e[0m|"
    echo -e "   '----------------------------------'"
    echo -e "     \e[1;32m1)\e[0m Menggunakan Domain Sendiri"
    echo -e "     \e[1;32m2)\e[0m Menggunakan Domain Random"
    echo -e "   ------------------------------------"
    read -p "   Please select numbers 1-2 or Any Button(Random) : " host
    echo ""
    if [[ "$host" == "1" ]]; then
        echo -e "   \e[1;32mPlease Enter Your Subdomain ${NC}"
        read -p "   Subdomain: " host1
        echo "IP=" >> /var/lib/kyt/ipvps.conf
        echo "$host1" > /etc/xray/domain
        echo "$host1" > /root/domain
        echo ""
    elif [[ "$host" == "2" ]]; then
        # Install Cloudflare (cf.sh)
        wget -q ${REPO}files/cf.sh && chmod +x cf.sh && ./cf.sh
        rm -f /root/cf.sh
        clear
    else
        print_install "Random Subdomain/Domain is Used"
        clear
    fi
}

clear
# GANTI PASSWORD DEFAULT
restart_system(){
    # IZIN SCRIPT
    MYIP=$(curl -sS ipv4.icanhazip.com)
    echo -e "\e[32mloading...\e[0m" 
    clear
    izinsc="https://raw.githubusercontent.com/vermiliion/izin/main/ip"

    # USERNAME
    rm -f /usr/bin/user
    username=$(curl -s $izinsc | grep "$MYIP" | awk '{print $2}')
    echo "$username" >/usr/bin/user
    expx=$(curl -s $izinsc | grep "$MYIP" | awk '{print $3}')
    echo "$expx" >/usr/bin/e

    # DETAIL ORDER
    username=$(cat /usr/bin/user)
    oid=$(cat /usr/bin/ver 2>/dev/null || echo "N/A")
    exp=$(cat /usr/bin/e 2>/dev/null || echo "N/A")
    clear

    # CERTIFICATE STATUS
    d1=$(date -d "$valid" +%s 2>/dev/null || echo "0")
    d2=$(date -d "$today" +%s 2>/dev/null || echo "0")
    certifacate=$(((d1 - d2) / 86400))

    # VPS Information
    DATE=$(date +'%Y-%m-%d')
    today=$(date +"%Y-%m-%d")
    Exp1=$(curl -s $izinsc | grep "$MYIP" | awk '{print $4}')

    # Status Expired Active
    Info="(${green}Active${NC})"
    Error="(${RED}ExpiRED${NC})"

    if [[ "$today" < "$Exp1" ]]; then
        sts="${Info}"
    else
        sts="${Error}"
    fi

    # Telegram Notification
    TIMES="10"
    CHATID="5092269467"
    KEY="YOUR_TELEGRAM_BOT_TOKEN"
    URL="https://api.telegram.org/bot$KEY/sendMessage"
    TIMEZONE=$(printf '%(%H:%M:%S)T')

    TEXT="
<code>────────────────────</code>
<b>🍄 AUTOSCRIPT LITE 🍄</b>
<code>────────────────────</code>
<code>User     :</code><code>$username</code>
<code>Domain   :</code><code>$domain</code>
<code>IPVPS    :</code><code>$MYIP</code>
<code>ISP      :</code><code>$ISP</code>
<code>Exp Sc.  :</code><code>$exp</code>
<code>────────────────────</code>
   <b>🔑 LITE VERMILION 🔑</b>
<code>────────────────────</code>
<i>Automatic Notifications From Github</i>
\"&reply_markup={\"inline_keyboard\":[[{\"text\":\"ᴏʀᴅᴇʀ\",\"url\":\"https://wa.me/6283867809137\"}]]}\"
"

    curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
}

clear
# Pasang SSL
function pasang_ssl() {
    clear
    print_install "Memasang SSL Pada Domain"
    rm -rf /etc/xray/xray.key /etc/xray/xray.crt
    domain=$(cat /root/domain)
    
    # Tentukan Web Server yang Berjalan di Port 80
    STOPWEBSERVER=$(lsof -i:80 | awk 'NR==2 {print $1}')
    
    # Hentikan Web Server
    if [[ -n "$STOPWEBSERVER" ]]; then
        systemctl stop "$STOPWEBSERVER"
        systemctl disable "$STOPWEBSERVER"
    fi
    
    # Pasang ACME.sh
    rm -rf /root/.acme.sh
    mkdir /root/.acme.sh
    curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    /root/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256
    /root/.acme.sh/acme.sh --installcert -d "$domain" --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
    chmod 600 /etc/xray/xray.key
    print_success "SSL Certificate"
}

function make_folder_xray() {
    # Hapus Database Lama
    rm -rf /etc/vmess/.vmess.db /etc/vless/.vless.db /etc/trojan/.trojan.db /etc/shadowsocks/.shadowsocks.db /etc/ssh/.ssh.db /etc/bot/.bot.db /etc/user-create/user.log

    # Buat Direktori Baru
    mkdir -p /etc/bot /etc/xray /etc/vmess /etc/vless /etc/trojan /etc/shadowsocks /etc/ssh /usr/bin/xray/ /var/log/xray/ /var/www/html
    mkdir -p /etc/kyt/limit/vmess/ip /etc/kyt/limit/vless/ip /etc/kyt/limit/trojan/ip /etc/kyt/limit/ssh/ip
    mkdir -p /etc/limit/vmess /etc/limit/vless /etc/limit/trojan /etc/limit/ssh /etc/user-create

    # Atur Izin
    chmod 755 /var/log/xray

    # Buat File Konfigurasi dan Log
    touch /etc/xray/domain
    touch /var/log/xray/access.log /var/log/xray/error.log
    touch /etc/vmess/.vmess.db /etc/vless/.vless.db /etc/trojan/.trojan.db /etc/shadowsocks/.shadowsocks.db /etc/ssh/.ssh.db /etc/bot/.bot.db
    echo "& plughin Account" >> /etc/vmess/.vmess.db
    echo "& plughin Account" >> /etc/vless/.vless.db
    echo "& plughin Account" >> /etc/trojan/.trojan.db
    echo "& plughin Account" >> /etc/shadowsocks/.shadowsocks.db
    echo "& plughin Account" >> /etc/ssh/.ssh.db
    echo "echo -e 'Vps Config User Account'" >> /etc/user-create/user.log
}

# Instal Xray
function install_xray() {
    clear
    print_install "Core Xray 2.2.1 Latest Version"
    domainSock_dir="/run/xray"
    [ ! -d "$domainSock_dir" ] && mkdir "$domainSock_dir"
    chown www-data:www-data "$domainSock_dir"
    
    # Ambil Xray Core Version Terbaru dan Install
    latest_version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep tag_name | cut -d '"' -f4)
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version "$latest_version"
    
    # Ambil Konfigurasi Server
    wget -q -O /etc/xray/config.json "${REPO}config/config.json"
    wget -q -O /etc/systemd/system/runn.service "${REPO}files/runn.service"
    
    domain=$(cat /etc/xray/domain)
    IPVS=$(cat /etc/xray/ipvps)
    print_success "Core Xray Latest Version"
    
    # Pengaturan Nginx Server
    clear
    curl -s ipinfo.io/city > /etc/xray/city
    curl -s ipinfo.io/org | cut -d " " -f2-10 > /etc/xray/isp
    print_install "Memasang Konfigurasi Paket"
    
    wget -q -O /etc/haproxy/haproxy.cfg "${REPO}config/haproxy.cfg"
    wget -q -O /etc/nginx/conf.d/xray.conf "${REPO}config/xray.conf"
    sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
    curl -s "${REPO}config/nginx.conf" > /etc/nginx/nginx.conf
    
    cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem
    
    # Set Izin
    chmod +x /etc/systemd/system/runn.service
    
    # Buat dan Aktifkan Layanan Xray
    rm -rf /etc/systemd/system/xray.service.d
    cat >/etc/systemd/system/xray.service <<EOF
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
    systemctl daemon-reload
    systemctl enable xray
    systemctl restart xray
    print_success "Konfigurasi Paket"
}

function ssh(){
    clear
    print_install "Memasang Password SSH"
    wget -q -O /etc/pam.d/common-password "${REPO}files/password"
    chmod 644 /etc/pam.d/common-password
    
    DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/altgr select The default for the keyboard layout"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/compose select No compose key"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/ctrl_alt_bksp boolean false"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layoutcode string de"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout select English"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/modelcode string pc105"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/model select Generic 105-key (Intl) PC"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/optionscode string "
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/store_defaults_in_debconf_db boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/switch select No temporary switch"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/toggle select No toggling"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_layout boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_options boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_layout boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_options boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variantcode string "
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variant select English"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/xkb-keymap select "

    # Buat dan Atur rc-local
    cat > /etc/systemd/system/rc-local.service <<-END
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
END

    # Buat /etc/rc.local
    cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END

    # Ubah izin akses
    chmod +x /etc/rc.local

    # Aktifkan rc-local
    systemctl enable rc-local
    systemctl start rc-local.service

    # Disable IPv6
    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
    sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

    # Update dan Set Timezone
    ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

    # Set Locale untuk SSH
    sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
    systemctl restart ssh

    print_success "Password SSH"
}

function udp_mini(){
    clear
    print_install "Memasang Service Limit IP & Quota"
    wget -q https://raw.githubusercontent.com/vermiliion/v3/main/config/fv-tunnel && chmod +x fv-tunnel && ./fv-tunnel

    # Installing UDP Mini
    mkdir -p /usr/local/kyt/
    wget -q -O /usr/local/kyt/udp-mini "${REPO}files/udp-mini"
    chmod +x /usr/local/kyt/udp-mini
    wget -q -O /etc/systemd/system/udp-mini-1.service "${REPO}files/udp-mini-1.service"
    wget -q -O /etc/systemd/system/udp-mini-2.service "${REPO}files/udp-mini-2.service"
    wget -q -O /etc/systemd/system/udp-mini-3.service "${REPO}files/udp-mini-3.service"

    # Aktifkan dan Mulai Layanan UDP Mini
    for service in udp-mini-1 udp-mini-2 udp-mini-3; do
        systemctl disable "$service"
        systemctl stop "$service"
        systemctl enable "$service"
        systemctl start "$service"
    done

    print_success "Limit IP Service"
}

function ssh_slow(){
    clear
    print_install "Memasang modul SlowDNS Server"
    wget -q -O /tmp/nameserver "${REPO}files/nameserver" >/dev/null 2>&1
    chmod +x /tmp/nameserver
    bash /tmp/nameserver | tee /root/install.log
    print_success "SlowDNS"
}

clear
function ins_SSHD(){
    clear
    print_install "Memasang SSHD"
    wget -q -O /etc/ssh/sshd_config "${REPO}files/sshd" >/dev/null 2>&1
    chmod 644 /etc/ssh/sshd_config

    # Restart dan Aktifkan SSH menggunakan systemctl
    systemctl restart ssh
    systemctl enable ssh
    systemctl status ssh --no-pager

    print_success "SSHD"
}

clear
function ins_dropbear(){
    clear
    print_install "Menginstall Dropbear"
    # Instal Dropbear
    apt-get install -y dropbear > /dev/null 2>&1

    # Unduh konfigurasi Dropbear
    wget -q -O /etc/default/dropbear "${REPO}config/dropbear.conf"
    chmod 644 /etc/default/dropbear

    # Restart dan Aktifkan Dropbear menggunakan systemctl
    systemctl restart dropbear
    systemctl enable dropbear
    systemctl status dropbear --no-pager

    print_success "Dropbear"
}

clear
function ins_vnstat(){
    clear
    print_install "Menginstall Vnstat"
    # Instal vnstat
    apt -y install vnstat > /dev/null 2>&1
    systemctl restart vnstat
    apt -y install libsqlite3-dev > /dev/null 2>&1

    # Instalasi Vnstat dari Sumber
    wget -q https://humdi.net/vnstat/vnstat-2.6.tar.gz
    tar zxvf vnstat-2.6.tar.gz
    cd vnstat-2.6
    ./configure --prefix=/usr --sysconfdir=/etc && make && make install
    cd
    rm -rf vnstat-2.6 vnstat-2.6.tar.gz

    # Konfigurasi Vnstat
    NET=$(ip -4 route ls | grep default | grep -oP '(?<=dev )\w+')
    vnstat -u -i "$NET"
    sed -i "s/Interface \"eth0\"/Interface \"$NET\"/g" /etc/vnstat.conf
    chown vnstat:vnstat /var/lib/vnstat -R
    systemctl enable vnstat
    systemctl restart vnstat
    systemctl status vnstat --no-pager
    print_success "Vnstat"
}

function ins_openvpn(){
    clear
    print_install "Menginstall OpenVPN"
    # Instal OpenVPN dan Easy-RSA
    apt update -y
    apt install -y openvpn easy-rsa

    # Setup Easy-RSA
    make-cadir /etc/openvpn/easy-rsa
    cd /etc/openvpn/easy-rsa

    # Inisialisasi PKI dan buat sertifikat
    ./easyrsa init-pki
    ./easyrsa build-ca nopass
    ./easyrsa gen-req server nopass
    echo yes | ./easyrsa sign-req server server
    ./easyrsa gen-dh

    # Salin sertifikat dan kunci
    cp pki/ca.crt pki/private/server.key pki/issued/server.crt /etc/openvpn/
    cp pki/dh.pem /etc/openvpn/

    # Buat file konfigurasi OpenVPN
    cat > /etc/openvpn/server.conf <<EOF
port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
keepalive 10 120
cipher AES-256-CBC
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
log-append /var/log/openvpn.log
verb 3
EOF

    # Aktifkan IP forwarding
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    sysctl -p

    # Atur iptables untuk NAT
    NET=$(ip -4 route ls | grep default | grep -oP '(?<=dev )\w+')
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$NET" -j MASQUERADE
    netfilter-persistent save

    # Start dan enable OpenVPN menggunakan systemctl
    systemctl start openvpn@server
    systemctl enable openvpn@server
    systemctl status openvpn@server --no-pager

    print_success "OpenVPN"
}

function ins_backup(){
    clear
    print_install "Memasang Backup Server"
    # Backup Option
    apt install -y rclone
    printf "q\n" | rclone config
    wget -q -O /root/.config/rclone/rclone.conf "${REPO}config/rclone.conf"

    # Install Wondershaper dari Sumber
    cd /bin
    git clone https://github.com/magnific0/wondershaper.git
    cd wondershaper
    make install
    cd
    rm -rf wondershaper

    echo > /home/limit
    apt install -y msmtp-mta ca-certificates bsd-mailx

    # Konfigurasi msmtp
    cat <<EOF >/etc/msmtprc
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt

account default
host smtp.gmail.com
port 587
auth on
user oceantestdigital@gmail.com
from oceantestdigital@gmail.com
password jokerman77
logfile ~/.msmtp.log
EOF

    chown -R www-data:www-data /etc/msmtprc
    wget -q -O /etc/ipserver "${REPO}files/ipserver" && bash /etc/ipserver
    print_success "Backup Server"
}

clear
function ins_swab(){
    clear
    print_install "Memasang Swap 1 G"
    # Instal gotop
    gotop_latest=$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases/latest | grep tag_name | cut -d '"' -f4)
    gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v${gotop_latest}_linux_amd64.deb"
    curl -sL "$gotop_link" -o /tmp/gotop.deb
    dpkg -i /tmp/gotop.deb >/dev/null 2>&1
    apt -f install -y

    # Buat swap sebesar 1G
    if [ ! -f /swapfile ]; then
        dd if=/dev/zero of=/swapfile bs=1M count=1024
        mkswap /swapfile
        chown root:root /swapfile
        chmod 600 /swapfile
        swapon /swapfile
        echo '/swapfile swap swap defaults 0 0' >> /etc/fstab
    fi

    # Sinkronisasi jam
    chronyd -q 'server 0.id.pool.ntp.org iburst'
    chronyc sourcestats -v
    chronyc tracking -v

    # Instal BBR
    wget -q -O /usr/local/bin/bbr.sh "${REPO}files/bbr.sh"
    chmod +x /usr/local/bin/bbr.sh
    bash /usr/local/bin/bbr.sh
    rm -f /usr/local/bin/bbr.sh

    print_success "Swap 1 G"
}

function ins_Fail2ban(){
    clear
    print_install "Menginstall Fail2ban"
    # Instal Fail2ban
    apt -y install fail2ban > /dev/null 2>&1
    systemctl enable fail2ban
    systemctl restart fail2ban
    systemctl status fail2ban --no-pager

    # Instal DDoS Flate
    if [ -d '/usr/local/ddos' ]; then
        echo -e "\nPlease un-install the previous version first"
        exit 0
    else
        mkdir /usr/local/ddos
    fi

    clear
    # Set Banner
    echo "Banner /etc/kyt.txt" >> /etc/ssh/sshd_config
    sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/kyt.txt"@g' /etc/default/dropbear

    # Ganti Banner
    wget -q -O /etc/kyt.txt "${REPO}files/issue.net"
    print_success "Fail2ban"
}

function ins_epro(){
    clear
    print_install "Menginstall ePro WebSocket Proxy"
    wget -q -O /usr/bin/ws "${REPO}files/ws" >/dev/null 2>&1
    wget -q -O /usr/bin/tun.conf "${REPO}config/tun.conf" >/dev/null 2>&1
    wget -q -O /etc/systemd/system/ws.service "${REPO}files/ws.service" >/dev/null 2>&1

    chmod +x /usr/bin/ws
    chmod 644 /usr/bin/tun.conf
    chmod 644 /etc/systemd/system/ws.service

    # Restart dan Aktifkan Layanan ws
    systemctl disable ws
    systemctl stop ws
    systemctl enable ws
    systemctl start ws
    systemctl restart ws

    # Unduh geosite dan geoip
    wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
    wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"

    # Instal ftvpn
    wget -q -O /usr/sbin/ftvpn "${REPO}files/ftvpn" >/dev/null 2>&1
    chmod +x /usr/sbin/ftvpn

    # Atur iptables untuk memblokir traffic tertentu
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

    # Hapus file yang tidak diperlukan
    cd
    apt autoclean -y >/dev/null 2>&1
    apt autoremove -y >/dev/null 2>&1

    print_success "ePro WebSocket Proxy"
}

function ins_restart(){
    clear
    print_install "Restarting All Services"
    # Restart layanan menggunakan systemctl
    systemctl restart nginx
    systemctl restart openvpn@server
    systemctl restart ssh
    systemctl restart dropbear
    systemctl restart fail2ban
    systemctl restart vnstat
    systemctl restart haproxy
    systemctl restart cron
    systemctl daemon-reload
    systemctl start netfilter-persistent
    systemctl enable --now nginx
    systemctl enable --now xray
    systemctl enable --now rc-local
    systemctl enable --now dropbear
    systemctl enable --now openvpn@server
    systemctl enable --now cron
    systemctl enable --now haproxy
    systemctl enable --now netfilter-persistent
    systemctl enable --now ws
    systemctl enable --now fail2ban

    history -c
    echo "unset HISTFILE" >> /etc/profile

    cd
    rm -f /root/openvpn /root/key.pem /root/cert.pem
    print_success "All Services Restarted"
}

# Instal Menu
function menu(){
    clear
    print_install "Memasang Menu Paket"
    wget -q "${REPO}menu/menu.zip"
    unzip -q menu.zip
    chmod +x menu/*
    mv menu/* /usr/local/sbin
    rm -rf menu menu.zip
}

# Membuat Default Menu 
function profile(){
    clear
    cat >/root/.profile <<EOF
# ~/.profile: executed by Bourne-compatible login shells.
if [ "\$BASH" ]; then
    if [ -f ~/.bashrc ]; then
        . ~/.bashrc
    fi
fi
mesg n || true
menu
EOF

    # Buat Cron Jobs
    cat >/etc/cron.d/xp_all <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
2 0 * * * root /usr/local/sbin/xp
END

    cat >/etc/cron.d/logclean <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/20 * * * * root /usr/local/sbin/clearlog
END

    chmod 644 /root/.profile

    cat >/etc/cron.d/daily_reboot <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 5 * * * root /sbin/reboot
END

    cat >/etc/cron.d/limit_ip <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/2 * * * * root /usr/local/sbin/limit-ip
END

    cat >/etc/cron.d/limit_ip2 <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/2 * * * * root /usr/bin/limit-ip
END

    # Buat Log Cron
    echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx
    echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >>/etc/cron.d/log.xray

    # Restart Cron
    systemctl restart cron

    # Buat File daily_reboot
    cat >/home/daily_reboot <<-END
5
END

    # Buat dan Atur rc-local.service
    cat >/etc/systemd/system/rc-local.service <<EOF
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

    # Tambahkan Shell ke /etc/shells
    echo "/bin/false" >>/etc/shells
    echo "/usr/sbin/nologin" >>/etc/shells

    # Buat /etc/rc.local dengan iptables
    cat >/etc/rc.local <<EOF
#!/bin/sh -e
# rc.local
# By default this script does nothing.
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent
exit 0
EOF

    # Ubah izin akses
    chmod +x /etc/rc.local

    # Tentukan Autoreboot
    AUTOREB=$(cat /home/daily_reboot)
    SETT=11
    if [ "$AUTOREB" -gt "$SETT" ]; then
        TIME_DATE="PM"
    else
        TIME_DATE="AM"
    fi

    print_success "Menu Paket"
}

# Restart layanan after install
function enable_services(){
    clear
    print_install "Enable Services"
    systemctl daemon-reload
    systemctl start netfilter-persistent
    systemctl enable --now rc-local
    systemctl enable --now cron
    systemctl enable --now netfilter-persistent
    systemctl restart nginx
    systemctl restart xray
    systemctl restart cron
    systemctl restart haproxy
    print_success "Enable Services"
    clear
}

# Fungsi Install Script
function instal(){
    clear
    first_setup
    nginx_install
    base_package
    make_folder_xray
    pasang_domain
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
    ins_swab
    ins_Fail2ban
    ins_epro
    ins_restart
    menu
    profile
    enable_services
    restart_system
}

instal

# Bersihkan histori dan file yang tidak diperlukan
echo ""
history -c
rm -rf /root/menu /root/*.zip /root/*.sh /root/LICENSE /root/README.md /root/domain

# Atur hostname
secs_to_human "$(($(date +%s) - ${start}))"
hostnamectl set-hostname "$username"

echo -e "${green} Script Successfully Installed"
echo ""
read -p "$(echo -e "Press ${YELLOW}[ ${NC}${YELLOW}Enter${NC} ${YELLOW}]${NC} For reboot") "
reboot
