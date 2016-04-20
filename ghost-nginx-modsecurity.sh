#!/bin/bash
#
# Use this automated bash script to install the latest Ghost blog on Ubuntu or Debian,
# with Nginx (as a reverse proxy) and ModSecurity web application firewall.
#
# It should only be used on a Virtual Private Server (VPS) or dedicated server,
# with *freshly installed* Ubuntu LTS or Debian 8.
#
# *DO NOT* run this script on your PC or Mac!
#
# Copyright (C) 2015-2016 Lin Song
# Based on the work of Herman Stevens (Copyright 2013)
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program. If not, see http://www.gnu.org/licenses/.

os_type="$(lsb_release -si 2>/dev/null)"
if [ "$os_type" != "Ubuntu" ] && [ "$os_type" != "Debian" ]; then
  echo "This script only supports Ubuntu or Debian systems."
  exit 1
fi

if [ "$os_type" = "Ubuntu" ]; then
os_ver="$(lsb_release -sr)"
if [ "$os_ver" != "16.04" ] && [ "$os_ver" != "14.04" ] && [ "$os_ver" != "12.04" ]; then
  echo "This script only supports Ubuntu 16.04, 14.04 and 12.04."
  exit 1
fi
fi

if [ "$os_type" = "Debian" ]; then
os_ver="$(sed 's/\..*//' /etc/debian_version 2>/dev/null)"
if [ "$os_ver" != "8" ]; then
  echo "This script only supports Debian 8 (Jessie)."
  exit 1
fi
fi

if [ "$(id -u)" != 0 ]; then
  echo "Script must be run as root. Try 'sudo bash $0'"
  exit 1
fi

phymem="$(free | awk '/^Mem:/{print $2}')"
[ -z "$phymem" ] && phymem=500000
if [ "$phymem" -lt 500000 ]; then
  echo "This server does not have enough RAM. Setup cannot continue."
  echo "A minimum of 512MB RAM is required for Ghost blog install."
  exit 1
fi

if id -u ghost >/dev/null 2>&1; then
  echo "User 'ghost' already exists! Setup cannot continue."
  echo "Please use this script on a freshly installed system."
  exit 1
fi

if [ "$1" = "" ] || [ "$1" = "BLOG_FULL_DOMAIN_NAME" ]; then
  script_name=$(basename "$0")
  echo "Usage: sudo bash $script_name BLOG_FULL_DOMAIN_NAME"
  echo '(Replace the above with your actual domain name)'
  exit 1
fi

clear
echo 'Welcome! This script installs Ghost blog (https://ghost.org) on your server,'
echo 'with Nginx (as a reverse proxy) and Modsecurity web application firewall.'
echo
echo 'The fully qualified domain name (FQDN) for your new blog is:'
echo
echo "$1"
echo
echo 'Please double check. This MUST be correct for your blog to work!'
echo
echo 'IMPORTANT NOTES:'
echo 'This script should only be used on a Virtual Private Server (VPS) or dedicated server,'
echo 'with *freshly installed* Ubuntu LTS or Debian 8. At least 512MB RAM is required.'
echo '*DO NOT* run this script on your PC or Mac!'
echo

read -r -p "Confirm and proceed with the install? [y/N] " response
case $response in
    [yY][eE][sS]|[yY])
        echo
        echo "Please be patient. Setup is continuing..."
        echo
        ;;
    *)
        echo "Aborting."
        exit 1
        ;;
esac

BLOG_FQDN=$1
export BLOG_FQDN
echo "$BLOG_FQDN" > /tmp/BLOG_FQDN

# Create and change to working dir
mkdir -p /opt/src
cd /opt/src || { echo "Failed to change directory to /opt/src. Aborting."; exit 1; }

# Before doing anything else, we update the OS and software:
export DEBIAN_FRONTEND=noninteractive
apt-get -y update
apt-get -y dist-upgrade

# We need some more software:
apt-get -y install unzip fail2ban iptables-persistent \
  build-essential apache2-dev libxml2-dev wget curl \
  libcurl4-openssl-dev libpcre3-dev libssl-dev \
  libtool autoconf

: '
# (Optional) Commands between dividers below are optional, but they could improve the security
# of your server and reduce the number of brute-force login attempts in your SSH logs.

# Start of optional commands
# -------------------------------------------------------------------------------------------

# Configure a non-standard port for SSH (e.g. 6543)
/bin/cp -f /etc/ssh/sshd_config /etc/ssh/sshd_config.old
sed "s/Port 22/Port 6543/" </etc/ssh/sshd_config >/etc/ssh/sshd_config.new
/bin/cp -f /etc/ssh/sshd_config.new /etc/ssh/sshd_config
/bin/rm -f /etc/ssh/sshd_config.new
service ssh restart

# Let Fail2Ban monitor the non-standard SSH port
/bin/cp -f /etc/fail2ban/jail.local /etc/fail2ban/jail.local.old 2>/dev/null
nano -w /etc/fail2ban/jail.local

# Copy the following content and paste into nano editor.
# Change 6543 below to the new SSH port you configured.

[DEFAULT]
ignoreip = 127.0.0.0/8
bantime  = 1800
findtime  = 1800
maxretry = 5
backend = gamin

[ssh]
enabled  = true
port     = 6543
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 5

# Save the file by CTRL-O and Enter and exit nano with CTRL-X.

# -------------------------------------------------------------------------------------------
# End of optional commands
'

# Modify the iptables configuration
# Make those rules persistent using the package "iptables-persistent".
/bin/cp -f /etc/iptables/rules.v4 /etc/iptables/rules.v4.old
service iptables-persistent start 2>/dev/null
service netfilter-persistent start 2>/dev/null
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -F
iptables -t nat -F
iptables -t raw -F
iptables -t mangle -F
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -d 127.0.0.0/8 -j REJECT
iptables -A INPUT -p icmp -j ACCEPT
# Allow DHCP traffic
iptables -A INPUT -p udp --dport 67:68 --sport 67:68 -j ACCEPT
# Delete the next line if you configured a non-standard SSH port:
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
# IMPORTANT: If you configured a non-standard SSH port (e.g. 6543),
# uncomment the next line and replace 6543 with your new port.
# iptables -A INPUT -p tcp --dport 6543 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -j DROP
iptables -A FORWARD -j DROP
service fail2ban stop
/etc/init.d/iptables-persistent save 2>/dev/null
netfilter-persistent save 2>/dev/null
service fail2ban start

# (Optional) If your server has IPv6 enabled, you may also want to configure IP6Tables
# by editing the file "/etc/iptables/rules.v6". Search for related tutorials on the web.

# Next, we need to install Node.js.
# See separate steps for Ubuntu 16.04, 14.04/12.04 and Debian 8 below.

# -----------------------------------
# * Steps for Ubuntu 16.04 (Xenial) *
# -----------------------------------

if [ "$os_ver" = "16.04" ]; then
  apt-get -y install nodejs nodejs-legacy npm
fi

# --------------------------------------------------
# * Steps for Ubuntu 14.04 and 12.04, and Debian 8 *
# --------------------------------------------------
# Ref: https://github.com/nodesource/distributions#debinstall

if [ "$os_ver" = "14.04" ] || [ "$os_ver" = "12.04" ] || [ "$os_ver" = "8" ]; then
  curl -sL https://deb.nodesource.com/setup_0.12 | bash -
  apt-get -y install nodejs
fi

# Instructions below are for all supported OS and versions.

# To keep your Ghost blog running, install "forever".
npm install forever -g

# Create a user to run Ghost:
mkdir -p /var/www
useradd -d "/var/www/${BLOG_FQDN}" -m -s /bin/false ghost

# Stop running Ghost blog processes, if any.
su - ghost -s /bin/bash -c "forever stopall"

# Switch to user "ghost".
# REMOVE <<'SU_END' if running script manually.
su - ghost -s /bin/bash <<'SU_END'

# Commands below will be run as user "ghost".

# Retrieve the domain name of your blog from temp file:
BLOG_FQDN=$(cat /tmp/BLOG_FQDN)
export BLOG_FQDN

# Get the ghost blog source (latest version), unzip and install.
wget -t 3 -T 30 -nv -O ghost-latest.zip https://ghost.org/zip/ghost-latest.zip
[ ! -f ghost-latest.zip ] && { echo "Could not retrieve Ghost blog source file. Aborting."; exit 1; }
unzip -o ghost-latest.zip && /bin/rm -f ghost-latest.zip
npm install --production

# Generate config file and make sure that Ghost uses your actual domain name
/bin/cp -f config.js config.js.old 2>/dev/null
sed "s/my-ghost-blog.com/${BLOG_FQDN}/" <config.example.js >config.js

# We need to make certain that Ghost will start automatically after a reboot
cat > starter.sh <<'EOF'
#!/bin/sh
pgrep -f "/usr/bin/node" >/dev/null
if [ $? -ne 0 ]; then
  export PATH=/usr/local/bin:$PATH
  export NODE_ENV=production
  NODE_ENV=production forever start --sourceDir /var/www/YOUR.DOMAIN.NAME index.js >> /var/log/nodelog.txt 2>&1
else
  echo "Already running!"
fi
EOF

# Replace placeholder domain with your actual domain name:
sed -i "s/YOUR.DOMAIN.NAME/${BLOG_FQDN}/" starter.sh

# Make the script executable with:
chmod +x starter.sh

# We use crontab to start this script after a reboot:
crontab -r
crontab -l 2>/dev/null | { cat; echo "@reboot /var/www/${BLOG_FQDN}/starter.sh"; } | crontab -

# SKIP this line if running script manually
SU_END

: '
# Exit the shell so that you are root again.
exit
'

# Check if Ghost blog download was successful
[ ! -f "/var/www/${BLOG_FQDN}/index.js" ] && exit 1

# Commands below will be run as "root".

# Create the logfile:
touch /var/log/nodelog.txt
chown ghost.ghost /var/log/nodelog.txt

# Download and compile ModSecurity:
# We use ModSecurity's sources from "nginx_refactoring" branch for improved stability.
# Ref: https://mescanef.net/blog/2015/11/nginx-with-modsecurity/

cd /opt/src || { echo "Failed to change directory to /opt/src. Aborting."; exit 1; }
wget -t 3 -T 30 -nv -O nginx_refactoring.zip https://github.com/SpiderLabs/ModSecurity/archive/nginx_refactoring.zip
[ ! -f nginx_refactoring.zip ] && { echo "Could not retrieve ModSecurity source files. Aborting."; exit 1; }
unzip -o nginx_refactoring.zip && /bin/rm -f nginx_refactoring.zip
cd ModSecurity-nginx_refactoring || { echo "Failed to change directory to /opt/src/ModSecurity-nginx_refactoring. Aborting."; exit 1; }
./autogen.sh
./configure --enable-standalone-module --disable-mlogc
make
# The "make" command may take some time...

# Next we create a user for nginx:
adduser --system --no-create-home --disabled-login --disabled-password --group nginx

# Download and compile the latest version of Nginx:
cd /opt/src || { echo "Failed to change directory to /opt/src. Aborting."; exit 1; }
wget -t 3 -T 30 -qO- http://nginx.org/download/nginx-1.8.1.tar.gz | tar xvz
[ ! -d nginx-1.8.1 ] && { echo "Could not retrieve Nginx source files. Aborting."; exit 1; }
cd nginx-1.8.1 || { echo "Failed to change directory to /opt/src/nginx-1.8.1. Aborting."; exit 1; }
./configure --add-module=../ModSecurity-nginx_refactoring/nginx/modsecurity \
  --prefix=/opt/nginx --user=nginx --group=nginx \
  --with-http_ssl_module --with-http_spdy_module --with-http_realip_module
make && make install
# The "make" command may take some time...

# Copy the ModSecurity configuration file to the Nginx directory:
cd /opt/nginx/conf || { echo "Failed to change directory to /opt/nginx/conf. Aborting."; exit 1; }
/bin/cp -f /opt/src/ModSecurity-nginx_refactoring/modsecurity.conf-recommended modsecurity.conf
/bin/cp -f /opt/src/ModSecurity-nginx_refactoring/unicode.mapping ./

# We need some more rules for ModSecurity:
wget -t 3 -T 30 -nv -O modsecurity_crs_41_xss_attacks.conf https://raw.githubusercontent.com/SpiderLabs/owasp-modsecurity-crs/master/base_rules/modsecurity_crs_41_xss_attacks.conf
[ ! -f modsecurity_crs_41_xss_attacks.conf ] && { echo "Could not retrieve modsecurity_crs_41_xss_attacks.conf. Aborting."; exit 1; }
wget -t 3 -T 30 -nv -O modsecurity_crs_41_sql_injection_attacks.conf https://raw.githubusercontent.com/SpiderLabs/owasp-modsecurity-crs/master/base_rules/modsecurity_crs_41_sql_injection_attacks.conf
[ ! -f modsecurity_crs_41_sql_injection_attacks.conf ] && { echo "Could not retrieve modsecurity_crs_41_sql_injection_attacks.conf. Aborting."; exit 1; }

# Disable the JSON parser due to issues (400 Bad Request) when updating a blog post.
# Ref: https://github.com/SpiderLabs/ModSecurity/issues/939
sed -i '/Content-Type "application\/json"/s/^/# /' modsecurity.conf
sed -i '/requestBodyProcessor=JSON/s/^/# /' modsecurity.conf

# Configure ModSecurity to filter Cross-Site-Scripting (XSS) and SQL Injection (SQLi) attacks:
sed -i '/SecRuleEngine DetectionOnly/s/DetectionOnly/On/' modsecurity.conf
sed -i '/SecRequestBodyLimit 13107200/s/13107200/100000000/' modsecurity.conf

# Change ModSecurity audit log type from Serial to Concurrent for better scalability:
sed -i '/SecAuditLogType Serial/s/Serial/Concurrent/' modsecurity.conf
sed -i -e '/SecAuditLog /s/^/# /' -e '/SecStatusEngine On/s/On/Off/' modsecurity.conf

# Create the audit log directory for ModSecurity:
mkdir -p /var/log/modsec_audit
chown -hR nginx:nginx /var/log/modsec_audit

# Append the following lines to modsecurity.conf. This will:
# 1. Define the default list of actions for ModSecurity
# 2. Include the XSS and SQLi rules in the main config file
# 3. Whitelist certain request cookies due to false positives

cat >> modsecurity.conf <<'EOF'
SecAuditLogStorageDir /var/log/modsec_audit
SecDefaultAction "log,deny,phase:1"
Include "modsecurity_crs_41_sql_injection_attacks.conf"
Include "modsecurity_crs_41_xss_attacks.conf"
SecRuleUpdateTargetById 981172 !REQUEST_COOKIES:'/^PRUM_EPISODES/'
SecRuleUpdateTargetById 981172 !REQUEST_COOKIES:'/^CFGLOBALS/'
SecRuleUpdateTargetById 981231 !REQUEST_COOKIES:'/^CFGLOBALS/'
SecRuleUpdateTargetById 981245 !REQUEST_COOKIES:'/^CFGLOBALS/'
SecRuleUpdateTargetById 973338 !ARGS:token
EOF

# Create the following files to make Nginx autorun:

cat > /etc/init/nginx.conf <<'EOF'
# nginx
description "nginx http daemon"
author "Philipp Klose <me@[thisdomain].de>"
start on (filesystem and net-device-up IFACE!=lo)
stop on runlevel [!2345]
env DAEMON=/opt/nginx/sbin/nginx
env PID=/opt/nginx/logs/nginx.pid
expect fork
respawn
respawn limit 10 5
#oom never
pre-start script
$DAEMON -t
if [ $? -ne 0 ]
  then exit $?
fi
end script
exec $DAEMON
EOF

if [ -d /lib/systemd/system ]; then

cat > /lib/systemd/system/nginx.service <<'EOF'
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=syslog.target network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
PIDFile=/opt/nginx/logs/nginx.pid
ExecStartPre=/opt/nginx/sbin/nginx -t
ExecStart=/opt/nginx/sbin/nginx
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s QUIT $MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload 2>/dev/null
systemctl enable nginx.service 2>/dev/null

fi

# Create the public folder which will hold robots.txt, etc.
mkdir -p "/var/www/${BLOG_FQDN}/public"

# Download example Nginx configuration file
cd /opt/nginx/conf || { echo "Failed to change directory to /opt/nginx/conf. Aborting."; exit 1; }
/bin/cp -f nginx.conf nginx.conf.old
example_conf=https://github.com/hwdsl2/setup-ghost-blog/raw/master/conf/nginx-modsecurity.conf
wget -t 3 -T 30 -nv -O nginx.conf $example_conf
[ ! -f nginx.conf ] && { echo "Could not retrieve example nginx.conf. Aborting."; exit 1; }

# Replace every placeholder domain with your actual domain name:
sed -i "s/YOUR.DOMAIN.NAME/${BLOG_FQDN}/g" nginx.conf

# Disable SSL configuration in nginx.conf for now (enable it after you fully set it up)
sed -i -e "s/listen 443/# listen 443/" -e "s/ssl_/# ssl_/" nginx.conf

# Check the validity of the nginx.conf file:
echo; /opt/nginx/sbin/nginx -t; echo

# The output should look like:
# nginx: the configuration file /opt/nginx/conf/nginx.conf syntax is ok
# nginx: configuration file /opt/nginx/conf/nginx.conf test is successful

# Finally, start Ghost blog and Nginx:
su - ghost -s /bin/bash -c "./starter.sh"
service nginx restart

# Remove temporary file
/bin/rm -f /tmp/BLOG_FQDN

# Retrieve server public IP for display below
PUBLIC_IP=$(wget -t 3 -T 15 -qO- http://ipv4.icanhazip.com)

echo
echo "------------------------------------------------------------------------------------------"
echo
echo 'Setup is complete. Your new Ghost blog is now ready for use!'
echo
echo "Ghost blog is installed in: /var/www/${BLOG_FQDN}"
echo "ModSecurity and Nginx config files: /opt/nginx/conf"
echo "Nginx web server logs: /opt/nginx/logs"
echo
echo "[Next Steps]"
echo
echo "You must set up DNS (A Record) to point ${BLOG_FQDN} to the IP of this server ${PUBLIC_IP}"
echo
echo "Browse to http://${BLOG_FQDN}/ghost (or http://localhost:2368/ghost via SSH port forwarding)"
echo "to configure your blog and create an admin user. Choose a very secure password."
echo
echo "Finally, follow additional instructions at the link below to:"
echo "https://blog.ls20.com/install-ghost-0-3-3-with-nginx-and-modsecurity/#tag1"
echo
echo "1. Set Up HTTPS for Your Blog (Optional)"
echo "2. Sitemap, Robots.txt and Extras (Optional)"
echo "3. Setting Up E-Mail on Ghost (Optional)"
echo
echo "Questions? Refer to the official Ghost Guide: http://support.ghost.org/"
echo
echo "------------------------------------------------------------------------------------------"
echo

exit 0
