#!/bin/bash
#
# Use this automated bash script to install Ghost blog on Ubuntu or Debian,
# with Nginx (as a reverse proxy) and ModSecurity web application firewall.
#
# This script should only be used on a Virtual Private Server (VPS)
# or dedicated server, with *freshly installed* Ubuntu LTS or Debian 8.
#
# DO NOT RUN THIS SCRIPT ON YOUR PC OR MAC!
#
# Copyright (C) 2015-2016 Lin Song <linsongui@gmail.com>
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

max_blogs=10

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

echoerr() { echo "Error: ${1}" >&2; }

os_type="$(lsb_release -si 2>/dev/null)"
if [ "$os_type" != "Ubuntu" ] && [ "$os_type" != "Debian" ]; then
  echoerr "This script only supports Ubuntu/Debian."
  exit 1
fi

if [ "$os_type" = "Ubuntu" ]; then
  os_ver="$(lsb_release -sr)"
  if [ "$os_ver" != "16.04" ] && [ "$os_ver" != "14.04" ] && [ "$os_ver" != "12.04" ]; then
    echoerr "This script only supports Ubuntu 16.04/14.04/12.04."
    exit 1
  fi
fi

if [ "$os_type" = "Debian" ]; then
  os_ver="$(sed 's/\..*//' /etc/debian_version 2>/dev/null)"
  if [ "$os_ver" != "8" ]; then
    echoerr "This script only supports Debian 8 (Jessie)."
    exit 1
  fi
fi

if [ "$(id -u)" != 0 ]; then
  echoerr "Script must be run as root. Try 'sudo bash $0'"
  exit 1
fi

phymem="$(free | awk '/^Mem:/{print $2}')"
[ -z "$phymem" ] && phymem=0
if [ "$phymem" -lt 500000 ]; then
  echoerr "A minimum of 512 MB RAM is required for Ghost blog install."
  exit 1
fi

if [ "$1" = "" ] || [ "$1" = "BLOG_FULL_DOMAIN_NAME" ]; then
  script_name=$(basename "$0")
  echo "Usage: bash $script_name BLOG_FULL_DOMAIN_NAME (Replace with actual domain name)"
  exit 1
fi

FQDN_REGEX='^(([a-zA-Z](-?[a-zA-Z0-9])*)\.)*[a-zA-Z](-?[a-zA-Z0-9])+\.[a-zA-Z]{2,}$'
if ! printf %s "$1" | grep -Eq "$FQDN_REGEX"; then
  echoerr "Invalid parameter. You must enter a fully qualified domain name (FQDN)."
  exit 1
fi

if id -u "ghost${max_blogs}" >/dev/null 2>&1; then
  echoerr "Maximum number of Ghost blogs (${max_blogs}) reached."
  exit 1
fi

ghost_num=1
ghost_user=ghost
ghost_port=2368
if id -u ghost >/dev/null 2>&1; then
  echo 'It looks like this server already has Ghost blog installed! '
  if [ -d "/var/www/$1" ]; then
    echo
    echo "To install additional blogs, you must use a new full domain name."
    exit 1
  fi
  
  for count in $(seq 2 ${max_blogs}); do
    if ! id -u "ghost${count}" >/dev/null 2>&1; then
      ghost_num="${count}"
      ghost_user="ghost${count}"
      let ghost_port=$ghost_port+$count
      let ghost_port=$ghost_port-1
      break
    fi
  done
  
  echo
  read -r -p "Install another Ghost blog on this server? [y/N] " response
  case $response in
    [yY][eE][sS]|[yY])
      echo
      ;;
    *)
      echo "Aborting."
      exit 1
      ;;
  esac
  
  phymem_req=250
  let phymem_req1=$phymem_req*$ghost_num
  let phymem_req2=$phymem_req*$ghost_num*1000
  [ "$ghost_num" = "3" ] && phymem_req1=500
  [ "$ghost_num" = "3" ] && phymem_req2=500000
  
  if [ "$phymem" -lt "$phymem_req2" ]; then
    echo "This server may not have enough RAM to install another Ghost blog."
    echo "It is estimated that at least $phymem_req1 MB total RAM is required."
    echo
    echo 'WARNING! If you continue, the install could fail and your blog will not work!'
    echo
    read -r -p "Do you REALLY want to continue (at your own risk)? [y/N] " response
    case $response in
      [yY][eE][sS]|[yY])
        echo
        ;;
      *)
        echo "Aborting."
        exit 1
        ;;
    esac
    
  fi
fi

clear

cat <<EOF
Welcome! This script will install Ghost blog (https://ghost.org) on your server,
with Nginx (as a reverse proxy) and Modsecurity web application firewall.

The full domain name for your new blog is:

>>> $1 <<<

Please double check. This MUST be correct for it to work!

IMPORTANT: DO NOT RUN THIS SCRIPT ON YOUR PC OR MAC!
This script should only be used on a Virtual Private Server (VPS)
or dedicated server, with *freshly installed* Ubuntu LTS or Debian 8.

EOF

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

# Create and change to working dir
mkdir -p /opt/src
cd /opt/src || exit 1

# Update package index
export DEBIAN_FRONTEND=noninteractive
apt-get -yq update || { echoerr "'apt-get update' failed."; exit 1; }

# We need some more software
apt-get -yq install unzip fail2ban iptables-persistent \
  build-essential apache2-dev libxml2-dev wget curl sudo \
  libcurl4-openssl-dev libpcre3-dev libssl-dev \
  libtool autoconf || { echoerr "'apt-get install' failed."; exit 1; }

# Create new iptables configuration
# Make those rules persistent using the package "iptables-persistent".
/bin/cp -f /etc/iptables/rules.v4 /etc/iptables/rules.v4.old
service iptables-persistent start 2>/dev/null
service netfilter-persistent start 2>/dev/null
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t raw -F
iptables -t raw -X
iptables -t mangle -F
iptables -t mangle -X
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -d 127.0.0.0/8 -j REJECT
iptables -A INPUT -p icmp -j ACCEPT
# Allow DHCP traffic
iptables -A INPUT -p udp --dport 67:68 --sport 67:68 -j ACCEPT
iptables -A INPUT -p tcp --dport $(netstat -plunt|grep sshd|awk '{print $4}'|awk -F":" '{print $2}'|sed '/^\s*$/d') -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -j DROP
iptables -A FORWARD -j DROP
service fail2ban stop
/etc/init.d/iptables-persistent save 2>/dev/null
netfilter-persistent save 2>/dev/null
service fail2ban start

# Next, we need to install Node.js.
# Ref: https://github.com/nodesource/distributions#debinstall
if [ "$ghost_num" = "1" ] || [ ! -f /usr/bin/node ]; then
  curl -sL https://deb.nodesource.com/setup_4.x | bash -
  apt-get -yq install nodejs || { echoerr "Failed to install 'nodejs'."; exit 1; }
fi

# To keep your Ghost blog running, install "forever".
npm install forever -g

# Create a user to run Ghost:
mkdir -p /var/www
useradd -d "/var/www/${BLOG_FQDN}" -m -s /bin/false "$ghost_user"

# Stop running Ghost blog processes, if any.
su - "$ghost_user" -s /bin/bash -c "forever stopall"

# Create temporary swap file to prevent out of memory errors during install
# Do not create if OpenVZ VPS
swap_tmp="/tmp/swapfile_temp.tmp"
if [ ! -f /proc/user_beancounters ]; then
  echo
  echo "Creating temporary swap file, please wait ..."
  echo
  dd if=/dev/zero of="$swap_tmp" bs=1M count=512 2>/dev/null || /bin/rm -f "$swap_tmp"
  chmod 600 "$swap_tmp" && mkswap "$swap_tmp" >/dev/null && swapon "$swap_tmp"
fi

# Switch to Ghost blog user. We use a "here document" to run multiple commands as this user.
cd "/var/www/${BLOG_FQDN}" || exit 1
sudo -u "$ghost_user" BLOG_FQDN="$BLOG_FQDN" ghost_num="$ghost_num" ghost_port="$ghost_port" HOME="/var/www/$BLOG_FQDN" /bin/bash <<'SU_END'

# Get the Ghost blog source (latest version), unzip and install.
ghost_url1="https://ghost.org/zip/ghost-latest.zip"
ghost_rels="https://api.github.com/repos/TryGhost/Ghost/releases"
ghost_url2="$(wget -t 3 -T 15 -qO- $ghost_rels | grep browser_download_url | grep -v beta | head -n 1 | cut -d '"' -f 4)"
wget -t 3 -T 30 -nv -O ghost-latest.zip "$ghost_url1" || wget -t 3 -T 30 -nv -O ghost-latest.zip "$ghost_url2"
[ "$?" != "0" ] && { echo "Error: Cannot download Ghost blog source." >&2; exit 1; }
unzip -o -qq ghost-latest.zip && /bin/rm -f ghost-latest.zip
npm install --production

# Generate config file and make sure that Ghost uses your actual domain name
/bin/cp -f config.js config.js.old 2>/dev/null
sed "s/my-ghost-blog.com/${BLOG_FQDN}/" <config.example.js >config.js
sed -i "s/port: '2368'/port: '${ghost_port}'/" config.js

# We need to make certain that Ghost will start automatically after a reboot
cat > starter.sh <<'EOF'
#!/bin/sh
pgrep -u ghost -f "/usr/bin/node" >/dev/null
if [ $? -ne 0 ]; then
  export PATH=/usr/local/bin:$PATH
  export NODE_ENV=production
  NODE_ENV=production forever start --sourceDir /var/www/YOUR.DOMAIN.NAME index.js >> /var/log/nodelog.txt 2>&1
else
  echo "Already running!"
fi
EOF

# Replace placeholder with your actual domain name:
sed -i "s/YOUR.DOMAIN.NAME/${BLOG_FQDN}/" starter.sh

if [ "$ghost_num" != "1" ]; then
  sed -i "/^pgrep/s/ghost/ghost${ghost_num}/" starter.sh
  sed -i "s/nodelog\.txt/nodelog${ghost_num}.txt/" starter.sh
fi

# Make the script executable with:
chmod +x starter.sh

# We use crontab to start this script after a reboot:
crontab -r 2>/dev/null
crontab -l 2>/dev/null | { cat; echo "@reboot /var/www/${BLOG_FQDN}/starter.sh"; } | crontab -

SU_END

# Remove temporary swap file
[ -f "$swap_tmp" ] && swapoff "$swap_tmp" && /bin/rm -f "$swap_tmp"

# Check if Ghost blog download was successful
[ ! -f "/var/www/${BLOG_FQDN}/index.js" ] && exit 1

# Create the logfile:
if [ "$ghost_num" = "1" ]; then
  touch /var/log/nodelog.txt
  chown ghost.ghost /var/log/nodelog.txt
else
  touch "/var/log/nodelog${ghost_num}.txt"
  chown "ghost${ghost_num}.ghost${ghost_num}" "/var/log/nodelog${ghost_num}.txt"
fi

if [ "$ghost_num" = "1" ] || [ ! -f /opt/nginx/sbin/nginx ]; then
  
  # Download and compile ModSecurity:
  # We use ModSecurity's "nginx_refactoring" branch for improved stability.
  cd /opt/src || exit 1
  wget -t 3 -T 30 -nv -O nginx_refactoring.zip https://github.com/SpiderLabs/ModSecurity/archive/nginx_refactoring.zip
  [ "$?" != "0" ] && { echoerr "Cannot download ModSecurity source."; exit 1; }
  unzip -o -qq nginx_refactoring.zip && /bin/rm -f nginx_refactoring.zip
  cd ModSecurity-nginx_refactoring || { echoerr "Cannot enter ModSecurity source dir."; exit 1; }
  ./autogen.sh
  ./configure --enable-standalone-module --disable-mlogc
  make -s
  
  # Next we create a user for nginx:
  adduser --system --no-create-home --disabled-login --disabled-password --group nginx
  
  # Download and compile Nginx:
  cd /opt/src || exit 1
  wget -t 3 -T 30 -qO- http://nginx.org/download/nginx-1.10.1.tar.gz | tar xz
  [ ! -d nginx-1.10.1 ] && { echoerr "Cannot download Nginx source."; exit 1; }
  cd nginx-1.10.1 || exit 1
  ./configure --add-module=../ModSecurity-nginx_refactoring/nginx/modsecurity \
  --prefix=/opt/nginx --user=nginx --group=nginx \
  --with-http_ssl_module --with-http_v2_module --with-http_realip_module
  make -s && make -s install
  
  # Copy the ModSecurity configuration file to the Nginx directory:
  cd /opt/nginx/conf || exit 1
  /bin/cp -f /opt/src/ModSecurity-nginx_refactoring/modsecurity.conf-recommended modsecurity.conf
  /bin/cp -f /opt/src/ModSecurity-nginx_refactoring/unicode.mapping ./
  
  # We need some more rules for ModSecurity:
  mod_conf1="modsecurity_crs_41_xss_attacks.conf"
  mod_conf2="modsecurity_crs_41_sql_injection_attacks.conf"
  wget -t 3 -T 30 -nv -O "$mod_conf1" "https://raw.githubusercontent.com/SpiderLabs/owasp-modsecurity-crs/master/base_rules/$mod_conf1"
  [ "$?" != "0" ] && { echoerr "Cannot download $mod_conf1."; exit 1; }
  wget -t 3 -T 30 -nv -O "$mod_conf2" "https://raw.githubusercontent.com/SpiderLabs/owasp-modsecurity-crs/master/base_rules/$mod_conf2"
  [ "$?" != "0" ] && { echoerr "Cannot download $mod_conf2."; exit 1; }
  
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
SecRuleUpdateTargetById 981243 !REQUEST_COOKIES:'/^CFGLOBALS/'
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
  
fi

# Create the public folder which will hold robots.txt, etc.
mkdir -p "/var/www/${BLOG_FQDN}/public"

# Download example Nginx configuration file
cd /opt/nginx/conf || exit 1
/bin/cp -f nginx.conf nginx.conf.old
if [ "$ghost_num" = "1" ]; then
  example_conf1=https://github.com/hwdsl2/setup-ghost-blog/raw/master/conf/nginx-modsecurity.conf
  wget -t 3 -T 30 -nv -O nginx.conf "$example_conf1"
  [ "$?" != "0" ] && { echoerr "Cannot download example nginx.conf."; exit 1; }
fi

if [ "$ghost_num" = "1" ] || [ ! -f nginx-include.conf ]; then
  example_conf2=https://github.com/hwdsl2/setup-ghost-blog/raw/master/conf/nginx-modsecurity-include.conf
  wget -t 3 -T 30 -nv -O nginx-include.conf "$example_conf2"
  [ "$?" != "0" ] && { echoerr "Cannot download example nginx.conf."; exit 1; }
fi

# Modify example configuration for use
if [ "$ghost_num" = "1" ]; then
  /bin/cp -f nginx-include.conf nginx-blog1.conf
  sed -i "s/YOUR.DOMAIN.NAME/${BLOG_FQDN}/g" nginx-blog1.conf
else
  /bin/cp -f nginx-include.conf "nginx-blog${ghost_num}.conf"
  sed -i -e "/127\.0\.0\.1:2368/s/2368/${ghost_port}/" \
  -e "s/ghost_upstream/ghost_upstream${ghost_num}/" \
  -e "s/YOUR.DOMAIN.NAME/${BLOG_FQDN}/g" "nginx-blog${ghost_num}.conf"
  sed -i "/include nginx-blog1\.conf/a\    include nginx-blog${ghost_num}.conf;" nginx.conf
fi

# Check the validity of the nginx.conf file:
echo; /opt/nginx/sbin/nginx -t; echo

# The output should look like:
# nginx: the configuration file /opt/nginx/conf/nginx.conf syntax is ok
# nginx: configuration file /opt/nginx/conf/nginx.conf test is successful

# Finally, start Ghost blog and Nginx:
su - "$ghost_user" -s /bin/bash -c "./starter.sh"
service nginx restart

# Retrieve server IP for display below
PUBLIC_IP=$(wget -t 3 -T 15 -qO- http://whatismyip.akamai.com)

cat <<EOF

==================================================================================

Setup is complete. Your new Ghost blog is now ready for use!

Ghost blog is installed in: /var/www/${BLOG_FQDN}
ModSecurity and Nginx config files: /opt/nginx/conf
Nginx web server logs: /opt/nginx/logs

[Next Steps]

You must set up DNS (A Record) to point ${BLOG_FQDN} to this server ${PUBLIC_IP}

EOF

if [ "$ghost_num" = "1" ]; then
  
cat <<EOF
Browse to http://${BLOG_FQDN}/ghost (alternatively, set up SSH port forwarding
and browse to http://localhost:${ghost_port}/ghost) to complete the initial configuration
of your blog. Choose a very secure password.
EOF
  
else
  
cat <<'EOF'
IMPORTANT: To work around a ModSecurity bug which only affects multiple blogs,
from now on you must configure your blogs via SSH port forwarding.
First, set up your SSH client to forward port 2368 (1st blog), 2369 (2nd blog), etc.
Then browse to http://localhost:2368/ghost (or 2369, etc.) to manage your blogs.
Ref: https://github.com/hwdsl2/setup-ghost-blog/issues/1
EOF
  
fi

cat <<EOF

To restart this Ghost blog:
su - ${ghost_user} -s /bin/bash -c 'forever stopall; ./starter.sh'

To restart Nginx web server:
service nginx restart

(Optional) Follow additional steps at the link below to:
https://blog.ls20.com/install-ghost-0-3-3-with-nginx-and-modsecurity/

1. Set up HTTPS for your blog
2. Sitemap, robots.txt and extras
3. Setting up e-mail on Ghost

Ghost support: http://support.ghost.org, Real-time chat: https://ghost.org/slack

==================================================================================

EOF

exit 0
