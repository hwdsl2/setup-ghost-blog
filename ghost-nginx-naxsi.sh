#!/bin/bash
#
# Use this automated bash script to install the latest Ghost blog on Ubuntu or Debian,
# with Nginx (as a reverse proxy) and Naxsi web application firewall.
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

if [ "$1" = "" ] || [ "$1" = "BLOG_FULL_DOMAIN_NAME" ]; then
  script_name=$(basename "$0")
  echo "Usage: bash $script_name BLOG_FULL_DOMAIN_NAME"
  echo '(Replace the above with your actual domain name)'
  exit 1
fi

if id -u ghost3 >/dev/null 2>&1; then
  echo "This script cannot set up more than 3 Ghost blogs on the same server."
  echo "Aborting."
  exit 1
fi

ghost_user=ghost
if id -u ghost >/dev/null 2>&1; then
  echo 'It looks like this server already has Ghost blog installed! '
  [ -d "/var/www/$1" ] && { echo "Aborting."; exit 1; }

  if id -u ghost2 >/dev/null 2>&1; then
    ghost_user=ghost3
    touch /tmp/setting_up_ghost3
  else
    ghost_user=ghost2
    touch /tmp/setting_up_ghost2
  fi

  echo
  read -r -p "Do you wish to set up ANOTHER Ghost blog on this server? [y/N] " response
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

clear
echo 'Welcome! This script installs Ghost blog (https://ghost.org) on your server,'
echo 'with Nginx (as a reverse proxy) and Naxsi web application firewall.'
echo
echo 'The full domain name for your new blog is:'
echo
echo "$1"
echo
echo 'Please double check. This MUST be correct for it to work!'
echo
echo 'IMPORTANT NOTES:'
echo 'This script should only be used on a Virtual Private Server (VPS) or dedicated server,'
echo 'with *freshly installed* Ubuntu LTS or Debian 8. A minimum of 512MB RAM is required.'
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
cd /opt/src || exit 1

# Update package index
export DEBIAN_FRONTEND=noninteractive
apt-get -y update

# We need some more software
apt-get -y install unzip fail2ban iptables-persistent \
  build-essential apache2-dev libxml2-dev wget curl \
  libcurl4-openssl-dev libpcre3-dev libssl-dev

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
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
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
curl -sL https://deb.nodesource.com/setup_0.12 | bash -
apt-get -y install nodejs=0.12\*

# To keep your Ghost blog running, install "forever".
npm install forever -g

# Create a user to run Ghost:
mkdir -p /var/www
useradd -d "/var/www/${BLOG_FQDN}" -m -s /bin/false "$ghost_user"

# Stop running Ghost blog processes, if any.
su - "$ghost_user" -s /bin/bash -c "forever stopall"

# Create temporary swap file to prevent out of memory errors during install
# Do not create if OpenVZ VPS or if RAM size >= 750 MB
swap_tmp="/tmp/swapfile_temp.tmp"
if [ ! -f /proc/user_beancounters ]; then
  if [ "$phymem" -lt 750000 ]; then
    echo
    echo "Creating temporary swap file, please wait ..."
    echo
    dd if=/dev/zero of="$swap_tmp" bs=1M count=512 2>/dev/null || /bin/rm -f "$swap_tmp"
    chmod 600 "$swap_tmp" && mkswap "$swap_tmp" >/dev/null && swapon "$swap_tmp"
  fi
fi

# Switch to user "ghost".
# REMOVE <<'SU_END' if running script manually.
su - "$ghost_user" -s /bin/bash <<'SU_END'

# Commands below will be run as user "ghost".

# Retrieve domain name from temp file:
BLOG_FQDN=$(cat /tmp/BLOG_FQDN)
export BLOG_FQDN

# Get the ghost blog source (latest version), unzip and install.
wget -t 3 -T 30 -nv -O ghost-latest.zip https://ghost.org/zip/ghost-latest.zip
[ "$?" != "0" ] && { echo "Cannot download Ghost blog source. Aborting."; exit 1; }
unzip -o ghost-latest.zip && /bin/rm -f ghost-latest.zip
npm install --production

# Generate config file and make sure that Ghost uses your actual domain name
/bin/cp -f config.js config.js.old 2>/dev/null
sed "s/my-ghost-blog.com/${BLOG_FQDN}/" <config.example.js >config.js

if [ -f "/tmp/setting_up_ghost2" ]; then
  sed -i "s/port: '2368'/port: '2369'/" config.js
elif [ -f "/tmp/setting_up_ghost3" ]; then
  sed -i "s/port: '2368'/port: '2370'/" config.js
fi

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

if [ -f "/tmp/setting_up_ghost2" ]; then
  sed -i "/^pgrep/s/ghost/ghost2/" starter.sh
  sed -i "s/nodelog\.txt/nodelog2.txt/" starter.sh
elif [ -f "/tmp/setting_up_ghost3" ]; then
  sed -i "/^pgrep/s/ghost/ghost3/" starter.sh
  sed -i "s/nodelog\.txt/nodelog3.txt/" starter.sh
fi

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

# Remove temporary swap file
[ -f "$swap_tmp" ] && swapoff "$swap_tmp" && /bin/rm -f "$swap_tmp"

# Check if Ghost blog download was successful
[ ! -f "/var/www/${BLOG_FQDN}/index.js" ] && exit 1

# Commands below will be run as "root".

# Create the logfile:
touch /var/log/nodelog.txt
chown ghost.ghost /var/log/nodelog.txt

if [ "$ghost_user" = "ghost2" ]; then
  touch /var/log/nodelog2.txt
  chown ghost2.ghost2 /var/log/nodelog2.txt
elif [ "$ghost_user" = "ghost3" ]; then
  touch /var/log/nodelog3.txt
  chown ghost3.ghost3 /var/log/nodelog3.txt
fi

# Download and extract Naxsi:
cd /opt/src || exit 1
wget -t 3 -T 30 -qO- https://github.com/nbs-system/naxsi/archive/0.54.tar.gz | tar xvz
[ ! -d naxsi-0.54 ] && { echo "Cannot download Naxsi source. Aborting."; exit 1; }

# Next we create a user for nginx:
adduser --system --no-create-home --disabled-login --disabled-password --group nginx

# Download and compile the latest version of Nginx:
cd /opt/src || exit 1
wget -t 3 -T 30 -qO- http://nginx.org/download/nginx-1.8.1.tar.gz | tar xvz
[ ! -d nginx-1.8.1 ] && { echo "Cannot download Nginx source. Aborting."; exit 1; }
cd nginx-1.8.1 || { echo "Cannot enter Nginx source dir. Aborting."; exit 1; }
./configure --add-module=../naxsi-0.54/naxsi_src/ \
  --prefix=/opt/nginx --user=nginx --group=nginx \
  --with-http_ssl_module --with-http_spdy_module --with-http_realip_module
make && make install

# Add Naxsi core rules
mkdir -p /etc/nginx
/bin/cp -f /opt/src/naxsi-0.54/naxsi_config/naxsi_core.rules /etc/nginx/

# Add Naxsi whitelist rules needed for Ghost blog.
# Ref: https://github.com/nbs-system/naxsi/wiki/whitelists

cat > /etc/nginx/mysite.rules <<'EOF'
#LearningMode; #Enables learning mode
SecRulesEnabled;
#SecRulesDisabled;
DeniedUrl "/RequestDenied";
## check rules
CheckRule "$SQL >= 8" BLOCK;
CheckRule "$RFI >= 8" BLOCK;
CheckRule "$TRAVERSAL >= 4" BLOCK;
CheckRule "$EVADE >= 4" BLOCK;
CheckRule "$XSS >= 8" BLOCK;
BasicRule  wl:1000 "mz:$URL_X:^/ghost/api/v[0-9]+\.[0-9]+/users/([0-9]+/)?$|BODY|NAME";
BasicRule  wl:1000 "mz:$URL_X:^/ghost/api/v[0-9]+\.[0-9]+/posts/([0-9]+/)?$|BODY|NAME";
BasicRule  wl:1000 "mz:$URL_X:^/ghost/api/v[0-9]+\.[0-9]+/tags/([0-9]+/)?$|BODY|NAME";
BasicRule  wl:1000,1001,1007,1008,1009,1010,1011,1013,1015 "mz:$URL_X:^/ghost/api/v[0-9]+\.[0-9]+/posts/([0-9]+/)?$|BODY";
BasicRule  wl:1016,1100,1101,1205,1302,1303,1310,1311,1314 "mz:$URL_X:^/ghost/api/v[0-9]+\.[0-9]+/posts/([0-9]+/)?$|BODY";
BasicRule  wl:1000,1001,1007,1008,1009,1010,1011,1013,1015 "mz:$URL_X:^/ghost/api/v[0-9]+\.[0-9]+/posts/([0-9]+/)?$|$BODY_VAR_X:^markdown$";
BasicRule  wl:1016,1100,1101,1205,1302,1303,1310,1311,1314 "mz:$URL_X:^/ghost/api/v[0-9]+\.[0-9]+/posts/([0-9]+/)?$|$BODY_VAR_X:^markdown$";
BasicRule  wl:1015 "mz:$URL_X:^/ghost/api/v[0-9]+\.[0-9]+/posts/$|ARGS";
BasicRule  wl:1015 "mz:$URL_X:^/ghost/api/v[0-9]+\.[0-9]+/posts/$|$ARGS_VAR_X:^type$";
BasicRule  wl:1015 "mz:$URL_X:^/ghost/api/v[0-9]+\.[0-9]+/settings/$|ARGS";
BasicRule  wl:1015 "mz:$URL_X:^/ghost/api/v[0-9]+\.[0-9]+/settings/$|$ARGS_VAR_X:^type$";
BasicRule  wl:1310,1311 "mz:$URL_X:^/ghost/api/v[0-9]+\.[0-9]+/users/password/$|BODY|NAME";
BasicRule  wl:1310,1311 "mz:$URL_X:^/ghost/api/v[0-9]+\.[0-9]+/authentication/setup/$|BODY|NAME";
BasicRule  wl:1310,1311 "mz:$URL_X:^/ghost/api/v[0-9]+\.[0-9]+/authentication/passwordreset/$|BODY|NAME";
BasicRule  wl:1001,1015,1205,1302,1303,1310,1311 "mz:$URL_X:^/ghost/api/v[0-9]+\.[0-9]+/settings/$|BODY";
BasicRule  wl:1001,1015,1205,1302,1303,1310,1311 "mz:$URL_X:^/ghost/api/v[0-9]+\.[0-9]+/settings/$|$BODY_VAR_X:^value$";
BasicRule  wl:16 "mz:$URL_X:^/ghost/api/v[0-9]+\.[0-9]+/mail/test/$|BODY";
BasicRule  wl:2 "mz:$URL_X:^/ghost/api/v[0-9]+\.[0-9]+/uploads/$|BODY";
EOF

# Set up NXAPI (Naxsi log parser, whitelist & report generator)
# Ref: https://github.com/nbs-system/naxsi/tree/master/nxapi
cd /opt/src/naxsi-0.54/nxapi/ || { echo "Cannot enter Naxsi NXAPI dir. Aborting."; exit 1; }
python setup.py install

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
cd /opt/nginx/conf || exit 1
/bin/cp -f nginx.conf nginx.conf.old
if [ "$ghost_user" = "ghost" ]; then
  example_conf=https://github.com/hwdsl2/setup-ghost-blog/raw/master/conf/nginx-naxsi.conf
  wget -t 3 -T 30 -nv -O nginx.conf $example_conf
  [ "$?" != "0" ] && { echo "Cannot download example nginx.conf. Aborting."; exit 1; }

  # Disable SSL configuration for now (enable it after you fully set it up)
  sed -i -e "s/listen 443/# listen 443/" -e "s/ssl_/# ssl_/" nginx.conf
fi

# Replace placeholder with your actual domain name:
if [ "$ghost_user" = "ghost2" ]; then
  sed -i "/^#/s/#//" nginx.conf
  sed -i "s/YOUR.DOMAIN2.NAME/${BLOG_FQDN}/g" nginx.conf
elif [ "$ghost_user" = "ghost3" ]; then
  sed -i "/^#/s/#//" nginx.conf
  sed -i "s/YOUR.DOMAIN3.NAME/${BLOG_FQDN}/g" nginx.conf
else
  sed -i "s/YOUR.DOMAIN.NAME/${BLOG_FQDN}/g" nginx.conf
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
PUBLIC_IP=$(wget -t 3 -T 15 -qO- http://ipv4.icanhazip.com)

# Define port number for display below
ghost_port=2368
[ -f "/tmp/setting_up_ghost2" ] && ghost_port=2369
[ -f "/tmp/setting_up_ghost3" ] && ghost_port=2370

# Remove temporary files
/bin/rm -f /tmp/BLOG_FQDN
/bin/rm -f /tmp/setting_up_ghost2
/bin/rm -f /tmp/setting_up_ghost3

echo
echo "============================================================================================="
echo
echo 'Setup is complete. Your new blog is now ready for use!'
echo
echo "Ghost blog is installed in: /var/www/${BLOG_FQDN}"
echo "Naxsi and Nginx config files: /etc/nginx and /opt/nginx/conf"
echo "Nginx web server logs: /opt/nginx/logs"
echo
echo "[Next Steps]"
echo
echo "You must set up DNS (A Record) to point ${BLOG_FQDN} to this server's IP ${PUBLIC_IP}"
echo
echo "Browse to http://${BLOG_FQDN}/ghost (or http://localhost:${ghost_port}/ghost via SSH port forwarding)"
echo "to configure your blog and create an admin user. Choose a very secure password."
echo
echo "Next, follow additional instructions at the link below to:"
echo "https://blog.ls20.com/install-ghost-0-4-with-nginx-and-naxsi-on-ubuntu/#naxsi1"
echo
echo "1. Set Up HTTPS for Your Blog (Optional)"
echo "2. Sitemap, Robots.txt and Extras (Optional)"
echo "3. Setting Up E-Mail on Ghost (Optional)"
echo
echo "Questions? Refer to the official Ghost Guide: http://support.ghost.org/"
echo "Documentation for Naxsi: https://github.com/nbs-system/naxsi/wiki"
echo
echo "============================================================================================="
echo

exit 0
