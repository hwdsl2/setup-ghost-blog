#!/bin/bash
#
# Use this automated bash script to install the latest Ghost blog on Ubuntu or Debian,
# with Nginx (as a reverse proxy) and Naxsi web application firewall.
#
# This script should only be used on a Virtual Private Server (VPS) or dedicated server,
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

if [ "$(lsb_release -si 2>/dev/null)" != "Ubuntu" ] && [ "$(lsb_release -si 2>/dev/null)" != "Debian" ]; then
  echo "Looks like you aren't running this script on a Ubuntu or Debian system."
  exit 1
fi

if [ "$(lsb_release -si 2>/dev/null)" = "Ubuntu" ]; then

os_ver="$(lsb_release -sr)"
if [ "$os_ver" != "16.04" ] && [ "$os_ver" != "14.04" ] && [ "$os_ver" != "12.04" ]; then
  echo "This script only supports Ubuntu versions 16.04, 14.04 and 12.04."
  exit 1
fi

fi

if [ "$(lsb_release -si 2>/dev/null)" = "Debian" ]; then

os_ver="$(sed 's/\..*//' /etc/debian_version 2>/dev/null)"
if [ "$os_ver" != "8" ]; then
  echo "This script only supports Debian versions 8 (Jessie)."
  exit 1
fi

fi

if [ "$(id -u)" != 0 ]; then
  echo "Sorry, you need to run this script as root."
  exit 1
fi

if [ "$1" = "" ] || [ "$1" = "BLOG_FULL_DOMAIN_NAME" ]; then
  script_name=$(basename "$0")
  echo "Usage: bash $script_name BLOG_FULL_DOMAIN_NAME"
  echo
  echo 'Note: You must replace BLOG_FULL_DOMAIN_NAME above with'
  echo 'the actual full domain name of your new Ghost blog!'
  exit 1
fi

clear
echo 'Welcome! This script installs Ghost blog (https://ghost.org) on your server,'
echo 'with Nginx (as a reverse proxy) and Naxsi web application firewall.'
echo
echo 'The fully qualified domain name (FQDN) for your new blog is:'
echo
echo "$1"
echo
echo 'Please double check. This MUST be correct for your blog to work!'
echo
echo 'IMPORTANT NOTES:'
echo 'This script should only be used on a Virtual Private Server (VPS) or dedicated server,'
echo 'with *freshly installed* Ubuntu LTS or Debian 8.'
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
cd /opt/src || { echo "Failed to change working directory to /opt/src. Aborting."; exit 1; }

# Before doing anything else, we update the OS and software:
export DEBIAN_FRONTEND=noninteractive
apt-get -y update
apt-get -y dist-upgrade

# We need some more software:
apt-get -y install unzip fail2ban iptables-persistent \
  build-essential apache2-dev libxml2-dev wget curl \
  libcurl4-openssl-dev libpcre3-dev libssl-dev

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
[ -f /etc/fail2ban/jail.local ] && /bin/cp -f /etc/fail2ban/jail.local /etc/fail2ban/jail.local.old
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
unzip -o ghost-latest.zip && /bin/rm -f ghost-latest.zip
npm install --production

# Generate config file and make sure that Ghost uses your actual domain name
/bin/cp -f config.js config.js.old
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

# Commands below will be run as "root".

# Create the logfile:
touch /var/log/nodelog.txt
chown ghost.ghost /var/log/nodelog.txt

# Download and extract Naxsi:
cd /opt/src || { echo "Failed to change working directory to /opt/src. Aborting."; exit 1; }
wget -t 3 -T 30 -qO- https://github.com/nbs-system/naxsi/archive/0.54.tar.gz | tar xvz
[ ! -d naxsi-0.54 ] && { echo "Could not retrieve the Naxsi archive file. Aborting."; exit 1; }

# Next we create a user for nginx:
adduser --system --no-create-home --disabled-login --disabled-password --group nginx

# Download and compile the latest version of Nginx:
cd /opt/src || { echo "Failed to change working directory to /opt/src. Aborting."; exit 1; }
wget -t 3 -T 30 -qO- http://nginx.org/download/nginx-1.8.1.tar.gz | tar xvz
[ ! -d nginx-1.8.1 ] && { echo "Could not retrieve Nginx source files. Aborting."; exit 1; }
cd nginx-1.8.1 || { echo "Failed to change directory to /opt/src/nginx-1.8.1. Aborting."; exit 1; }
./configure --add-module=../naxsi-0.54/naxsi_src/ \
  --prefix=/opt/nginx --user=nginx --group=nginx \
  --with-http_ssl_module --with-http_spdy_module --with-http_realip_module
make && make install
# The "make" command may take some time...

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
# Note: This step is not required for Naxsi to work. You can do it later.
cd /opt/src/naxsi-0.54/nxapi/ || { echo "Failed to change directory to /opt/src/naxsi-0.54/nxapi. Aborting."; exit 1; }
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

systemctl daemon-reload
systemctl enable nginx.service

fi

# Create the public folder which will hold robots.txt, etc.
mkdir -p "/var/www/${BLOG_FQDN}/public"

# The only thing left is modifying the Nginx configuration file
# Download example Nginx.conf at https://gist.github.com/hwdsl2/2556d2cf9d73ba858c63
cd /opt/nginx/conf || { echo "Failed to change working directory to /opt/nginx/conf. Aborting."; exit 1; }
/bin/cp -f nginx.conf nginx.conf.old
example_nginx_conf=https://gist.githubusercontent.com/hwdsl2/2556d2cf9d73ba858c63/raw/nginx.conf
wget -t 3 -T 30 -nv -O nginx.conf $example_nginx_conf
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
echo 'Congratulations! Your new Ghost blog install is complete!'
echo
echo "Next, you must set up DNS (A Record) to point ${BLOG_FQDN} to this server's IP $PUBLIC_IP."
echo
echo "When using your blog for the first time, browse to http://${BLOG_FQDN}/ghost/"
echo "Or alternatively, set up SSH port forwarding and browse to http://localhost:2368/ghost/"
echo "to create the Admin user of your Ghost blog. Choose a very secure password."
echo
echo "After your blog is set up, follow additional instructions in my tutorial (link below) to:"
echo "https://blog.ls20.com/install-ghost-0-4-with-nginx-and-naxsi-on-ubuntu/#naxsi1"
echo
echo "1. Set Up HTTPS for Your Blog (Optional)"
echo "2. Sitemap, Robots.txt and Extras (Optional)"
echo "3. Setting Up E-Mail on Ghost (Optional)"
echo
echo "Questions? Refer to the official Ghost Guide: http://support.ghost.org/"
echo "Or feel free to leave a comment on my blog at link above."
echo
echo "Documentation for Naxsi: https://github.com/nbs-system/naxsi/wiki"
