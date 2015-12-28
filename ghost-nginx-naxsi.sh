Follow this step-by-step guide to install Ghost blog (https://ghost.org/) on Ubuntu,
with Nginx as a reverse proxy and the Naxsi web application firewall. This guide is based on
the blog post of Herman Stevens, with important fixes and optimizations added by me (Lin Song).

Link to my tutorial: 
https://blog.ls20.com/install-ghost-0-4-with-nginx-and-naxsi-on-ubuntu/
Alternative tutorial for Ghost blog with ModSecurity:
https://blog.ls20.com/install-ghost-0-3-3-with-nginx-and-modsecurity/
Original post by Herman Stevens: 
https://blog.igbuend.com/dude-looks-like-a-ghost/

Special thanks to these people for help on improving this guide:
Remy van Elst (https://raymii.org), Phil Bayfield (http://phil.io/)

This guide can be used with both Ubuntu 14.04 (Trusty) and 12.04 (Precise) servers.
The only difference is in the install steps for Node.js. See details below.

Please start with a freshly installed Ubuntu 14.04/12.04 system.
Commands below should be run as user "root", unless otherwise noted.

# -------------------------------------------------------------------------------------------

** !! IMPORTANT !! **
Please define the full domain name of your Ghost blog here:
 (You MUST replace myblog.example.com with your actual domain name)

BLOG_FQDN=myblog.example.com
export BLOG_FQDN
echo "$BLOG_FQDN" > /tmp/BLOG_FQDN

# Before doing anything else make it a habit to update the OS and software:
apt-get update
apt-get -y upgrade

# Install git (if not already installed):
apt-get -y install git

# We need some more software:
apt-get -y install unzip fail2ban iptables-persistent \
  build-essential apache2-dev libxml2-dev \
  libcurl4-openssl-dev libpcre3-dev libssl-dev

(Optional) Commands between dividers below are optional, but they could improve the security 
  of your server and reduce the number of brute-force login attempts in your SSH logs.

# Start of optional commands
# -------------------------------------------------------------------------------------------

# Configure a non-standard port for SSH (e.g. 6543)
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.old
sed 's/Port 22/Port 6543/' </etc/ssh/sshd_config >/etc/ssh/sshd_config.new
mv /etc/ssh/sshd_config.new /etc/ssh/sshd_config
service ssh restart

# Let Fail2Ban monitor the non-standard SSH port
[ -f /etc/fail2ban/jail.local ] && cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.old
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

# Modify the iptables configuration
# Make those rules persistent using the package "iptables-persistent".
# Hint: To save time, copy multiple lines at once before pasting.

service iptables-persistent start
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -d 127.0.0.0/8 -j REJECT
iptables -A INPUT -p icmp --fragment -j DROP
iptables -A INPUT -p icmp --icmp-type 0 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type 3 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type 4 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type 8 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type 11 -j ACCEPT
iptables -A INPUT -p icmp -j DROP
# This line is not needed if you configured a different SSH port.
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
# Replace 6543 below with the new SSH port you configured
# or remove this line if you use the standard port 22
iptables -A INPUT -p tcp --dport 6543 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -j DROP
iptables -A FORWARD -j DROP
service fail2ban stop
/etc/init.d/iptables-persistent save
service fail2ban start

(Optional) If your server has IPv6 enabled, you may also want to configure IP6Tables
 by editing the file "/etc/iptables/rules.v6". You can search for examples on the web.

Next, we need to install Node.js. See separate steps for Ubuntu 14.04 and 12.04 below.
 (Check Ubuntu version: lsb_release -sr)

# -------------------------------------------------------------------------------------------
** Steps for Ubuntu 14.04 (Trusty) ONLY **
# -------------------------------------------------------------------------------------------

apt-get -y install nodejs nodejs-legacy npm

# -------------------------------------------------------------------------------------------
** Steps for Ubuntu 12.04 (Precise) ONLY **
# -------------------------------------------------------------------------------------------
(Choose ONE from the two methods below)

IMPORTANT: Ghost blog supports Node.js versions 0.10.x, 0.12.x and 4.2.x only.

[Method 1] Installing Node.js via package manager.
  Source: https://nodesource.com/blog/nodejs-v012-iojs-and-the-nodesource-linux-repositories#installingnodejsv012

curl -sL https://deb.nodesource.com/setup_0.12 | sudo bash -
sudo apt-get install -y nodejs

[Method 2] Compile node.js from source.
  Note: If you use this method to install node.js, later when a newer version is available,
  you may want to repeat these download, compile & install steps to upgrade it.
  This also applies to other software (e.g. Naxsi, Nginx) that are compiled from source.

cd
wget -qO- https://nodejs.org/dist/v0.12.9/node-v0.12.9.tar.gz | tar xvz
cd node-v0.12.9
./configure --prefix=/usr
make && make install
# The "make" command may take some time...

# -------------------------------------------------------------------------------------------

* Instructions below are for BOTH Ubuntu 14.04 and 12.04.

# To keep your Ghost blog running, install "forever".
cd
npm install forever -g

# Create a user to run Ghost:
mkdir -p /var/www
useradd -d /var/www/${BLOG_FQDN} -m -s /bin/false ghost

# Switch to user "ghost".
su - ghost -s /bin/bash

# Commands below will be run as user "ghost".

# Retrieve the domain name of your blog from temp file:
BLOG_FQDN=$(cat /tmp/BLOG_FQDN)
export BLOG_FQDN

# Get the ghost source (latest version), unzip and install.
cd
wget https://ghost.org/zip/ghost-latest.zip
unzip ghost-latest.zip && rm ghost-latest.zip
npm install --production

# Generate config file and make sure that Ghost uses your actual domain name
sed "s/my-ghost-blog.com/${BLOG_FQDN}/" <config.example.js >config.js

# We need to make certain that Ghost will start automatically after a reboot
# Open the file in the editor:
cd
nano -w starter.sh

# Copy the following content and paste into nano editor

#!/bin/sh
pgrep -f "/usr/bin/node" >/dev/null
if [ $? -ne 0 ]; then
  export PATH=/usr/local/bin:$PATH
  export NODE_ENV=production
  NODE_ENV=production forever start --sourceDir /var/www/YOUR.DOMAIN.NAME index.js >> /var/log/nodelog.txt 2>&1
else
  echo "Already running!"
fi

# Save the file by CTRL-O and Enter and exit nano with CTRL-X.

# Replace placeholder domain with your actual domain name:
sed -i "s/YOUR.DOMAIN.NAME/${BLOG_FQDN}/" starter.sh

# Make the script executable with:
chmod +x starter.sh

# We use crontab to start this script after a reboot:
crontab -l 2>/dev/null | { cat; echo "@reboot /var/www/${BLOG_FQDN}/starter.sh"; } | crontab -

# Exit the shell so that you are root again.
exit

# Commands below will be run as user "root".

# Create the logfile:
touch /var/log/nodelog.txt
chown ghost.ghost /var/log/nodelog.txt

# Download and extract Naxsi:
cd
wget -qO- https://github.com/nbs-system/naxsi/archive/0.54.tar.gz | tar xvz

# Next we create a user for nginx:
adduser --system --no-create-home --disabled-login --disabled-password --group nginx

# Download and compile the latest version of Nginx:
cd
wget -qO- http://nginx.org/download/nginx-1.8.0.tar.gz | tar xvz
cd nginx-1.8.0
./configure --add-module=../naxsi-0.54/naxsi_src/ \
  --prefix=/opt/nginx --user=nginx --group=nginx \
  --with-http_ssl_module --with-http_spdy_module --with-http_realip_module \
  --without-http_scgi_module --without-http_uwsgi_module \
  --without-http_fastcgi_module --without-http_autoindex_module
make && make install
# The "make" command may take some time...

# Set Up Naxsi
cd ~/naxsi-0.54/nxapi/
python setup.py install
mkdir -p /etc/nginx
cp ~/naxsi-0.54/naxsi_config/naxsi_core.rules /etc/nginx/
nano -w /etc/nginx/mysite.rules

# Copy the following content and paste into nano editor.

LearningMode; #Enables learning mode
SecRulesEnabled;
#SecRulesDisabled;
DeniedUrl "/RequestDenied";
## check rules
CheckRule "$SQL >= 8" BLOCK;
CheckRule "$RFI >= 8" BLOCK;
CheckRule "$TRAVERSAL >= 4" BLOCK;
CheckRule "$EVADE >= 4" BLOCK;
CheckRule "$XSS >= 8" BLOCK;
BasicRule  wl:1015 "mz:BODY";
BasicRule  wl:1001 "mz:BODY";
BasicRule  wl:1205 "mz:BODY";
BasicRule  wl:1310 "mz:BODY";
BasicRule  wl:1311 "mz:BODY";
BasicRule  wl:1200 "mz:BODY";
BasicRule  wl:1000 "mz:BODY";
BasicRule  wl:1007 "mz:BODY";
BasicRule  wl:1008 "mz:BODY";
BasicRule  wl:1009 "mz:BODY";
BasicRule  wl:1010 "mz:BODY";
BasicRule  wl:1011 "mz:BODY";
BasicRule  wl:1013 "mz:BODY";
BasicRule  wl:1016 "mz:BODY";
BasicRule  wl:1100 "mz:BODY";
BasicRule  wl:1101 "mz:BODY";
BasicRule  wl:1302 "mz:BODY";
BasicRule  wl:1303 "mz:BODY";
BasicRule  wl:1314 "mz:BODY";
BasicRule  wl:1015 "mz:$BODY_VAR:value";
BasicRule  wl:1001 "mz:$BODY_VAR:value";
BasicRule  wl:1200 "mz:$BODY_VAR:value";
BasicRule  wl:1205 "mz:$BODY_VAR:value";
BasicRule  wl:1310 "mz:$BODY_VAR:value";
BasicRule  wl:1311 "mz:$BODY_VAR:value";
BasicRule  wl:1000 "mz:$BODY_VAR:markdown";
BasicRule  wl:1001 "mz:$BODY_VAR:markdown";
BasicRule  wl:1007 "mz:$BODY_VAR:markdown";
BasicRule  wl:1008 "mz:$BODY_VAR:markdown";
BasicRule  wl:1009 "mz:$BODY_VAR:markdown";
BasicRule  wl:1010 "mz:$BODY_VAR:markdown";
BasicRule  wl:1011 "mz:$BODY_VAR:markdown";
BasicRule  wl:1013 "mz:$BODY_VAR:markdown";
BasicRule  wl:1015 "mz:$BODY_VAR:markdown";
BasicRule  wl:1016 "mz:$BODY_VAR:markdown";
BasicRule  wl:1100 "mz:$BODY_VAR:markdown";
BasicRule  wl:1101 "mz:$BODY_VAR:markdown";
BasicRule  wl:1205 "mz:$BODY_VAR:markdown";
BasicRule  wl:1302 "mz:$BODY_VAR:markdown";
BasicRule  wl:1303 "mz:$BODY_VAR:markdown";
BasicRule  wl:1310 "mz:$BODY_VAR:markdown";
BasicRule  wl:1311 "mz:$BODY_VAR:markdown";
BasicRule  wl:1314 "mz:$BODY_VAR:markdown";
BasicRule  wl:1000 "mz:BODY|NAME";
BasicRule  wl:1015 "mz:$URL:/ghost/api/v0.1/settings/|ARGS";
BasicRule  wl:1015 "mz:$URL:/ghost/api/v0.1/settings/|$ARGS_VAR:type";
BasicRule  wl:1310 "mz:$URL:/ghost/api/v0.1/authentication/setup/|BODY|NAME";
BasicRule  wl:1311 "mz:$URL:/ghost/api/v0.1/authentication/setup/|BODY|NAME";

# Save the file by CTRL-O and Enter and exit nano with CTRL-X.

# Create the following file:
nano -w /etc/init/nginx.conf

# Copy and paste the following content to make Nginx autorun:

# nginx
description "nginx http daemon"
author "Philipp Klose <me@'thisdomain'.de>"
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

# Save the file by CTRL-O and Enter and exit nano with CTRL-X.

# Create the public folder which will hold robots.txt, etc.
mkdir /var/www/${BLOG_FQDN}/public

# The only thing left is modifying the Nginx configuration file
mv /opt/nginx/conf/nginx.conf /opt/nginx/conf/nginx.conf.old
nginx_conf_url=https://gist.githubusercontent.com/hwdsl2/2556d2cf9d73ba858c63/raw/nginx.conf
wget -t 3 -T 30 -O /opt/nginx/conf/nginx.conf $nginx_conf_url

# Replace every placeholder domain with your actual domain name:
sed -i "s/YOUR.DOMAIN.NAME/${BLOG_FQDN}/g" /opt/nginx/conf/nginx.conf

# Disable SSL configuration in nginx.conf for now (enable it after you fully set it up)
sed -i -e "s/listen 443/# listen 443/" -e "s/ssl_/# ssl_/" /opt/nginx/conf/nginx.conf

# Check the validity of the nginx.conf file and fix errors where necessary:
/opt/nginx/sbin/nginx -t

# The output should look like:
# nginx: the configuration file /opt/nginx/conf/nginx.conf syntax is ok
# nginx: configuration file /opt/nginx/conf/nginx.conf test is successful

# There is nothing left to do but reboot:
reboot

# -------------------------------------------------------------------------------------------

Next, set up DNS (A Record) to point your blog's domain name to your server's IP.
When using your blog for the first time, browse to http://YOUR.DOMAIN.NAME/ghost/
Alternatively, use SSH port forwarding and browse to http://localhost:2368/ghost/
to create the Admin user of your Ghost blog. Choose a very secure password.

After your blog is set up, follow additional instructions in my tutorial (link below) to:
https://blog.ls20.com/install-ghost-0-4-with-nginx-and-naxsi-on-ubuntu/#naxsi1

1. Set Up HTTPS for Your Blog (Optional)
2. Sitemap, Robots.txt and Extras (Optional)
3. Setting Up E-Mail on Ghost (Optional)

Questions? Refer to the official Ghost Guide: http://support.ghost.org/
Or feel free to leave a comment on my blog at link above.
