# Ghost Blog Auto Setup Scripts &nbsp;[![Build Status](https://static.ls20.com/travis-ci/setup-ghost-blog.svg)](https://travis-ci.org/hwdsl2/setup-ghost-blog)

*Read this in other languages: [English](README.md), [简体中文](README-zh.md).*

Scripts to install your own <a href="https://github.com/TryGhost/Ghost" target="_blank">Ghost blog</a>, with <a href="http://nginx.org/en/" target="_blank">Nginx</a> (as a reverse proxy) and <a href="https://www.modsecurity.org/" target="_blank">ModSecurity</a> or <a href="https://github.com/nbs-system/naxsi" target="_blank">Naxsi</a> web application firewall for maximum performance and security. The latest <a href="https://dev.ghost.org/lts/" target="_blank">v0.11-LTS</a> version of Ghost blog will be installed.

Ghost blog is a simple, modern <a href="https://ghost.org/vs/wordpress/" target="_blank">WordPress alternative</a> which puts the excitement back into blogging. It's beautifully designed, easy to use, completely open source, and free for everyone.

**New:** Install **up to 10 blogs** on your server! Simply re-run the script with a new full domain name.

<a href="https://blog.ls20.com/install-ghost-0-3-3-with-nginx-and-modsecurity/" target="_blank">**&raquo; Related tutorial: Ghost Blog Auto Setup with Nginx and ModSecurity**</a> <a href="https://blog.ls20.com/install-ghost-0-4-with-nginx-and-naxsi-on-ubuntu/" target="_blank">**(or Naxsi)**</a>

## Requirements

A dedicated server or Virtual Private Server (VPS), **freshly installed** with:   
- Ubuntu 16.04 (Xenial), 14.04 (Trusty) or 12.04 (Precise)
- Debian 8 (Jessie)

**Note:** A minimum of **512 MB** RAM is required.

:warning: **DO NOT** run these scripts on your PC or Mac! They should only be used on a server!

## Installation

First, update your system with `apt-get update && apt-get dist-upgrade` and reboot. This is optional, but recommended.

#### Select ModSecurity WAF:

```
wget https://git.io/ghost-nginx-modsecurity -O ghost-nginx-modsecurity.sh
sudo bash ghost-nginx-modsecurity.sh BLOG_FULL_DOMAIN_NAME
```

#### Select Naxsi WAF:

```
wget https://git.io/ghost-nginx-naxsi -O ghost-nginx-naxsi.sh
sudo bash ghost-nginx-naxsi.sh BLOG_FULL_DOMAIN_NAME
```

**Note:** Replace `BLOG_FULL_DOMAIN_NAME` above with your actual full domain name.

## Author

**Lin Song** (linsongui@gmail.com)   
- Final year U.S. PhD candidate, majoring in Electrical and Computer Engineering (ECE)
- Actively seeking opportunities in areas such as Software or Systems Engineering
- Contact me on LinkedIn: <a href="https://www.linkedin.com/in/linsongui" target="_blank">https://www.linkedin.com/in/linsongui</a>

## License

Copyright (C) 2015-2016&nbsp;Lin Song&nbsp;&nbsp;&nbsp;<a href="https://www.linkedin.com/in/linsongui" target="_blank"><img src="https://static.licdn.com/scds/common/u/img/webpromo/btn_viewmy_160x25.png" width="160" height="25" border="0" alt="View my profile on LinkedIn"></a>    
Based on <a href="https://blog.igbuend.com/dude-looks-like-a-ghost/" target="_blank">the work of Herman Stevens</a> (Copyright 2013)

Special thanks to <a href="https://raymii.org" target="_blank">Remy van Elst</a> and <a href="https://philio.me" target="_blank">Phil Bayfield</a> for their helpful suggestions.

This program is free software: you can redistribute it and/or modify it under the terms of the <a href="https://www.gnu.org/licenses/gpl.html" target="_blank">GNU General Public License</a> as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
