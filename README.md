# Ghost Blog Auto Setup Scripts &nbsp; [![Build Status](https://travis-ci.org/hwdsl2/setup-ghost-blog.svg?branch=master)](https://travis-ci.org/hwdsl2/setup-ghost-blog)

*Read this in other languages: [English](README.md), [简体中文](README-zh.md).*

Scripts to install your own <a href="https://github.com/TryGhost/Ghost" target="_blank">Ghost blog</a> on Ubuntu, Debian or CentOS, with <a href="http://nginx.org/en/" target="_blank">Nginx</a> (as a reverse proxy) and <a href="https://www.modsecurity.org/" target="_blank">ModSecurity</a> or <a href="https://github.com/nbs-system/naxsi" target="_blank">Naxsi</a> web application firewall for optimal performance and security.

Powered by Node.js, Ghost blog is a simple and modern <a href="https://ghost.org/vs/wordpress/" target="_blank">WordPress alternative</a> which puts the excitement back into blogging. It's beautifully designed, easy to use, completely open source, and free for everyone.

**New:** **Install multiple blogs** on the same server! Simply re-run the script with a new full domain name.

<a href="https://blog.ls20.com/install-ghost-0-3-3-with-nginx-and-modsecurity/" target="_blank">**&raquo; Related tutorial: Ghost Blog Auto Setup with Nginx and ModSecurity**</a> <a href="https://blog.ls20.com/install-ghost-0-4-with-nginx-and-naxsi-on-ubuntu/" target="_blank">**(or Naxsi)**</a>

## Requirements

A dedicated server or Virtual Private Server (VPS), **freshly installed** with:   
- Ubuntu 16.04 (Xenial), 14.04 (Trusty) or 12.04 (Precise)
- Debian 8 (Jessie)
- CentOS 6 or 7

**Note:** A minimum of **512 MB** RAM is required.

:warning: **DO NOT** run these scripts on your PC or Mac! They should only be used on a server!

## Installation

First, update your system with `apt-get update && apt-get dist-upgrade` (Ubuntu/Debian) or `yum update` (CentOS) and reboot. This is optional, but recommended.

#### Select ModSecurity WAF:

```
wget https://git.io/ghost-nginx-modsecurity -O ghost-setup.sh
sudo bash ghost-setup.sh BLOG_FULL_DOMAIN_NAME
```

#### Select Naxsi WAF:

```
wget https://git.io/ghost-nginx-naxsi -O ghost-setup.sh
sudo bash ghost-setup.sh BLOG_FULL_DOMAIN_NAME
```

**Note:** Replace the above with your blog's full domain name. The latest <a href="https://dev.ghost.org/tag/releases/" target="_blank">0.11.x (LTS)</a> version of Ghost blog will be installed.

## License

Copyright (C) 2015-2017 <a href="https://www.linkedin.com/in/linsongui" target="_blank">Lin Song</a> <a href="https://www.linkedin.com/in/linsongui" target="_blank"><img src="https://static.licdn.com/scds/common/u/img/webpromo/btn_viewmy_160x25.png" width="160" height="25" border="0" alt="View my profile on LinkedIn"></a>   
Based on <a href="https://blog.igbuend.com/dude-looks-like-a-ghost/" target="_blank">the work of Herman Stevens</a> (Copyright 2013)

Special thanks to <a href="https://raymii.org" target="_blank">Remy van Elst</a> and <a href="https://philio.me" target="_blank">Phil Bayfield</a> for their helpful suggestions.

This program is free software: you can redistribute it and/or modify it under the terms of the <a href="https://www.gnu.org/licenses/gpl.html" target="_blank">GNU General Public License</a> as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
