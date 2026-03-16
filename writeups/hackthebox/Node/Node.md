# Node

We’ve started executing a full port scan on the host.

![Untitled](images/Untitled.png)

Now let’s execute a port scan on the open ports on the host.

![Untitled](images/Untitled%201.png)

Accessing the webserver running on port 3000 we got the following on our browser.

![Untitled](images/Untitled%202.png)

Running a brute-force directory we got the following:

![Untitled](images/Untitled%203.png)

Analyzing the page’s source code we got the following JavaScript files.

![Untitled](images/Untitled%204.png)

By accessing those files we could get the API for the user’s path resource of the application.

![Untitled](images/Untitled%205.png)

Accessing the endpoint [`http://10.10.10.58:3000/api/users`](http://10.10.10.58:3000/api/users) we got the users that are save on the application.

![Untitled](images/Untitled%206.png)

With JohnTheRipper we could crack three hashes:

| **USERNAME** | **PASSWORD** | **ADMIN** |
| --- | --- | --- |
| myP14ceAdm1nAcc0uNT | manchester | True |
| tom | spongebob | False |
| mark | snowflake | False |

Log into the application using the administrator user, we got the following:

![Untitled](images/Untitled%207.png)

Downloading the backup file.

By examining the backup file we notice this is encoded on the base64 algorithm.

![Untitled](images/Untitled%208.png)

We first decrypt this file and save the output on myplace file. Checking the myplace file we got that the file is a ZIP file, so we try to unzip it.

![Untitled](images/Untitled%209.png)

The ZIP file needs a password in order to unzip it. Using `zip2john` tool we extracted the hash and save it on a file in order to crack this hash using the JohnTheRipper tool.

![Untitled](images/Untitled%2010.png)

The hash file is:

![Untitled](images/Untitled%2011.png)

Cracking it with john:

![Untitled](images/Untitled%2012.png)

The password from ZIP file is **magicword**.

![Untitled](images/Untitled%2013.png)

We noticed that the file unzipped was the backup of the whole site running on port 3000.

 Open the file we’ve got something like a password from user mark where there is a login URL using MongoDB database.

![Untitled](images/Untitled%2014.png)

We tried to log in on to the SSH service using this password and we were successful.

![Untitled](images/Untitled%2015.png)

| **USERNAME** | **PASSWORD** | **SERVICE** |
| --- | --- | --- |
| mark | 5AYRft73VtFpc84k | SSH |

## Privilege Escalation - Lateral Moviment

We searched around the host and executing the `ps` command we could check what process are running under user `tom`.

![Untitled](images/Untitled%2016.png)

Checking the app.js in /var/scheduler/ we’ve got:

![Untitled](images/Untitled%2017.png)

The code above is executing a system command. Knowing that we insert a command in `tasks` collection on MongoDB. We copy the `bash` to `/tmp` directory and set the SUID bit for it.

![Untitled](images/Untitled%2018.png)

![Untitled](images/Untitled%2019.png)

Executing the `test` bash.

![Untitled](images/Untitled%2020.png)

## Privilege Escalation - root

Searching for some privilege escalation as root, we found an application that is set the SUID bit.

![Untitled](images/Untitled%2021.png)

Checking this application on its directory

![Untitled](images/Untitled%2022.png)

We have to set up priviously our copy of bash user tom on group admin. We’ve do it using the tasks scheduler function on MongoDB.

![Untitled](images/Untitled%2023.png)

Our copy of bash now is

![Untitled](images/Untitled%2024.png)

Executing our malicious bash

![Untitled](images/Untitled%2025.png)

We copied, via `netcat`, the `backup` binary to our local machine in order to analyze it.

![Untitled](images/Untitled%2026.png)

![Untitled](images/Untitled%2027.png)

Executing `strings` command to `backup` binary we’ve got the interesting part of the binary.

![Untitled](images/Untitled%2028.png)

Executing the binary under strace tool we’ve got

```bash
╭─[us-vip-21]-[10.10.14.2]-[th3g3ntl3m4n@kali-mpt-pentest]-[~/htb/oscp/images/exploitation/privesc/backup]                                                                                    
╰─ $ strace ./backup 1 2 3                                                                                                                                                                  
execve("./backup", ["./backup", "1", "2", "3"], 0x7ffdb6de1ce8 /* 56 vars */) = 0                                                                                                           
[ Process PID=36146 runs in 32 bit mode. ]
```

![Untitled](images/Untitled%2029.png)

Checking this directory on the host.

![Untitled](images/Untitled%2030.png)

We created the `keys` file on `/etc/myplace` directory. Back on the `app.js` file there is a line where the application get the `backup_key` from this file.

![Untitled](images/Untitled%2031.png)

And the variable `backup_key` on the code is the second one on the `keys` file.

![Untitled](images/Untitled%2032.png)

In the file `keys`:

![Untitled](images/Untitled%2033.png)

Executing the `backup` tool like it shows on the `app.js`:

![Untitled](images/Untitled%2034.png)

So, after analyzing the backup’s tool code we could inject bash commands by breaking the `zip` command flow and change `>/dev/null` into `/bin/bash`.

![Untitled](images/Untitled%2035.png)