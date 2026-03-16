# Poison

We started with the full port scan on the host.

![Untitled](images/Untitled.png)

We found two ports open. We executed a detailed port scan on that open ports.

![Untitled](images/Untitled%201.png)

Accessing the webpage on port 80 we got the following page.

![Untitled](images/Untitled%202.png)

On the page, we could test some PHP scripts. Testing one of the was suggested we got.

![Untitled](images/Untitled%203.png)

The `pwdbackup.txt` file is interesting and we write the name of the file on the parameter `?file=pwdbackup.txt` and we got.

![Untitled](images/Untitled%204.png)

In the file, there is a note saying the password was encoded 13 times. On the CyberChef site we could decrypt the encoded password by applying 13 times Base64 decoded.

![Untitled](images/Untitled%205.png)

As we could read the `pwdbackup` file we could have a Local File Inclusion vulnerability. Trying to read the `/etc/passwd` file from the system, we got.

![Untitled](images/Untitled%206.png)

We have the user `charix` on the system. Tried to log in via SSH with that decrypted password we were successful.

![Untitled](images/Untitled%207.png)

## Privilege Escalation

In the crarix’s home directory, we found a ZIP file called `secret.zip`.

![Untitled](images/Untitled%208.png)

Trying to unzip the file, we got a message that the zip file needs a passphrase.

![Untitled](images/Untitled%209.png)

We downloaded the file to our local machine and extract the hash and try to crack this hash.

![Untitled](images/Untitled%2010.png)

Trying to use the same password of the user charix, we could unzip the file.

![Untitled](images/Untitled%2011.png)

Running the [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) script we got the interesting VNC process running as root user.

![Untitled](images/Untitled%2012.png)

Checking the ports are open on the host.

![Untitled](images/Untitled%2013.png)

We port forwarding the 5901 from the server to our local machine:

![Untitled](images/Untitled%2014.png)

Doing some research we have found a tool that cracks VNC passwords. We tried to crack that secret file we downloaded from the server and we were successful.

![Untitled](images/Untitled%2015.png)

Trying to connect to the VNC service that is running on our local machine using the `vncviewer` we were successful.

![Untitled](images/Untitled%2016.png)

![Untitled](images/Untitled%2017.png)

We could compromise the root user.

## Persistence root Access

Now we have access as root, we copied our public key to the host via SSH `scp`command.

![Untitled](images/Untitled%2018.png)

And we write our public key in authorized_keys file in root SSH directory.

![Untitled](images/Untitled%2019.png)

Now we have access to the host as root user.

![Untitled](images/Untitled%2020.png)