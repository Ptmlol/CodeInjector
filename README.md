# CodeInjector
This is a very powerful Linux program used to inject any kind of code you want into the target's web browser.
Only works with HTTP at the moment.
HTTPS/Windows version coming soon...

Change injection_code variable at line 32 with any code you want.

If you want to test the program on your own machine use:

>iptables -I INPUT -j NFQUEUE --queue-num 0

>iptables -I OUTPUT -j NFQUEUE --queue-num 0

then execute the program in the linux terminal by typing: python code_injector.py

If you want to test it while being the MITM (use arpspoofer.py) then you ll need to use the following commands before executing any python program:
Use:

>iptables --flush

>iptables -I FORWARD -j NFQUEUE --queue-num 0

>echo 1 > /proc/sys/net/ipv4/ip_forward

then feel free to run the arpspoofer.py followed by the code_injector. Remember it only works with HTTP.
