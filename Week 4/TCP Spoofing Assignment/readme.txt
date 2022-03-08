To solve this flag, I have decided to create a low-level socket program with Python that does not use scapy, but raw sockets directly.

The reason for that is that I have always wanted to learn raw socket programming, and with this assignment I got the occasion for it.

It has been a much longer learning curve than I thought, and although I have learned a lot, I haven't been able to identify the flag - so far.

My program solves both the UDP and TCP spoofing by the means of choosing the modality via command-line parameters. By default, it will try to solve the UDP spoofing, and by using -t will try the TCP flag.

The program also has a built-in UDP server which collects the flags sent by the server, and therefore it is not necessary to run netcat or Wireshark.  Furthermore, it will automatically detect the self-IP address on the "tap0" interface (by default) and the flag server's IP address.

The program is pretty self-explaining by the means of the simple code and comments.  The following are the command line parameters implemented:

"-I" or "--int"   Interface to use (default is tap0)
"-u" or "--udp"   UDP spoofing (default)
"-t" or "--tcp"   TCP spoofing (cannot be together with UDP)
"-g" or "--guess" TCP guess mode (only TCP, used to guess sequence numbers, UDP server disabled)
"-n" or "--syn"   Sequence number to start (only TCP, default is 1)
"-s" or "--srv"   Server to attack (default to assignment server)
"-p" or "--port"  Port to attack (default to assignment 13337)

IMPORTANT: it is necessary to install the following IPTABLES rule to make this assignment work:

# sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

Furthermore, the program has to be run as privileged user (root).  The included launch.json file is a configuration file for Microsoft Visual Studio which allows to run it comfortably from inside the IDE.

Shortcomings
------------
Where I have failed so far, is that I have been unable to reproduce the spoofed sequence number.  I have definitely identify some form of pattern through the sequence number, but I have been so far unable to reproduce it and receive the flag back from the server.  It works brilliantly for the UDP, anyway.

While it is a pity I have not finished on time, I have enjoyed the learning process and the activity a lot.