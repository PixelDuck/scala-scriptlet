TCPDUMP parsing
===============

This scala scriptlet was developed to parse a lot of tcpdump file in order to find client calling some SOAP web services.
The script analyse the file, remove header, retrieve TCP packet, find ip source (forwarded or real ip) and find the operation called.
This file can be used as a good starting point for a real TCP parser. PCAP definition was foud on http://www.kroosec.com/2012/10/a-look-at-pcap-file-format.html
