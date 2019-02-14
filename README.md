# multiprocessing-port-scan
port-scanning-utility

This utility uses nmap infra to do port scan for the given set of IPs.
Nmap sends a TCP SYN to the receiving host. Receiving host can do 3 things:
1. Reply with an ACK packet => Receiving host's port is OPEN
2. Reply with an RST packet => Receiving host's port is CLOSED
3. No Reply                 => Receiving host's port is Filtered (this potentially points to a firewall at the receiving host)

This utility has been tested with ~3k hosts and it was able to scan it in less than 50 minutes with this configuration(see parallel-port-scan.py):

NUMBER_OF_FORKED_PROCESSES = 150

Additionally this tool will also analyse which ports are open and which are closed and report back in this format:


1.2.3.4 {'closed_ports': ['22'], 'open_ports': ['80']}
1.2.4.5 {'closed_ports': [], 'open_ports': ['22', '80']}
1.2.3.6 {'closed_ports': [], 'open_ports': ['22']}
