import os, sys, commands, time, datetime
from multiprocessing import Pool

# Enter the IPs here want to scan for
CUSTOMER_PUBLIC_IP = '1.2.3.4 1.2.3.5 1.2.3.6 1.2.3.7'
CUSTOMER_PUBLIC_IP_LIST = CUSTOMER_PUBLIC_IP.split()

# These many processes will be spawned for scanning 
NUMBER_OF_FORKED_PROCESSES = 150

ip_ports = {}
lines = []
open_ports = []
closed_ports = [] 

current_time = datetime.datetime.fromtimestamp(time.time()).strftime('%Y%m%d-%H%M%S')
filename = "~/port-scan-" + current_time + ".log"

def write_to_file(val):
    global filename
    with open(filename, "a") as f0:
        f0.write(val)

def run_parallel_nmap(ip):
    nmap_cmd = "sudo nmap -sV -n -p 0-65535 -T5 -Pn --version-light " + ip
    print "Now running : %s" % nmap_cmd
    try:
        status, nmap_cmd_resp = commands.getstatusoutput(nmap_cmd)
    except Exception as e:
        print "ERROR: Exception occurred  %s" % str(e)
    return nmap_cmd_resp

def do_nmap():
    global NUMBER_OF_FORKED_PROCESSES
    nmap_results = []
    pool = Pool(processes = NUMBER_OF_FORKED_PROCESSES)
    nmap_results = pool.map(run_parallel_nmap, CUSTOMER_PUBLIC_IP_LIST)
    pool.terminate()
    return nmap_results

def do_nmap_analysis(all_nmap_data):
    global filename
    global ip_ports
    write_to_file(" Analysing gathered data from nmap......\n")
    key = ''
    for item in list(all_nmap_data):
        one_nmap_data = item.split('\n')
        for line in one_nmap_data:
            if 'Nmap scan report for' in line:
                # extract the key(which is IP)
                ip = line.split()[-1]
                key = ip
                ip_ports[key] = {'open_ports': [], 'closed_ports': []}
            if '/tcp' in line and 'open' in line:
                # extract the value(port) of the key
                port = line.split()[0].split('/')[0]
                ip_ports[key]['open_ports'].append(port)
            if '/tcp' in line and 'closed' in line:
                # extract the value(port) of the key
                port = line.split()[0].split('/')[0]
                ip_ports[key]['closed_ports'].append(port)

    for ip,ports in ip_ports.iteritems():
        if (len(ip_ports[ip]['open_ports']) is not 0) or (len(ip_ports[ip]['closed_ports']) is not 0):
            ip_ports_string = str(ip) + " " + str(ports) + "\n"
            write_to_file(ip_ports_string)
   

def job():
    all_nmap_data = []
    global current_time
    global filename
    start_string = "******** Port scan started at " + current_time + "********\n"
    print start_string    
    write_to_file(start_string)
    all_nmap_data = do_nmap()
    with open(filename, "a") as f:
        for item in all_nmap_data:
            f.write("%s\n" % item)
    print "Detailed nmap log has been dumped at %s" % filename
    end_time = datetime.datetime.fromtimestamp(time.time()).strftime('%Y%m%d-%H%M%S')
    host_scanned_string = " Scanned " + str(len(CUSTOMER_PUBLIC_IP_LIST)) + " hosts !!!\n"
    write_to_file(host_scanned_string)
    end_string = "******** Port scan completed at " + end_time + "********\n"
    print end_string
    write_to_file(end_string)
    do_nmap_analysis(all_nmap_data)

job()
