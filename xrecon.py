#!/usr/bin/env python3
# 
#    xrecon is a tool made to automate the recon face in my OSCP journey, feel free to use the code and alter to your wishes
#
#    This program can be redistributed and/or modified under the terms of the
#    GNU General Public License, either version 3 of the License, or (at your
#    option) any later version.

import argparse
import sys
import time
import concurrent.futures
import functools
import os
import subprocess
from pathlib import Path
import shutil
from datetime import datetime

# import custom recon scripts
import nmap_parser
import logger
import pool
import webrecon
import ftprecon
import smtprecon
import snmprecon
import mysqlrecon
import smbrecon
import pop3recon



# TODO:
#  fix verbosity for other files
#  add rbac for http module
#  add ssl for http module
#  skip already scanned ip, unless overwrite param is set
#  change every line of "... is done, ... workers still in the queue" to heartbeat at the bottom
#  only scan 443 instead of 80 and 443 for http
#  add UDP portscans
#    DNS


# initialise logger as global variable (verbosity level will be set through logger.set_verbosity())
logger=logger.Logger(0)
# processpool that will handle all asynchronous running functions
# will be overwritten
procPool=pool.Pool(1,"global_pool_that_will_be_overwritten")
# async_jobs list to check if  async workers raised errors
async_jobs=[] 


########################
###      EXTRAS      ###
########################

def create_folders(ip):
    # checks if folders are already in place, if not makes them 
    # if already there, move scan folder to backup folder and make new empty scan folder
    # make the directory structure 
    #   ip
    #      - exploit 
    #      - scans              -- most recent scans
    #      - scans_02123...     -- previous scans
    try:
        logger.info('creating folder structure for {byellow}{ip}{rst}')
        # get current date + time
        now = datetime.now()
        # create the classes path for each directory
        path_workdir = Path.cwd()
        path_ip = path_workdir / f"{ip}"
        path_ip_scan= path_ip / "scans"
        path_ip_exploit= path_ip / "exploit"
        path_ip_loot= path_ip / "loot"
        now = now.strftime("%d.%m.%Y..%H.%M")
        path_ip_scan_now = path_ip / f"scans_{now}"
        # if ip directory already exists 
        if path_ip.exists():
            # if scans folder exists in ip folder, move to backup folder and make new scans folder
            logger.debug('IP folder already exists for {byellow}{ip}{rst}, creating backup')
            if path_ip_scan.exists():
                shutil.move(str(path_ip_scan), str(path_ip_scan_now))
                path_ip_scan.mkdir()
            else:
                path_ip_scan.mkdir()
        else:
            # ip folder does not exist so make the folders
            logger.debug('IP folder made for {byellow}{ip}{rst}')
            path_ip.mkdir()
            path_ip_scan.mkdir()
            path_ip_exploit.mkdir()
            path_ip_loot.mkdir()

    except Exception as e:
        logger.fail(f'{bred} Failed to make folder structure: {e}')
    

########################
### PROTOCOL SCANNER ###
########################

# async test copy paste and adjust for every protocol
def async_test(sec, ip):
    # print(f"sleep {sec} for ip {ip}")
    logger.info('Started {bgreen}async_test{rst} for {byellow}{ip}{rst}')
    time.sleep(sec)
    logger.info('Finished {bgreen}async_test{rst} for {byellow}{ip}{rst}')

########################
###   NMAP SCANNING  ###
########################
# seperate nmap scan for each ip, protocol scans will only be started when nmap is ready

#add_done_callback returns the value and a function so we need to catch both and filter
def service_scanner_tcp(ip,future):
    global async_jobs
    logger.info('Started {bgreen}service scans{rst} on {byellow}{ip}{rst}')
    # parse xml TCP files to determine open ports
    try:
        nmapParser = nmap_parser.NmapParser(f"{ip}/scans/nmap_TCP_{ip}.xml")
        # services format = {'80': 'http', '443': 'http'} 
        tcpservices = nmapParser.get_open_ports()
        logger.info('nmap detected the services {bred}{tcpservices}{rst} on {byellow}{ip}{rst}')
        # start scanning of all the TCP ports
        for port in tcpservices:
            service_on_port = tcpservices[port]
            if("http" in service_on_port):
                async_jobs_http = webrecon.http_scan_all(procPool,ip,port)
                async_jobs+=async_jobs_http
            if("ssh" in service_on_port):
                async_jobs_ssh = webrecon.ssh_scan_all(procPool,ip,port)
                async_jobs+=async_jobs_ssh
            elif("ftp" in service_on_port ):
                async_jobs_ftp = ftprecon.ftp_scan_all(procPool,ip,port)
                async_jobs+=async_jobs_ftp
            elif("netbios-ssn" in service_on_port or "microsoft-ds" in service_on_port or "samba" in service_on_port):
                async_jobs_smb = smbrecon.smb_scan_all(procPool,ip,port)
                async_jobs+=async_jobs_smb
            elif("smtp" in service_on_port):
                async_jobs_smtp = smtprecon.smtp_scan_all(procPool,ip,port)
                async_jobs+=async_jobs_smtp
            elif("kv-server" in service_on_port):
                async_jobs_mysql = mysqlrecon.mysql_scan_all(procPool,ip,port)
                async_jobs+=async_jobs_mysql
            elif("pop" in service_on_port):
                async_jobs_pop3 = pop3recon.pop3_scan_all(procPool,ip,port)
                async_jobs+=async_jobs_pop3
            else:
                logger.warn('no recon scripts found for {bred}{service_on_port}{rst} on {byellow}{ip}{rst} port {byellow}{port}{rst}')

    except Exception as e:
        logger.error('Failed to {bgreen} start all TCP service scans {rst} for {byellow}{ip}{rst}, error={e}')
    
    

def service_scanner_udp(ip,future):
    global async_jobs
    logger.info('Started {bgreen} UDP service scans{rst} on {byellow}{ip}{rst}')

    # parse xml UDP files to determine open ports
    try:
        nmapParser = nmap_parser.NmapParser(f"{ip}/scans/nmap_UDP_{ip}.xml")
        # services format = {'80': 'http', '443': 'http'} 
        udpservices = nmapParser.get_open_ports()
        logger.info('nmap detected the services {bred}{udpservices}{rst} on {byellow}{ip}{rst}')
         # start scanning of all the UDP ports
        for port in udpservices:
            service_on_port = udpservices[port]
            if("snmp" in service_on_port):
                async_jobs_snmp = snmprecon.snmp_scan_all(procPool,ip,port)
                async_jobs+=async_jobs_snmp
            else:
                logger.warn('no recon scripts found for {bred}{service_on_port}{rst} on {byellow}{ip}{rst} port {byellow}{port}{rst}')

    except Exception as e:
        logger.error('Failed to {bgreen}parse nmap UDP results{rst} for {byellow}{ip}{rst}')
    
   

# performs nmap scan and when ready activates the different modules for the open ports
def nmapScan_TCP(ip):
    nmap_tcp = f"nmap -sV -Pn -T4 -p- {ip} -oA {ip}/scans/nmap_TCP_{ip}"
    # nmap_tcp = f"nmap -sV -Pn -T4 --top-ports=10 {ip} -oA {ip}/scans/nmap_TCP_{ip}"
    logger.info('Started {bgreen}nmap TCP scans{rst} on {byellow}{ip}{rst}' + (' with {bblue}{nmap_tcp}{rst}' if logger.get_verbosity() >= 1 else ''))
    #execute the TCP nmap command, supress the output (is synchronous execution, no new processes are made)
    subprocess.call(nmap_tcp,shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    logger.info('Finished {bgreen}nmap TCP scans{rst} on {byellow}{ip}{rst}' + (' with {bblue}{nmap_tcp}{rst}' if logger.get_verbosity() >= 1 else ''))
    #avoid xml access errors because it is not written entirely yet
    time.sleep(0.5) 

def nmapScan_UDP(ip):
    nmap_udp = f"nmap -sV -sU -Pn -T4 --top-ports=100 {ip} -oA {ip}/scans/nmap_UDP_{ip}"
    logger.info('Started {bgreen}nmap UDP scans{rst} on {byellow}{ip}{rst}' + (' with {bblue}{nmap_udp}{rst}' if logger.get_verbosity() >= 1 else ''))
    #execute the UDP nmap command, supress the output (is synchronous execution, no new processes are made)
    subprocess.call(nmap_udp,shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    logger.info('Finished {bgreen}nmap UDP scans{rst} on {byellow}{ip}{rst}' + (' with {bblue}{nmap_udp}{rst}' if logger.get_verbosity() >= 1 else ''))
    #avoid xml access errors because it is not written entirely yet
    time.sleep(0.5)


# starts the nmap scan for each ip
def startEnum(targets):
    for ip in targets:
        logger.info('Started the {bgreen}enumeration{rst} for {byellow}{ip}{rst}')
        #create folder structure
        create_folders(ip)
        #start TCP nmap scan on this ip
        nmap_worker_tcp = procPool.submit(nmapScan_TCP, ip)
        #when ready start scans on services
        nmap_worker_tcp.add_done_callback(functools.partial(service_scanner_tcp, ip))
        #start UDP nmap scan on this ip
        nmap_worker_udp = procPool.submit(nmapScan_UDP, ip)
        #when ready start scans on services
        nmap_worker_udp.add_done_callback(functools.partial(service_scanner_udp, ip))

########################
### INPUT PROCESSING ###
########################
# processes the manual ip input 
# TODO add valid ip syntax check 
def parse_ip(input):
    # split multiple ip in list op ips
    targets =input.split(",")   
    return targets

# processes the input ip list
# TODO add valid ip syntax check 
def parse_ipList(inputFile):
    targets=[]
    try:
        # open file and read ip on each line, add to targets list
        f = open(inputFile, "r")
        line=f.readline().strip('\n')
        while line:
            targets.append(line)
            line=f.readline().strip('\n')
    except Exception as e:
        logger.fail('{bred} could not process target list:{rst} {e} ' )
    return targets

def getOptions(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description="manuals are for dummies but these arguments could be useful")
    parser.add_argument("-i", "--input", help="target ip (use -i x.x.x.x,y.y.y.y for multiple ips)")
    parser.add_argument("-iL", "--inputList", help="target ip list, one ip per line")
    parser.add_argument("-o", "--overwrite", default=False, help="overwrite directories when they already exist")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Maximum amount of concurrent processes")
    parser.add_argument("-v", "--verbose",type=int, default=2, help="Verbose mode, 0-2")
    options = parser.parse_args(args)
    return options

########################
###     MAIN         ###
########################


if __name__ == "__main__":
    starttime = time.time()

    # fetches the variables given in the command prompt to parse them
    options = getOptions(sys.argv[1:])
    if options.verbose:
        logger.info('verbosity level set to {options.verbose}')
        logger.set_verbosity(options.verbose)

    # initiates the pool to queue the different workers
    max_workers=options.threads
    procPool=pool.Pool(max_workers,"xrecon_pool")

    #processes the targets
    targets=[]
    # if ip addresses are entered manually
    if (options.input):
        targets = parse_ip(options.input)
        startEnum(targets)
    # if ip addresses are provided in file
    elif(options.inputList):
        targets = parse_ipList(options.inputList)
        startEnum(targets)
    else:
        logger.fail('{bred}No targets specified!{rst}')

    # wait for all the processes in the queue to be finished
    # TODO: add heartbeat instead of inefficient while loop
    
    while(procPool.get_workers_in_queue() > 0):
        #sleep to avoid last minute workers added queues after the time stop
        time.sleep(2)
        pass   
    
    # check for exceptions occured in the async_jobs
    # placed here otherwise program waits on the async process to finish, -> kills the asynchronity
    # async_job=[future,func_name,ip,port]
    for async_job in async_jobs:
        future = async_job[0]
        func = async_job[1]
        ip = async_job[2]
        port = async_job[3]
        if(async_job[0].exception()):
            logger.error(f"{func} did not execute correctly for {ip} port {port}: {future.exception()}")

    scan_time = round(time.time() - starttime,3)
    logger.info('This scan took {bmagenta}{scan_time}{rst} seconds')