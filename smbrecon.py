#!/usr/bin/env python3
import pool
import logger
import sys
import time
import argparse
import subprocess
import os
from colorama import Fore, Style

smblogger=logger.Logger(3)

# starts all smb scans for this specific port
# returns a list that will be used to check if everything went fine    
def smb_scan_all(pool,ip,port):
    smblogger.info('Started {bgreen}smb service scans{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')
    # list that will be appended to async_jobs to check for wrong executed async processes
    async_jobs_smb = []
    # smb_nmap
    future = pool.submit(smb_nmap, ip, port)
    async_jobs_smb.append([future,"smb_nmap", ip, port])
    # smb_enum4linux
    future = pool.submit(smb_enum4linux, ip, port)
    async_jobs_smb.append([future,"smb_enum4linux", ip, port])
    return async_jobs_smb

def smb_nmap(ip,port):
    smblogger.debug('Started {bgreen}smb nmap scan{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')
    # only the safe scripts to avoid crashes of the system, vuln scans should be done manually
    command=f"nmap -sV -Pn --script=smb-brute,smb-double-pulsar-backdoor,smb-enum-domains,smb-enum-groups,smb-enum-processes,smb-enum-services,smb-enum-sessions,smb-enum-shares,smb-enum-users,smb-ls,smb-mbenum,smb-os-discovery,smb-protocols,smb-psexec,smb-system-info,smb-security-mode -p {port} -o {port}_nmap_smb {ip}"
    subprocess.run(command,shell=True, cwd=f"{ip}/scans", stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL, check=True)
    smblogger.debug('Finished {bgreen}smb nmap scan{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')

def smb_enum4linux(ip,port):
    smblogger.debug('Started {bgreen}smb enum4linux scan{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')
    command=f"enum4linux -a {ip} | tee {port}_enum4linux.log"
    subprocess.run(command,shell=True, cwd=f"{ip}/scans", stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL, check=True)
    smblogger.debug('Finished {bgreen}smb enum4linux scan{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')

def async_test_smb(ip, port):
    smblogger.debug('Started {bgreen}async_test_smb{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')
    time.sleep(3)
    smblogger.debug('Finished {bgreen}async_test_smb{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')

def getOptions(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description="manuals are for dummies but these arguments could be useful")
    parser.add_argument("-i", "--inputIP", help="target ip ")
    parser.add_argument("-p", "--inputPort", help="port to scan on")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Maximum amount of concurrent processes")
    options = parser.parse_args(args)
    return options
    


if __name__ == "__main__":
    starttime = time.time()
    # ip="193.173.10.234"

    # get command arguments
    options = getOptions(sys.argv[1:])
    ip=options.inputIP
    port=options.inputPort
    max_workers=options.threads

    # initiate the classes
    smbPool=pool.Pool(max_workers,"smb_pool")
    async_jobs_smb=smb_scan_all(smbPool, ip, port)
  
    while(smbPool.get_workers_in_queue() > 0):
        #sleep to avoid last minute workers added queues after the time stop
        time.sleep(2)
        pass 
    scan_time = round(time.time() - starttime,3)
    
    for async_job in async_jobs_smb:
        future = async_job[0]
        func = async_job[1]
        ip = async_job[2]
        port = async_job[3]
        if(async_job[0].exception()):
            smblogger.error(f"{func} did not execute correctly for {ip} port {port}: {future.exception()}")

    smblogger.info('This scan took {bmagenta}{scan_time}{rst} seconds')