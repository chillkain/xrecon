#!/usr/bin/env python3

import pool
import logger
import sys
import time
import argparse
import subprocess
import os
from colorama import Fore, Style

sshlogger=logger.Logger(3)

# starts all ssh scans for this specific port
# returns a list that will be used to check if everything went fine    
def ssh_scan_all(pool,ip,port):
    sshlogger.info('Started {bgreen}ssh service scans{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')
    # list that will be appended to async_jobs to check for wrong executed async processes
    async_jobs_ssh = []
    # ssh_nmap
    future = pool.submit(ssh_nmap, ip, port)
    async_jobs_ssh.append([future,"ssh_nmap", ip, port])
    return async_jobs_ssh

def ssh_nmap(ip,port):
    sshlogger.debug('Started {bgreen}ssh nmap scan{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')
    command=f"nmap -T4 -sV -Pn --script=ssh* -p {port} -o {port}_nmap_ssh {ip}"
    subprocess.run(command,shell=True, cwd=f"{ip}/scans", stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL, check=True)
    sshlogger.debug('Finished {bgreen}ssh nmap scan{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')

def async_test_ssh(ip, port):
    sshlogger.debug('Started {bgreen}async_test_ssh{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')
    time.sleep(3)
    sshlogger.debug('Finished {bgreen}async_test_ssh{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')

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
    sshPool=pool.Pool(max_workers,"ssh_pool")
    async_jobs_ssh=ssh_scan_all(sshPool, ip, port)
  
    while(sshPool.get_workers_in_queue() > 0):
        #sleep to avoid last minute workers added queues after the time stop
        time.sleep(2)
        pass 
    scan_time = round(time.time() - starttime,3)
    
    for async_job in async_jobs_ssh:
        future = async_job[0]
        func = async_job[1]
        ip = async_job[2]
        port = async_job[3]
        if(async_job[0].exception()):
            sshlogger.error(f"{func} did not execute correctly for {ip} port {port}: {future.exception()}")

    sshlogger.info('This scan took {bmagenta}{scan_time}{rst} seconds')