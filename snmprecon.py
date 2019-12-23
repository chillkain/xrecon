#!/usr/bin/env python3

import pool
import logger
import sys
import time
import argparse
import subprocess
import os
from colorama import Fore, Style

snmplogger=logger.Logger(3)

# starts all snmp scans for this specific port
# returns a list that will be used to check if everything went fine    
def snmp_scan_all(pool,ip,port):
    snmplogger.info('Started {bgreen}snmp service scans{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')
    # list that will be appended to async_jobs to check for wrong executed async processes
    async_jobs_snmp = []
    # snmp_nmap
    future = pool.submit(snmp_nmap, ip, port)
    async_jobs_snmp.append([future,"snmp_nmap", ip, port])
    # snmp_onesixtyone
    future = pool.submit(snmp_onesixtyone, ip, port)
    async_jobs_snmp.append([future,"snmp_onesixtyone", ip, port])
    return async_jobs_snmp

def snmp_nmap(ip,port):
    snmplogger.debug('Started {bgreen}snmp nmap scan{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')
    command=f"nmap -sV -Pn -sU --script=snmp-netstat,snmp-processes -p {port} -o {port}_nmap_snmp {ip}"
    subprocess.run(command,shell=True, cwd=f"{ip}/scans", stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL, check=True)
    snmplogger.debug('Finished {bgreen}snmp nmap scan{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')

def snmp_onesixtyone(ip,port):
    snmplogger.debug('Started {bgreen}onesixtyone scan{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')
    command=f"onesixtyone {ip} -c /usr/share/seclists/Discovery/SNMP/snmp.txt | tee {port}_onesixtyone.log"
    results = subprocess.check_output(command,shell=True, cwd=f"{ip}/scans")
    # print(results)
    snmplogger.debug('Finished {bgreen}onesixtyone scan{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')

# def snmp_walk(ip,port):
#     snmplogger.debug('Started {bgreen}snmp specific nmap scan{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')
#     command=f"nmap -sV -Pn --script=snmp-netstat,snmp-processes -p {port} -oA {port}_nmap_snmp {ip}"
#     subprocess.run(command,shell=True, cwd=f"{ip}/scans", stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL, check=True)
#     snmplogger.debug('Finished {bgreen}snmp specific nmap scan{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')

def async_test_snmp(ip, port):
    snmplogger.debug('Started {bgreen}async_test_snmp{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')
    time.sleep(3)
    snmplogger.debug('Finished {bgreen}async_test_snmp{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')

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
    snmpPool=pool.Pool(max_workers,"snmp_pool")
    async_jobs_snmp=snmp_scan_all(snmpPool, ip, port)
  
    while(snmpPool.get_workers_in_queue() > 0):
        #sleep to avoid last minute workers added queues after the time stop
        time.sleep(2)
        pass 
    scan_time = round(time.time() - starttime,3)
    
    for async_job in async_jobs_snmp:
        future = async_job[0]
        func = async_job[1]
        ip = async_job[2]
        port = async_job[3]
        if(async_job[0].exception()):
            snmplogger.error(f"{func} did not execute correctly for {ip} port {port}: {future.exception()}")

    snmplogger.info('This scan took {bmagenta}{scan_time}{rst} seconds')