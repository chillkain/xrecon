#!/usr/bin/env python3

import pool
import logger
import sys
import time
import argparse
import subprocess
import os
from colorama import Fore, Style

pop3logger=logger.Logger(3)

# starts all pop3 scans for this specific port
# returns a list that will be used to check if everything went fine    
def pop3_scan_all(pool,ip,port):
    pop3logger.info('Started {bgreen}pop3 service scans{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')
    # list that will be appended to async_jobs to check for wrong executed async processes
    async_jobs_pop3 = []
    # pop3_nmap
    future = pool.submit(pop3_nmap, ip, port)
    async_jobs_pop3.append([future,"pop3_nmap", ip, port])
    return async_jobs_pop3

def pop3_nmap(ip,port):
    pop3logger.debug('Started {bgreen}pop3 nmap scan{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')
    command=f"nmap -sV -Pn --script='banner,(pop3* or ssl*) and not (brute or broadcast or dos or external or fuzzer)' -p {port} -o {port}_nmap_pop3 {ip}"
    subprocess.run(command,shell=True, cwd=f"{ip}/scans", stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL, check=True)
    pop3logger.debug('Finished {bgreen}pop3 nmap scan{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')

def async_test_pop3(ip, port):
    pop3logger.debug('Started {bgreen}async_test_pop3{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')
    time.sleep(3)
    pop3logger.debug('Finished {bgreen}async_test_pop3{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')

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
    pop3Pool=pool.Pool(max_workers,"pop3_pool")
    async_jobs_pop3=pop3_scan_all(pop3Pool, ip, port)
  
    while(pop3Pool.get_workers_in_queue() > 0):
        #sleep to avoid last minute workers added queues after the time stop
        time.sleep(2)
        pass 
    scan_time = round(time.time() - starttime,3)
    
    for async_job in async_jobs_pop3:
        future = async_job[0]
        func = async_job[1]
        ip = async_job[2]
        port = async_job[3]
        if(async_job[0].exception()):
            pop3logger.error(f"{func} did not execute correctly for {ip} port {port}: {future.exception()}")

    pop3logger.info('This scan took {bmagenta}{scan_time}{rst} seconds')