#!/usr/bin/env python3

import pool
import logger
import sys
import time
import argparse
import subprocess
import os
from colorama import Fore, Style

mysqllogger=logger.Logger(3)

# starts all mysql scans for this specific port
# returns a list that will be used to check if everything went fine    
def mysql_scan_all(pool,ip,port):
    mysqllogger.info('Started {bgreen}mysql service scans{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')
    # list that will be appended to async_jobs to check for wrong executed async processes
    async_jobs_mysql = []
    # mysql_nmap
    future = pool.submit(mysql_nmap, ip, port)
    async_jobs_mysql.append([future,"mysql_nmap", ip, port])
    return async_jobs_mysql

def mysql_nmap(ip,port):
    mysqllogger.debug('Started {bgreen}mysql nmap scan{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')
    command=f"nmap -sV -Pn --script=mysql-databases.nse,mysql-empty-password.nse,mysql-enum.nse,mysql-info.nse,mysql-variables.nse,mysql-vuln-cve2012-2122.nse -p {port} -o {port}_nmap_mysql {ip}"
    subprocess.run(command,shell=True, cwd=f"{ip}/scans", stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL, check=True)
    mysqllogger.debug('Finished {bgreen}mysql nmap scan{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')

def async_test_mysql(ip, port):
    mysqllogger.debug('Started {bgreen}async_test_mysql{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')
    time.sleep(3)
    mysqllogger.debug('Finished {bgreen}async_test_mysql{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')

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
    mysqlPool=pool.Pool(max_workers,"mysql_pool")
    async_jobs_mysql=mysql_scan_all(mysqlPool, ip, port)
  
    while(mysqlPool.get_workers_in_queue() > 0):
        #sleep to avoid last minute workers added queues after the time stop
        time.sleep(2)
        pass 
    scan_time = round(time.time() - starttime,3)
    
    for async_job in async_jobs_mysql:
        future = async_job[0]
        func = async_job[1]
        ip = async_job[2]
        port = async_job[3]
        if(async_job[0].exception()):
            mysqllogger.error(f"{func} did not execute correctly for {ip} port {port}: {future.exception()}")

    mysqllogger.info('This scan took {bmagenta}{scan_time}{rst} seconds')