#!/usr/bin/env python3

import pool
import logger
import sys
import time
import argparse
import subprocess
import os
from colorama import Fore, Style

httplogger=logger.Logger(3)

# starts all http scans for this specific port
# returns a list that will be used to check if everything went fine    
def http_scan_all(pool,ip,port):
    httplogger.info('Started {bgreen}http service scans{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')
    # list that will be appended to async_jobs to check for wrong executed async processes
    async_jobs_http = []
    # # async_test
    # future = pool.submit(async_test_http, ip, port)
    # async_jobs_http.append([future,"async_test_http", ip, port])
    # http_nmap
    future = pool.submit(http_nmap, ip, port)
    async_jobs_http.append([future,"http_nmap", ip, port])
    # http_robots
    future = pool.submit(http_robots, ip, port)
    async_jobs_http.append([future,"http_robots", ip, port])
    # http_nikto
    future = pool.submit(http_nikto, ip, port)
    async_jobs_http.append([future,"http_nikto", ip, port])    
    # http_davtest
    future = pool.submit(http_davtest, ip, port)
    async_jobs_http.append([future,"http_davtest", ip, port])  
    # dir brute
    future = pool.submit(http_dir_brute, ip, port)
    async_jobs_http.append([future,"http_dir_brute", ip, port])
    return async_jobs_http

def http_nmap(ip,port):
    httplogger.debug('Started {bgreen}http nmap scan{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')
    command=f"nmap -sV -Pn --script='banner,(http* or ssl*) and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)' -p {port} -o {port}_nmap_http {ip}"
    subprocess.run(command,shell=True, cwd=f"{ip}/scans", stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL, check=True)
    httplogger.debug('Finished {bgreen}http nmap scan{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')

def http_robots(ip,port):
    httplogger.debug('Started {bgreen}fetching robots.txt{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')
    if (port == "443"):
        command=f"wget https://{ip}:{port}/robots.txt --no-check-certificate --output-document='{port}_robots.txt'"
    else:
        command=f"wget http://{ip}:{port}/robots.txt --no-check-certificate --output-document='{port}_robots.txt'" 
    subprocess.run(command,shell=True, cwd=f"{ip}/scans", stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL, check=True)
    httplogger.debug('Finished {bgreen}fetching robots.txt{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')

def http_nikto(ip,port):
    httplogger.debug('Started {bgreen}nikto scan{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')
    command=f"nikto -host {ip}:{port}| tee {port}_nikto.log"
    subprocess.run(command,shell=True, cwd=f"{ip}/scans", stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL, check=True)
    httplogger.debug('Finished {bgreen}nikto scan{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')

def http_davtest(ip,port):
    httplogger.debug('Started {bgreen}davtest scan{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')
    if (port == 443):
        command=f"davtest -url https://{ip}:{port} | tee {port}_davtest.log"
    else:
        command=f"davtest -url http://{ip}:{port} | tee {port}_davtest.log"
    subprocess.run(command,shell=True, cwd=f"{ip}/scans", stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL, check=True)
    httplogger.debug('Finished {bgreen}davtest scan{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')

def http_dir_brute(ip,port):
    httplogger.debug('Started {bgreen}directory brute force{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')
    command=f"gobuster dir -u http://{ip}:{port} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k -t 100 -x php,txt,cgi,sh,pl,py -s '200,204,301,302,307,403,500' | tee {port}_gobuster.log"
    subprocess.run(command,shell=True, cwd=f"{ip}/scans", stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL, check=True)
    httplogger.debug('Finished {bgreen}directory brute force{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')

def async_test_http(ip, port):
    httplogger.debug('Started {bgreen}async_test_http{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')
    time.sleep(3)
    httplogger.debug('Finished {bgreen}async_test_http{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')

def getOptions(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description="manuals are for dummies but these arguments could be useful")
    parser.add_argument("-i", "--inputIP", help="target ip ")
    parser.add_argument("-p", "--inputPort", help="port to scan on")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Maximum amount of concurrent processes")
    options = parser.parse_args(args)
    return options
    


if __name__ == "__main__":
    starttime = time.time()
    print("started")
    # ip="193.173.10.234"

    # get command arguments
    options = getOptions(sys.argv[1:])
    ip=options.inputIP
    port=options.inputPort
    max_workers=options.threads

    # initiate the classes
    httpPool=pool.Pool(max_workers,"http_pool")
    async_jobs_http=http_scan_all(httpPool, ip, port)
  
    while(httpPool.get_workers_in_queue() > 0):
        #sleep to avoid last minute workers added queues after the time stop
        time.sleep(2)
        pass 
    scan_time = round(time.time() - starttime,3)
    
    for async_job in async_jobs_http:
        future = async_job[0]
        func = async_job[1]
        ip = async_job[2]
        port = async_job[3]
        if(async_job[0].exception()):
            httplogger.error(f"{func} did not execute correctly for {ip} port {port}: {future.exception()}")

    httplogger.info('This scan took {bmagenta}{scan_time}{rst} seconds')