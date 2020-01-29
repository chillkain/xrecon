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
    http_scripts="ssl-heartbleed,http-adobe-coldfusion-apsa1301.nse,http-apache-negotiation.nse,http-apache-server-status.nse,http-aspnet-debug.nse,http-auth-finder.nse,http-auth.nse,http-avaya-ipoffice-users.nse,http-awstatstotals-exec.nse,http-axis2-dir-traversal.nse,http-backup-finder.nse,http-barracuda-dir-traversal.nse,http-bigip-cookie.nse,http-brute.nse,http-cakephp-version.nse,http-cisco-anyconnect.nse,http-coldfusion-subzero.nse,http-comments-displayer.nse,http-config-backup.nse,http-cookie-flags.nse,http-cors.nse,http-cross-domain-policy.nse,http-csrf.nse,http-date.nse,http-default-accounts.nse,http-devframework.nse,http-dlink-backdoor.nse,http-dombased-xss.nse,http-domino-enum-passwords.nse,http-drupal-enum-users.nse,http-drupal-enum.nse,http-enum.nse,http-errors.nse,http-exif-spider.nse,http-feed.nse,http-fileupload-exploiter.nse,http-form-brute.nse,http-form-fuzzer.nse,http-frontpage-login.nse,http-git.nse,http-gitweb-projects-enum.nse,http-headers.nse,http-huawei-hg5xx-vuln.nse,http-iis-short-name-brute.nse,http-iis-webdav-vuln.nse,http-internal-ip-disclosure.nse,http-joomla-brute.nse,http-jsonp-detection.nse,http-litespeed-sourcecode-download.nse,http-ls.nse,http-majordomo2-dir-traversal.nse,http-mcmp.nse,http-method-tamper.nse,http-methods.nse,http-mobileversion-checker.nse,http-ntlm-info.nse,http-open-redirect.nse,http-passwd.nse,http-php-version.nse,http-phpmyadmin-dir-traversal.nse,http-phpself-xss.nse,http-proxy-brute.nse,http-put.nse,http-qnap-nas-info.nse,http-rfi-spider.nse,http-robots.txt.nse,http-security-headers.nse,http-server-header.nse,http-shellshock.nse,http-sitemap-generator.nse,http-sql-injection.nse,http-stored-xss.nse,http-svn-enum.nse,http-svn-info.nse,http-title.nse,http-tplink-dir-traversal.nse,http-trace.nse,http-traceroute.nse,http-trane-info.nse,http-unsafe-output-escaping.nse,http-useragent-tester.nse,http-userdir-enum.nse,http-vhosts.nse,http-vlcstreamer-ls.nse,http-vmware-path-vuln.nse,http-vuln-cve2006-3392.nse,http-vuln-cve2009-3960.nse,http-vuln-cve2010-0738.nse,http-vuln-cve2010-2861.nse,http-vuln-cve2011-3368.nse,http-vuln-cve2012-1823.nse,http-vuln-cve2013-0156.nse,http-vuln-cve2013-6786.nse,http-vuln-cve2013-7091.nse,http-vuln-cve2014-2126.nse,http-vuln-cve2014-2127.nse,http-vuln-cve2014-2128.nse,http-vuln-cve2014-3704.nse,http-vuln-cve2014-8877.nse,http-vuln-cve2015-1427.nse,http-vuln-cve2015-1635.nse,http-vuln-cve2017-1001000.nse,http-vuln-cve2017-5638.nse,http-vuln-cve2017-5689.nse,http-vuln-cve2017-8917.nse,http-vuln-misfortune-cookie.nse,http-vuln-wnr1000-creds.nse,http-waf-detect.nse,http-waf-fingerprint.nse,http-webdav-scan.nse,http-wordpress-brute.nse,http-wordpress-enum.nse,http-wordpress-users.nse,http-xssed.nse,membase-http-info.nse"
    command=f"nmap -sV -Pn --script={http_scripts} -p {port} -o {port}_nmap_http {ip}"
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
        command=f"davtest -url https://{ip} | tee {port}_davtest.log"
        subprocess.run(command,shell=True, cwd=f"{ip}/scans", stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL, check=True)
    elif(port== 80):
        command=f"davtest -url http://{ip} | tee {port}_davtest.log"
        subprocess.run(command,shell=True, cwd=f"{ip}/scans", stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL, check=True)
    else:
        httplogger.warn('http on different port; execute {bgreen}davtest scan{rst} manually by redirecting to localhost')
    
    httplogger.debug('Finished {bgreen}davtest scan{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')

def http_dir_brute(ip,port):
    httplogger.debug('Started {bgreen}directory brute force{rst} for {byellow}{ip}{rst} port {byellow}{port}{rst}')
    # command=f"gobuster dir -u http://{ip}:{port} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -f -k -t 100 -x php,txt,cgi,asp,pl,aspx -s '200,204,301,302,307,500' | tee {port}_gobuster.log"
    command=f"gobuster dir -u http://{ip}:{port} -w seclist_webbrute.txt -e -f -k -t 100 -s '200,204,301,302,307,500' | tee {port}_gobuster.log"
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