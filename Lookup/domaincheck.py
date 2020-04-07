#! /usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===============================================================================
      ___._    squ34k! | domainchecker.py
    .'  <@>'-.._   /   | 
   /  /.--.____")_/    | Checks a given domain or subdomain to see if it
  |   \   __.-'~       | resolves via http or https and grabs some information
  |  :  -'/            | about the domain registration using whois
 /:.  :.-/             |
@raptor_squeak         | Author: Dan Best (@raptor_squeak)
===============================================================================
Copyright 2020 Daniel Best

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies 
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
SOFTWARE.
"""
import argparse
import urllib3
import sys
import csv

importerr = False
try:
    import whois    #needs installed
except ImportError:
    print("Missing whois module")
    importerr = True

if importerr:
    print("Cannot continue: Missing imports")
    exit()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def getRedirectURL(url):
    """Gets the URL that the site is redirecting to
       url: URL that is kicking back a 301 or 301
    """
    try:
        http = urllib3.PoolManager(cert_reqs='CERT_NONE')
        req = http.request('GET', url, timeout=5)
        if len(req.retries.history):
            return req.retries.history[-1].redirect_location
        else:
            return url
    except:
        return 'redirect check error'

def getHttpStatus(proto,dubs,domain):
    """ Gets the status code for the domain sent in
        proto: http or https
        domain: domain to resolve
    """
    http = urllib3.PoolManager(cert_reqs='CERT_NONE')
    status = 'N/A'
    if dubs:
        url = "{}://www.{}".format(proto, domain)
    else:
        url = "{}://{}".format(proto, domain)
    finalurl = url
    try:
        req = http.request('GET', url, timeout=3, redirect=False)
        status = req.status
        if status in [301, 302, 303, 307, 308]:
            finalurl = getRedirectURL(url)
    except ConnectionError as connerr:
        status = "Connection-Error"
    except ConnectionRefusedError as connrefused:
        status = "Connection-Refused"
    except urllib3.exceptions.HTTPError as httperror:
        status = "HTTP-Error"

    return [status, finalurl]

def getDomainInfo(domain):
    """ Gets domain information using whois
        domain: domain to lookup
    """
    regi, org = '',''
    try:
        who = whois.whois(domain)
        if 'registrar' in who:
            regi = who['registrar']
        if 'org' in who:
            org = who['org']
        return [regi, org]
    except:
        return ['error', 'error']


        
def main(dfile,whois):
    """Run the domain check
       dfile: file to iterate over for domains
    """
    writer = csv.writer(sys.stdout)
    header = ["domain","http-status", "http-url-result", "https-status",
              "https-url-result", "www-http-status", "www-http-url-result",
              "www-https-status", "www-https-url-result"]
    if whois:
        header.extend(['registar','org'])
    writer.writerow(header)

    with open(dfile,'r') as reader:
        result = ""
        for line in reader.readlines():
            domain = line.strip()
            http = getHttpStatus("http", False, domain)
            https = getHttpStatus("https", False, domain)
            dubhttp = getHttpStatus("http", True, domain)
            dubhttps = getHttpStatus("https", True, domain)
            l = [domain]
            l.extend(http)
            l.extend(https)
            l.extend(dubhttp)
            l.extend(dubhttps)

            if whois:
                dominfo = getDomainInfo(domain)
                l.extend(dominfo)

            writer.writerow(l)
            sys.stdout.flush()

if __name__=='__main__':
    parser = argparse.ArgumentParser(description="Domain checker: Checks attributes of a domain or list of domains")
    parser.add_argument('-i','--input', help="List of domain names to check")
    parser.add_argument('-w','--whois', help='Add whois lookup to the query.  Be careful, whois has rate limits!',action='store_true',default=False)
    args = parser.parse_args()
    main(args.input, args.whois)
