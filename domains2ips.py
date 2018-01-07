#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Simple script that converts a list of domains/subdomains to DNS A Records (IPV4) and DNS AAAA Records (IPV6).
Does optional JSON output also.

Requires pyperclip to copy the json result to the clipboard:
pip3 install pyperclip
Requires validators to validate domain/subdomains:
pip3 install validators
Requires tldextract to extract domains/subdomains:
pip3 install tldextract

The file must contain a list with only one domain/subdomain per line.
Example list:
Valid:
yourname.xyz
 yourname.xyz
www.yourname.xyz
www.yourname.xyz/index.html
http://yourname.xyz
http://yourname.xyz/
https://yourname.xyz
https://yourname.xyz/index.html
someinvaliddomain12312313.com

Usage:
  - run this module without arguments --> get help message
  - run with 'file name' --> Select the file to be parsed - Must be set!
  - run with '--jsondomain' or '-jd' --> Outputs results as json sorted by domain
  - run with '--jsonip' or '-ji' --> Outputs results as json sorted by ip
  - run with '--version6' or '-v6' or '-v' --> Outputs IPV6 ips too, by default only IPV4 ips are outputted
  - run with '--clipboard' or '-c' --> will copy the resulting json to the clipboard for easy paste
  - run with '--help' or '-h' --> shows standard help message

Run:
./domains2ips.py domainlist.txt -ji -jd -v6 -c
"""

import validators
import tldextract
from pathlib import Path
from collections import OrderedDict
import pyperclip
import textwrap
import argparse
import socket
import json
import sys


def sort_by_ip(unsorted):
    """Sorts output by IP instead of Domain/Subdomain name"""
    by_ip = {}

    for k, v in unsorted.items():
        for ip in v:
            if ip in by_ip and k not in by_ip[ip]:
                by_ip[ip].append(k)
            else:
                by_ip[ip] = [k]

    return OrderedDict(sorted(by_ip.items()))


def non_unique_domain(invalidated_domain):
    """Uses validators to validate domain/subdomain or URL and tldextract to extract domain/subdomain"""
    # strip whitespaces from beginning or end of string
    invalidated_domain = invalidated_domain.strip()
    # valid domain / subdomain
    if validators.domain(invalidated_domain):
        not_unique_domain = invalidated_domain
        return not_unique_domain
    # valid url
    elif validators.url(invalidated_domain, public=True):
        temp_domain = tldextract.extract(invalidated_domain)
        if temp_domain.subdomain:
            not_unique_domain = '.'.join(temp_domain)
        else:
            not_unique_domain = temp_domain.domain + '.' + temp_domain.suffix
        # second validators.domain() check
        if validators.domain(not_unique_domain):
            return not_unique_domain
        else:
            return False
    else:
        return False


def main():
    parser = argparse.ArgumentParser(
        prog='domains2ips.py',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent('''\

      dP                              oo                   d8888b. oo                   
      88                                                       `88                      
.d888b88 .d8888b. 88d8b.d8b. .d8888b. dP 88d888b. .d8888b. .aaadP' dP 88d888b. .d8888b. 
88'  `88 88'  `88 88'`88'`88 88'  `88 88 88'  `88 Y8ooooo. 88'     88 88'  `88 Y8ooooo. 
88.  .88 88.  .88 88  88  88 88.  .88 88 88    88       88 88.     88 88.  .88       88 
`88888P8 `88888P' dP  dP  dP `88888P8 dP dP    dP `88888P' Y88888P dP 88Y888P' `88888P' 
                                                                      88                
                                                                      dP                

                    '''),
        epilog='''Simple script to convert a list of domains to DNS A records (IPv4)''')
    parser.add_argument('file', nargs='?', help='select domain list')  # required param
    parser.add_argument('-jd', '--jsondomain', help='output as json also - sort by domain', action='store_true')
    parser.add_argument('-ji', '--jsonip', help='output as json also - sort by ip', action='store_true')
    parser.add_argument('-v6', '--version6', help='outputs IPV6 ips too', action='store_true')
    parser.add_argument('-c', '--clipboard', action='store_true',
                        help='copy json result to clipboard for easy paste')  # optional param
    args = parser.parse_args()

    sorted_by_domain = {}

    if args.file and Path(args.file).is_file():
        print('======># Starting script #<=======')
        print('Input file is -->', args.file)
        print('==================================')
        with open(args.file, "r") as f:
            content = f.readlines()
            for invalidated_domain in content:
                # extract domain / subdomain
                domain = non_unique_domain(invalidated_domain)
                if domain:
                    try:
                        # get ips ips for domains
                        ipv4s = socket.gethostbyname_ex(domain)[2]
                        print('* ' + domain + ' *' + ' -->\t' + ', '.join(ipv4s))
                        sorted_by_domain[domain] = ipv4s
                    except Exception as e:
                        print('IPV4: ' + invalidated_domain + ' Error: ' + str(e))
                    if args.version6:
                        try:
                            ipv6s = socket.getaddrinfo(domain, None, socket.AF_INET6, socket.SOCK_DGRAM,
                                                       socket.IPPROTO_IP, socket.AI_CANONNAME)
                            for ipv6 in ipv6s:
                                print('* ' + domain + ' *' + ' -->\t' + str(ipv6[4][0]))
                                if domain in sorted_by_domain and ipv6[4][0] not in sorted_by_domain[domain]:
                                    sorted_by_domain[domain].append(ipv6[4][0])
                                else:
                                    sorted_by_domain[domain] = [ipv6[4][0]]
                        except Exception as e:
                            print('IPV6: ' + invalidated_domain + ' Error: ' + str(e))

        print('===========># Stats: #<===========')
        print('The input file contained ' + str(len(content)) + ' lines and ' + str(len(sorted_by_domain)) +
              ' domains are unique and valid. Difference: ' + str(int(len(content)) - int(len(sorted_by_domain))))
        print('==================================')

        if args.jsondomain and not args.jsonip:
            print("\n ** Sorted Domains by IPv4 ips as JSON ** \n")
            print(json.dumps(sorted_by_domain, sort_keys=True, indent=4))

        if args.jsonip and not args.jsondomain:
            print("\n ** Sorted IPv4 ips by domains as JSON ** \n")
            print(json.dumps(sort_by_ip(sorted_by_domain), sort_keys=True, indent=4))

        if args.jsonip and args.jsondomain:
            print("\n ** Sorted IPv4 ips with domains as JSON ** \n")
            print('{"sorted by ip":' + '\n' + json.dumps(sort_by_ip(sorted_by_domain), sort_keys=True, indent=4)
                  + ',"sorted by domain":' + '\n' + json.dumps(sorted_by_domain, sort_keys=True, indent=4) + '\n' + '}')

        if args.clipboard:
            if not args.jsondomain and not args.jsonip:
                try:
                    print('==================================')
                    print('WARNING:')
                    print('-c only works if -ji or -jd is set!')
                except Exception as e:
                    print(str(e))
                    print('Probably need to install pyperclip')
                    print('pip3 install pyperclip')
            elif args.jsonip and not args.jsondomain:
                try:
                    pyperclip.copy(json.dumps(sort_by_ip(sorted_by_domain)))
                except Exception as e:
                    print(str(e))
                    print('Probably need to install pyperclip')
                    print('pip3 install pyperclip')
            elif args.jsondomain and not args.jsonip:
                try:
                    pyperclip.copy(json.dumps(sorted_by_domain))
                except Exception as e:
                    print(str(e))
                    print('Probably need to install pyperclip')
                    print('pip3 install pyperclip')
            elif args.jsondomain and args.jsonip:
                try:
                    pyperclip.copy('{"sorted by ip":' + '\n' + json.dumps(sort_by_ip(sorted_by_domain))
                                   + ',"sorted by domain":' + '\n' + json.dumps(sorted_by_domain) + '\n' + '}')
                except Exception as e:
                    print(str(e))
                    print('Probably need to install pyperclip')
                    print('pip3 install pyperclip')
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
