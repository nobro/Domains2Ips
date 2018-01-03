#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Simple script that converts a list of domains/subdomains to DNS A Records (IPV4).

Requires pyperclip to copy the json result to the clipboard:
pip3 install pyperclip

The file must contain a list with only one domain/subdomain per line.
Example list:
Valid:
example.org
example.com
www.example.com

Invalid:
www.example.com/index.html

Usage:
  - run this module without arguments --> get help message
  - run with '--file' or '-f' --> Select the file to be parsed - Must be set!
  - run with '--json' or '-j' --> Output results as json also
  - run with '--clipboard' or '-c' --> will copy the resulting json to the clipboard for easy paste
  - run with '--help' or '-h' --> shows standard help message
"""

import pyperclip
import textwrap
import argparse
import socket
import json
import sys


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
    parser.add_argument('-f', '--file', help='select domain list', required=True)  # required param
    parser.add_argument('-j', '--json', help='output as json also', action='store_true') # optional param
    parser.add_argument('-c', '--clipboard', action='store_true',
                        help='copy json result to clipboard for easy paste')  # optional param
    args = parser.parse_args()

    domainips = {}

    if args.file:
        print('**Starting script**')
        print('Input file is -->', args.file)
        with open(args.file, "r") as f:
            content = f.readlines()
            # strip whitespace characters like `\n` at the end of each line just in case
            content = {x.strip() for x in content}
            for domain in content:
                try:
                    ips = socket.gethostbyname_ex(domain)[2]
                    print('** ' + domain + ' **' + '\t-->\t' + ', '.join(ips))
                    domainips[domain] = ips
                except Exception as e:
                    print('** ' + domain + ' **' + '\t-->\t' + str(e))

        if args.json:
            print("\n ** Domain with IPv4 ips as JSON ** \n")
            print(json.dumps(domainips, sort_keys=True, indent=4) + "\n")

        if args.clipboard:
            try:
                pyperclip.copy(json.dumps(domainips))
            except Exception as e:
                print(str(e))
                print('Probably need to install pyperclip')
                print('pip3 install pyperclip')
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
