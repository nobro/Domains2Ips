#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Simple script that converts a list of domains/subdomains to DNS A Records (IPV4) and DNS AAAA Records (IPV6).
Does optional JSON an HTML output also.

Requires pyperclip to copy the json result to the clipboard:
pip3 install pyperclip
Requires validators to validate domain/subdomains:
pip3 install validators
Requires tldextract to extract domains/subdomains:
pip3 install tldextract
Requires pandas to save output to a html file
pip3 install pandas
Required ipinfo for additional information on IP addreses
pip3 install ipinfo

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
  - run with '--file' or '-f' --> Select the file to be parsed - Must be set!
  - run with '--jsondomain' or '-jd' --> Outputs results as json sorted by domain
  - run with '--jsonip' or '-ji' --> Outputs results as json sorted by ip
  - run with '--jsonipinfo' or '-jii' --> Outputs results as json sorted by ip with additional information about the IP from ipinfo.io
  - run with '--version6' or '-v6' --> Outputs IPV6 ips too, by default only IPV4 ips are outputted
  - run with '--clipboard' or '-c' --> Will copy the resulting json to the clipboard for easy paste
  - run with '--web' or '-w' --> Will make a html file with the results from --jsonipinfo. -jii must be used!
  - run with '--help' or '-h' --> shows standard help message

Run:
./d2i.py domainlist.txt -ji -jd -v6 -c
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
import pandas as pd
import os
from datetime import datetime
import ipinfo


def sort_by_ip(unsorted):
    """Sorts output by IP instead of Domain/Subdomain"""
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


def ipinfo_get(ip_address):
    """Uses https://github.com/ipinfo/python to get additional information about IP addresess"""
    # get an API token from https://ipinfo.io/
    access_token=""
    handler = ipinfo.getHandler(access_token)
    try:
        details = handler.getDetails(ip_address)
        dictionary_ipinfo_response = OrderedDict(details.all)
        additional_ipinfo = [(key, dictionary_ipinfo_response[key]) for key in dictionary_ipinfo_response.keys()
                             if key in {'hostname', 'city', 'region', 'country', 'org'}]
    except Exception as e:
        additional_ipinfo = [('Error', str(e))]

    return OrderedDict(additional_ipinfo)



def main():
    parser = argparse.ArgumentParser(
        prog='d2i.py',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        # ANSI Shadow
        description=textwrap.dedent('''\

    ██████╗ ██████╗ ██╗
    ██╔══██╗╚════██╗██║
    ██║  ██║ █████╔╝██║
    ██║  ██║██╔═══╝ ██║
    ██████╔╝███████╗██║
    ╚═════╝ ╚══════╝╚═╝
    '''),
        epilog='''Simple script that converts a list of domains/subdomains to IPV4 and IPV6 ips''')
    parser.add_argument('file', nargs='?', help='select domain list')  # required param
    parser.add_argument('-jd', '--jsondomain', help='output as json sorted by domain', action='store_true')
    parser.add_argument('-ji', '--jsonip', help='output as json sorted by ip', action='store_true')
    parser.add_argument('-jii', '--jsonipinfo', help='output as json sorted by ip with additional information \
    	                                              about the IP from ipinfo.io', action='store_true')
    parser.add_argument('-v6', '--version6', help='outputs IPV6 ips too', action='store_true')
    parser.add_argument('-c', '--clipboard', action='store_true',
                        help='copy json result to clipboard for easy paste')  # optional param
    parser.add_argument('-w', '--web', action='store_true',
                        help='make a html file with the results. -jii must be used!')
    args = parser.parse_args()

    sorted_by_domain = {}
    # open file
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
                        # get ipv4 ips for domain / subdomain
                        ipv4s = socket.gethostbyname_ex(domain)[2]
                        print('* ' + domain + ' *' + ' -->\t' + ', '.join(ipv4s))
                        sorted_by_domain[domain] = ipv4s
                    except Exception as e:
                        print('\u001b[33m' + 'IPV4: ' + '\u001b[0m' + invalidated_domain + '\033[31m' + ' Error: ' +
                              '\u001b[0m' + str(e))
                    # get ipv6 ips for domain / subdomain
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
                            print('\u001b[33m' + 'IPV6: ' + '\u001b[0m' + invalidated_domain + '\033[31m' +
                                  ' Error: ' + '\u001b[0m' + str(e))
        # statistics with how many domains / subdomains are valid
        print('===========># Stats: #<===========')
        print('The input file contained ' + str(len(content)) + ' lines and ' + '\u001b[32m' +
              str(len(sorted_by_domain)) + '\u001b[0m' + ' domains/subdomains are unique. Difference: ' + '\033[31m' +
              str(int(len(content)) - int(len(sorted_by_domain))) + '\u001b[0m')
        print('==================================')
        # print json
        if args.jsondomain and not args.jsonip and not args.jsonipinfo:
            print("\n ** Sorted domains and subdomains with corresponding IPs as JSON ** \n")
            print(json.dumps(sorted_by_domain, sort_keys=True, indent=4))
        if args.jsonip and not args.jsondomain and not args.jsonipinfo:
            print("\n ** Sorted Ips with corresponding domains and subdomains as JSON ** \n")
            print(json.dumps(sort_by_ip(sorted_by_domain), sort_keys=True, indent=4))
        if args.jsonipinfo and not args.jsondomain and not args.jsonip:
            print("\n ** Sorted IPs by domains and subdomains as JSON with additional information from ipinfo.io ** \n")
            # the domain and subdomains are loaded into an ordered dictionary
            domain_info = OrderedDict(sort_by_ip(sorted_by_domain))
            # get ipinfo.io information for IPs and join with domain / subdomain
            ips_domains_info = OrderedDict()
            for domain, info in domain_info.items():
                ip_info = ipinfo_get(domain)
                ips_domains_info[domain] = {
                    'IP Information': ip_info,
                    'FQDN': info
                }
            # Print the JSON with sorted keys and formatted output
            print(json.dumps(ips_domains_info, sort_keys=True, indent=4))    
        if args.jsonip and args.jsondomain:
            print("\n ** Sorted IPs by domains and domains by IPs as JSON ** \n")
            print('{"sorted by ip":' + '\n' + json.dumps(sort_by_ip(sorted_by_domain), sort_keys=True, indent=4)
                  + ',"sorted by domain":' + '\n' + json.dumps(sorted_by_domain, sort_keys=True, indent=4) + '\n' + '}')
        # copy to clipboard if -c is used
        if args.clipboard:
            if not args.jsondomain and not args.jsonip and not args.jsonipinfo:
                try:
                    print('==================================')
                    print('WARNING:')
                    print('-c only works if -ji, -jii or -jd is set!')
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
            elif args.jsonipinfo and not args.jsonip and not args.jsondomain:
                try:
                    pyperclip.copy(json.dumps(ips_domains_info))
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
        # display result in a HTML page if -w is used
        if args.web and args.jsonipinfo:
            json_for_web = ips_domains_info
            #make a dataframe from Json, split the last column, concat it back and remove the second column
            df = pd.DataFrame(json_for_web.items())
            df.columns = ['IP', 'Info']

            splitInfo = pd.DataFrame(df['Info'].to_list(), columns = ['IP Information', 'FQDN'])

            df = pd.concat([df, splitInfo], axis = 1)

            df = df.drop('Info', axis = 1)
            
            #make a dataframe from Json, split the Ip Info column, concat it back and remove the second column
            splitIPInfo = pd.DataFrame(df['IP Information'].to_list(), columns = ['hostname', 'org', 'city', 'region', 'country'])
            
            df = pd.concat([df, splitIPInfo], axis = 1)

            df = df.drop('IP Information', axis = 1)

            html_table = df.to_html(index=False, na_rep='N/A', classes=["table table-hover table-striped"], escape=False)

            html_file= (
            '<!doctype html>\n'\
            '<html lang="en">'\
            '<head>'\
            '<!-- Required meta tags -->'\
            '<meta charset="utf-8">'\
            '<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">'\
            '<!-- Bootstrap CSS -->\n'\
            '<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css" '\
            'integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T" crossorigin="anonymous">\n'\
            '<title>Domains2Ips</title>\n'\
            '<style type="text/css">'\
            'ul {list-style: none;}'
            '</style>'
            '</head>'\
            '<body style="list-style-type: none;">' \
            '%s'
            '<!-- Optional JavaScript -->'\
            '<!-- jQuery first, then Popper.js, then Bootstrap JS -->'\
            '<script src="https://code.jquery.com/jquery-3.3.1.slim.min.js" '\
            'integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" crossorigin="anonymous"></script>'\
            '<script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js" '\
            'integrity="sha384-UO2eT0CpHqdSJQ6hJty5KVphtPhzWj9WO1clHTMGa3JDZwrnQq4sF86dIHNDz0W1" crossorigin="anonymous"></script>'\
            '<script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js" '\
            'integrity="sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM" crossorigin="anonymous"></script>'\
            '</body>'\
            '</html>') % html_table

            # check if 'generated_results' folder exists. if not create it
            if not os.path.isdir(os.getcwd()+'/results'):
                os.makedirs(os.getcwd()+'/results')

            # create name for the save file
            html_file_name = os.getcwd()+'/results/'+datetime.now().strftime("%d-%m-%Y_%H-%M-%S")+'.html'

            # write file
            with open(html_file_name, 'w') as my_file:
                my_file.write(html_file)
            print('The HTML file with the results was written at ' +html_file_name)
        else:
            print('-w works only if -jii is set')

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
