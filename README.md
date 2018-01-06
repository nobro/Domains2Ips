# Domains to IPv4 and IPV6 IPs

There are 3 simple scripts that convert a list of domains/subdomains to DNS A Records (IPV4) and to DNS AAAA Records (IPV6):

- **domains2ips.py** - converts domains/subdomains to IPV4 and IPV6 addresses (A and AAAA DNS Records)
- **domains2ipv4s.py** - converts domains/subdomains to IPV4 addresses (A DNS Records)
- **domains2ipv6s.py** - converts domains/subdomains to IPV6 addresses (AAAA DNS Records)

Uses socket to get IPs so it is subject to localy configured resolver.

### Install:
Requires **pyperclip** to copy the json result to the clipboard:
```
pip3 install pyperclip
```
Requires **tldextract** to validate domains/subdomains from list:
```
pip3 install tldextract
```
or install all requirements:
```
pip3 install -r requirements.txt
```

### Domain list:
The file must contain a list with only one domain/subdomain per line.

Valid example list:
```
yourname.xyz
 yourname.xyz
www.yourname.xyz
www.yourname.xyz/index.html
http://yourname.xyz
http://yourname.xyz/
https://yourname.xyz
https://yourname.xyz/index.html
someinvaliddomain12312313.com
```

### Usage:
  - run this module without arguments --> get help message
  - run with '--file' or '-f' --> Select the file to be parsed - Must be set!
  - run with '--jsondomain' or '-jd' --> Output results as json sorted by domain
  - run with '--jsonip' or '-ji' --> Output results as json sorted by ip
  - run with '--clipboard' or '-c' --> will copy the resulting json to the clipboard for easy paste
  - run with '--help' or '-h' --> shows standard help message

### Run:
./domains2ipv4s.py domainlist.txt
```
** Starting script **
Input file is --> domainlist.txt
** yourname.xyz ** -->	104.24.122.106, 104.24.123.106
** yourname.xyz ** -->	104.24.122.106, 104.24.123.106
** www.yourname.xyz ** -->	104.24.123.106, 104.24.122.106
** www.yourname.xyz ** -->	104.24.123.106, 104.24.122.106
** yourname.xyz ** -->	104.24.122.106, 104.24.123.106
** yourname.xyz ** -->	104.24.122.106, 104.24.123.106
** yourname.xyz ** -->	104.24.122.106, 104.24.123.106
** yourname.xyz ** -->	104.24.122.106, 104.24.123.106
** someinvaliddomain12312313.com ** -->	[Errno 8] nodename nor servname provided, or not known
```
./domains2ipv4s.py domainlist.txt -ji
```
** Starting script **
Input file is --> domainlist.txt
** yourname.xyz ** -->	104.24.122.106, 104.24.123.106
** yourname.xyz ** -->	104.24.122.106, 104.24.123.106
** www.yourname.xyz ** -->	104.24.123.106, 104.24.122.106
** www.yourname.xyz ** -->	104.24.123.106, 104.24.122.106
** yourname.xyz ** -->	104.24.122.106, 104.24.123.106
** yourname.xyz ** -->	104.24.122.106, 104.24.123.106
** yourname.xyz ** -->	104.24.122.106, 104.24.123.106
** yourname.xyz ** -->	104.24.122.106, 104.24.123.106
** someinvaliddomain12312313.com ** -->	[Errno 8] nodename nor servname provided, or not known

 ** Sorted IPv4 ips with domains as JSON **

{
    "104.24.122.106": [
        "yourname.xyz",
        "www.yourname.xyz"
    ],
    "104.24.123.106": [
        "yourname.xyz",
        "www.yourname.xyz"
    ]
}
```

./domains2ipv4s.py domainlist.txt -jd
```
** Starting script **
Input file is --> domainlist.txt
** yourname.xyz ** -->	104.24.122.106, 104.24.123.106
** yourname.xyz ** -->	104.24.122.106, 104.24.123.106
** www.yourname.xyz ** -->	104.24.123.106, 104.24.122.106
** www.yourname.xyz ** -->	104.24.123.106, 104.24.122.106
** yourname.xyz ** -->	104.24.122.106, 104.24.123.106
** yourname.xyz ** -->	104.24.122.106, 104.24.123.106
** yourname.xyz ** -->	104.24.122.106, 104.24.123.106
** yourname.xyz ** -->	104.24.122.106, 104.24.123.106
** someinvaliddomain12312313.com ** -->	[Errno 8] nodename nor servname provided, or not known

 ** Sorted Domains with IPv4 ips as JSON **

{
    "www.yourname.xyz": [
        "104.24.123.106",
        "104.24.122.106"
    ],
    "yourname.xyz": [
        "104.24.122.106",
        "104.24.123.106"
    ]
}
```

./domains2ipv4s.py domainlist.txt -ji -jd will output both json lists
```
** Starting script **
Input file is --> domainlist.txt
** yourname.xyz ** -->	104.24.122.106, 104.24.123.106
** yourname.xyz ** -->	104.24.122.106, 104.24.123.106
** www.yourname.xyz ** -->	104.24.123.106, 104.24.122.106
** www.yourname.xyz ** -->	104.24.123.106, 104.24.122.106
** yourname.xyz ** -->	104.24.122.106, 104.24.123.106
** yourname.xyz ** -->	104.24.122.106, 104.24.123.106
** yourname.xyz ** -->	104.24.122.106, 104.24.123.106
** yourname.xyz ** -->	104.24.122.106, 104.24.123.106
** someinvaliddomain12312313.com ** -->	[Errno 8] nodename nor servname provided, or not known

 ** Sorted IPv4 ips with domains as JSON **

{"sorted by ip":
{
    "104.24.122.106": [
        "www.yourname.xyz",
        "yourname.xyz"
    ],
    "104.24.123.106": [
        "www.yourname.xyz",
        "yourname.xyz"
    ]
},"sorted by domain":
{
    "www.yourname.xyz": [
        "104.24.123.106",
        "104.24.122.106"
    ],
    "yourname.xyz": [
        "104.24.122.106",
        "104.24.123.106"
    ]
}
}
```
