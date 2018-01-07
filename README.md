# Domains to IPv4 and IPV6 IPs

A simple script that convert a list of domains/subdomains to DNS A Records (IPV4) and optionally to DNS AAAA Records (IPV6):

Uses socket to get IPs so it is subject to localy configured resolver.

### Install:
Requires **pyperclip** to copy the json result to the clipboard:
```
pip3 install pyperclip
```
Requires **tldextract** to extract domains/subdomains from list:
```
pip3 install tldextract
```
Requires **validators** to validate domains/subdomains from list:
```
pip3 install validators
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
  - run with file name --> Select the file to be parsed - Must be set!
  - run with '--jsondomain' or '-jd' --> Output results as json sorted by domain
  - run with '--jsonip' or '-ji' --> Output results as json sorted by ip
  - run with '--version6', '-v6', '-v' --> Outputs IPV6 ips too
  - run with '--clipboard' or '-c' --> will copy the resulting json to the clipboard for easy paste
  - run with '--help' or '-h' --> shows standard help message

### Run:
./domains2ips.py domainlist.txt # IPV4 only
```
======># Starting script #<=======
Input file is --> domainlist.txt
==================================
* yourname.xyz * -->	104.24.123.106, 104.24.122.106
* yourname.xyz * -->	104.24.123.106, 104.24.122.106
* www.yourname.xyz * -->	104.24.122.106, 104.24.123.106
* yourname.xyz * -->	104.24.123.106, 104.24.122.106
* yourname.xyz * -->	104.24.123.106, 104.24.122.106
* yourname.xyz * -->	104.24.123.106, 104.24.122.106
* yourname.xyz * -->	104.24.123.106, 104.24.122.106
IPV4: someinvaliddomain12312313.com Error: [Errno 8] nodename nor servname provided, or not known
===========># Stats: #<===========
The input file contained 9 lines and 2 domains are unique and valid. Difference: 7
==================================
```
./domains2ips domainlist.txt -v6 # IPV4 and IPV6
```
======># Starting script #<=======
Input file is --> domainlist.txt
==================================
* yourname.xyz * -->	104.24.123.106, 104.24.122.106
* yourname.xyz * -->	2400:cb00:2048:1::6818:7a6a
* yourname.xyz * -->	2400:cb00:2048:1::6818:7b6a
* yourname.xyz * -->	104.24.123.106, 104.24.122.106
* yourname.xyz * -->	2400:cb00:2048:1::6818:7a6a
* yourname.xyz * -->	2400:cb00:2048:1::6818:7b6a
* www.yourname.xyz * -->	104.24.122.106, 104.24.123.106
* www.yourname.xyz * -->	2400:cb00:2048:1::6818:7b6a
* www.yourname.xyz * -->	2400:cb00:2048:1::6818:7a6a
* yourname.xyz * -->	104.24.123.106, 104.24.122.106
* yourname.xyz * -->	2400:cb00:2048:1::6818:7a6a
* yourname.xyz * -->	2400:cb00:2048:1::6818:7b6a
* yourname.xyz * -->	104.24.123.106, 104.24.122.106
* yourname.xyz * -->	2400:cb00:2048:1::6818:7a6a
* yourname.xyz * -->	2400:cb00:2048:1::6818:7b6a
* yourname.xyz * -->	104.24.123.106, 104.24.122.106
* yourname.xyz * -->	2400:cb00:2048:1::6818:7a6a
* yourname.xyz * -->	2400:cb00:2048:1::6818:7b6a
* yourname.xyz * -->	104.24.123.106, 104.24.122.106
* yourname.xyz * -->	2400:cb00:2048:1::6818:7a6a
* yourname.xyz * -->	2400:cb00:2048:1::6818:7b6a
IPV4: someinvaliddomain12312313.com Error: [Errno 8] nodename nor servname provided, or not known
IPV6: someinvaliddomain12312313.com Error: [Errno 8] nodename nor servname provided, or not known
===========># Stats: #<===========
The input file contained 9 lines and 2 domains are unique and valid. Difference: 7
==================================
```
./domains2ips.py domainlist.txt -ji # IPV4 with JSON sorted by IP
```
======># Starting script #<=======
Input file is --> domainlist.txt
==================================
* yourname.xyz * -->	104.24.123.106, 104.24.122.106
* yourname.xyz * -->	104.24.123.106, 104.24.122.106
* www.yourname.xyz * -->	104.24.122.106, 104.24.123.106
* yourname.xyz * -->	104.24.123.106, 104.24.122.106
* yourname.xyz * -->	104.24.123.106, 104.24.122.106
* yourname.xyz * -->	104.24.123.106, 104.24.122.106
* yourname.xyz * -->	104.24.123.106, 104.24.122.106
IPV4: someinvaliddomain12312313.com Error: [Errno 8] nodename nor servname provided, or not known
===========># Stats: #<===========
The input file contained 9 lines and 2 domains are unique and valid. Difference: 7
==================================

 ** Sorted IPv4 ips by domains as JSON **

{
    "104.24.122.106": [
        "www.yourname.xyz",
        "yourname.xyz"
    ],
    "104.24.123.106": [
        "www.yourname.xyz",
        "yourname.xyz"
    ]
}
```

./domains2ips.py domainlist.txt -jd # IPV4 with JSON sorted by Domain
```
======># Starting script #<=======
Input file is --> domainlist.txt
==================================
* yourname.xyz * -->	104.24.123.106, 104.24.122.106
* yourname.xyz * -->	104.24.123.106, 104.24.122.106
* www.yourname.xyz * -->	104.24.122.106, 104.24.123.106
* yourname.xyz * -->	104.24.123.106, 104.24.122.106
* yourname.xyz * -->	104.24.123.106, 104.24.122.106
* yourname.xyz * -->	104.24.123.106, 104.24.122.106
* yourname.xyz * -->	104.24.123.106, 104.24.122.106
IPV4: someinvaliddomain12312313.com Error: [Errno 8] nodename nor servname provided, or not known
===========># Stats: #<===========
The input file contained 9 lines and 2 domains are unique and valid. Difference: 7
==================================

 ** Sorted Domains by IPv4 ips as JSON **

{
    "www.yourname.xyz": [
        "104.24.122.106",
        "104.24.123.106"
    ],
    "yourname.xyz": [
        "104.24.123.106",
        "104.24.122.106"
    ]
}
```

./domains2ips.py domainlist.txt -ji -jd # IPV4 with JSON sorted by IP and Domain
```
======># Starting script #<=======
Input file is --> domainlist.txt
==================================
* yourname.xyz * -->	104.24.123.106, 104.24.122.106
* yourname.xyz * -->	104.24.123.106, 104.24.122.106
* www.yourname.xyz * -->	104.24.122.106, 104.24.123.106
* yourname.xyz * -->	104.24.123.106, 104.24.122.106
* yourname.xyz * -->	104.24.123.106, 104.24.122.106
* yourname.xyz * -->	104.24.123.106, 104.24.122.106
* yourname.xyz * -->	104.24.123.106, 104.24.122.106
IPV4: someinvaliddomain12312313.com Error: [Errno 8] nodename nor servname provided, or not known
===========># Stats: #<===========
The input file contained 9 lines and 2 domains are unique and valid. Difference: 7
==================================

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
        "104.24.122.106",
        "104.24.123.106"
    ],
    "yourname.xyz": [
        "104.24.123.106",
        "104.24.122.106"
    ]
}
}
```
