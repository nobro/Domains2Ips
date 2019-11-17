# Domains to IPv4 and IPV6 IPs

Simple script that converts a list of domains/subdomains to DNS A Records (IPV4) and DNS AAAA Records (IPV6).

Does optional JSON an HTML output also.

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
Requires **json2html** to save output to a html file
```
pip3 install json2html
```
Requires **ipinfo** (https://github.com/ipinfo/python) to get additional IP information
```
pip3 install ipinfo
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
  - run with '--jsondomain' or '-jd' --> Outputs results as json sorted by domain
  - run with '--jsonip' or '-ji' --> Outputs results as json sorted by ip
  - run with '--jsonipinfo' or '-jii' --> Outputs results as json sorted by ip with additional information about the IP from ipinfo.io
  - run with '--version6' or '-v6' --> Outputs IPV6 ips too, by default only IPV4 ips are outputted
  - run with '--clipboard' or '-c' --> Will copy the resulting json to the clipboard for easy paste
  - run with '--web' or '-w' --> Will make a html file with the results from --jsonipinfo. -jii must be used!
  - run with '--help' or '-h' --> shows standard help message

### Run:
./d2i.py domainlist.txt # IPV4 only
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
The input file contained 9 lines and 2 domains/subdomains are unique. Difference: 7
==================================
```
./d2i.py domainlist.txt -v6 # IPV4 and IPV6
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
The input file contained 9 lines and 2 domains/subdomains are unique. Difference: 7
==================================
```
./d2i.py domainlist.txt -ji # IPV4 with JSON sorted by IP
```
...
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
...
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

./d2i.py domainlist.txt -ji -jd # IPV4 with JSON sorted by IP and Domain
```
...
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
./d2i.py -jii domainlist.txt
```
...
 ** Sorted IPs by domains and subdomains as JSON with additional information from ipinfo.io **

{
    "104.24.116.11": [
        {
            "city": "New York City",
            "country": "US",
            "org": "AS13335 Cloudflare, Inc.",
            "region": "New York"
        },
        [
            "yourname.xyz",
            "www.yourname.xyz"
        ]
    ],
    "104.24.117.11": [
        {
            "city": "New York City",
            "country": "US",
            "org": "AS13335 Cloudflare, Inc.",
            "region": "New York"
        },
        [
            "yourname.xyz",
            "www.yourname.xyz"
        ]
    ]
}
```
./d2i.py -jii w domainlist.txt

Outputs results in a html file in the curent_folder/results/
