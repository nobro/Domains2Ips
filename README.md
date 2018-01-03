# Domains to IPv4 IPs

Simple script that converts a list of domains/subdomains to DNS A Records (IPV4).
Uses socket to get IPs so it is subject to localy configured resolver.

Requires pyperclip to copy the json result to the clipboard:
Install pyperclip 
```
pip3 install -r requirements.txt
```

The file must contain a list with only one domain/subdomain per line.
Example list:

Valid:
...
example.org
example.com
www.example.com
...

Invalid:
www.example.com/index.html

Only domain validity check is striping whitespace characters.

Usage:
  - run this module without arguments --> get help message
  - run with '--file' or '-f' --> Select the file to be parsed - Must be set!
  - run with '--json' or '-j' --> Output results as json also
  - run with '--clipboard' or '-c' --> will copy the resulting json to the clipboard for easy paste
  - run with '--help' or '-h' --> shows standard help message
