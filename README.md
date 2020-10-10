# Detector

![version 1.0](https://img.shields.io/badge/version-1.0-green.svg)
python script to detect and search for IP, domain, URLs, Hashes using VirusTotal API


# Usage:

  - detect if an IP_Address is malicious or not
  - detect if a domain is malicious or not
  - detect if a URL is a malicious or not
 
# Eamples:
```
$ virusDetector.py
    please enter your choice 
    [1] ip_addresses  [2] domain   [3] hashes    [4] URLs
$ 1
    please enter your search query: 50.27.197.202
    
    total detection: 75  clean_detection: 75   malicious_deteciton: 0
    clean
 ```
  ```
 $ virusDetector.py
    please enter your choice 
    [1] ip_addresses  [2] domain   [3] hashes    [4] URLs
$ 2
    please enter your search query: google.com
    
    total detection: 93  clean_detection: 86   malicious_deteciton: 0
    clean
 ```
