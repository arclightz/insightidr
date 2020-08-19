#!/usr/bin/env python3

import urllib.request
import ssl

ssl._create_default_https_context = ssl._create_unverified_context

ioc_url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
threat_key = ""
headers = ""


print('Starting data retrieval!\n')

try:
    r = urllib.request.urlopen(ioc_url)
except urllib.request.HTTPError as e:
    if e.code == 404:
        print('404')
    else:
        print('jotain')
except urllib.request.HTTPError as e:
    print('Cant connect')
else:
    # 200
    print('Data retrieval complete!\n')
    body = r.read()

print('Done!')

from IPython import embed; embed()

