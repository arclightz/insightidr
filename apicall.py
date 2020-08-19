#!/usr/bin/env python3

import requests
import ssl
import csv
import json

ssl._create_default_https_context = ssl._create_unverified_context

ioc_url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
threat_key = ""
api_key = ""
idr_url = "https://eu.api.insight.rapid7.com/idr/v1/customthreats/key/" + threat_key + "/indicators/replace?format=json"

headers = {
    'X-Api-Key': api_key,
    'Content-Type': 'application/json',
}

ioc_list = []
ioc_urls = {
    'domain_names':[''], 
    'hashes':[''], 
    'ips':[''],
    'urls':['']
    }

try:
    r = requests.get(ioc_url)
except r.status_code as e:
    if e.code == 404:
        print('404')
    else:
        print('jotain')
except r.status_code as e:
    print('Cant connect')
else:
    # 200
    print('Data retrieval complete!\n')
    body = r.text
   
lines = body.splitlines()
reader = csv.reader(lines, delimiter=',')

for row in reader:
    ioc_list.append(row)

# Remove the URLhause header information
del ioc_list[0:9]

for value in ioc_list:
    ioc_urls['urls'].append(value[2])

r = requests.post(idr_url, headers=headers, data=json.dumps(ioc_urls))