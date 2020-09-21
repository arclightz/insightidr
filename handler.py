import sys
import requests
from requests import exceptions as e
import ssl
import csv
import json
import logging
import os
from datetime import date

FORMAT = "%(levelname)s:%(asctime)s - %(message)s"
logger = logging.getLogger()

if logger.handlers:
    for handler in logger.handlers:
        logger.removeHandler(handler)
logging.basicConfig(format=FORMAT, level=logging.INFO)
logging.getLogger(__name__).setLevel(logging.WARN)

ssl._create_default_https_context = ssl._create_unverified_context

def update_iocs(event, context):

    logger.info("START")
    """
    API and threat keys on local variables.
    """
    urlhause_key = os.environ["URLHAUSE_KEY"]
    api_key = os.environ["API_KEY"]

    ioc_url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    idr_url = "https://eu.api.insight.rapid7.com/idr/v1/customthreats/key/" + urlhause_key + "/indicators/replace?format=json"
    
    headers = {
    'X-Api-Key': api_key,
    'Content-Type': 'application/json'
    }

    ioc_list = []
    ioc_urls = {
        'domain_names':[''], 
        'hashes':[''], 
        'ips':[''],
        'urls':['']
        }
    
    try:
        logger.info("Retrieving from URLhause database")
        r = requests.get(ioc_url)
        body = r.text
    except (
        e.HTTPError,
        e.ConnectionError,
        e.TooManyRedirects,
        e.RequestException,
    )as error:
        logger.error("Connection to %s failed %s" % ioc_url, error)


    lines = body.splitlines()
    record_count = len(lines)
    reader = csv.reader(lines, delimiter=',')

    for row in reader:
        ioc_list.append(row)

    # Remove the URLhause header information
    del ioc_list[0:9]

    for value in ioc_list:
        ioc_urls['urls'].append(value[2])

    try:
        logger.info("Updating %s records to InsightIDR threat list %s" % (record_count,urlhause_key))
        r = requests.post(idr_url, headers=headers, data=json.dumps(ioc_urls))
        logging.info("SUCCESS")
    except (
        e.HTTPError,
        e.ConnectionError,
        e.TooManyRedirects,
        e.RequestException,
    )as error:
        logging.info("FAILURE")
        logger.error("Connection to %s failed %s" % ioc_url, error)

def update_feodo(event, context):

    logger.info("START")
    """
    API and threat keys on local variables.
    """
    threat_key = os.environ["FEODO_KEY"]
    api_key = os.environ["API_KEY"]

    # abuse.ch Feodo Tracker Botnet C2 IP Blocklist
    ioc_url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
    idr_url = "https://eu.api.insight.rapid7.com/idr/v1/customthreats/key/" + threat_key + "/indicators/replace?format=json"
    
    ioc_urls = {
        'domain_names':[''], 
        'hashes':[''], 
        'ips':[''],
        'urls':['']
        }

    headers = {
    'X-Api-Key': api_key,
    'Content-Type': 'application/json'
    }
    
    try:
        logger.info("Retrieving abuse.ch Feodo Tracker Botnet C2 IP Blocklist")
        r = requests.get(ioc_url)
        body = r.text
    except (
        e.HTTPError,
        e.ConnectionError,
        e.TooManyRedirects,
        e.RequestException,
    )as error:
        logger.error("Connection to %s failed %s" % ioc_url, error)

    lines = body.splitlines()
    
    # Remove header information and footer
    del lines[0:9]
    del lines[-1]

    for row in lines:
        ioc_urls['ips'].append(row)

    record_count = len(lines)

    try:
        logger.info("Updating %s records to InsightIDR threat list %s" % (record_count,threat_key))
        r = requests.post(idr_url, headers=headers, data=json.dumps(ioc_urls))
        logging.info("SUCCESS")
    except (
        e.HTTPError,
        e.ConnectionError,
        e.TooManyRedirects,
        e.RequestException,
    )as error:
        logging.info("FAILURE")
        logger.error("Connection to %s failed %s" % ioc_url, error)
