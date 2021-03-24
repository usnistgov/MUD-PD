# Tools for collecting information ***
# MAC Address Lookup
import json
import logging
import requests
import socket
from socket import gaierror


# OUI Lookup based on MAC address
def lookup_mac(mac):
    mac_url = 'http://macvendors.co/api/%s'
    logger = logging.getLogger(__name__)

    try:
        r = requests.get(mac_url % mac)
    except gaierror as gaierr:
        logger.error("No internet connection: %s", gaierr)
        return "No internet connection"
    except requests.exceptions.ConnectionError as cerr:
        logger.error("No internet connection: %s", cerr)
        return "No internet Connection"
    except Exception as e:
        logger.error("Problem with internet connection: type(e) %s, %s ", type(e), e)
        return "Problem with connection"
    else:
        try:
            company = json.loads(r.text)['result']['company']
        except:
            logger.info("**company not found**")
            return "**company not found**"
        else:
            logger.info("company: %s", company)
            return company


# Hostname Lookup
def lookup_hostname(ip_addr):
    logger = logging.getLogger(__name__)
    try:
        r = socket.gethostbyaddr(ip_addr)
    except socket.herror as serr:
        if serr.errno != 1:
            logger.error(serr)
        else:
            logger.debug("**unknown host**")
            return "**unknown host**"
    except requests.exceptions.RequestException as cerr:
        logger.error("No internet connection: %s", cerr)
        return "No internet Connection"
    except Exception as exception:
        logger.error("%s", exception)
    else:
        logger.debug("%s", r[0])
        return r[0]


# Fingerbank API Lookup
def lookup_fingerbank(dhcp_fingerprint, device_hostname, mac, api_key):
    logger = logging.getLogger(__name__)
    base_url = "https://api.fingerbank.org/api/v2/combinations/interrogate?"
    data = {"dhcp_fingerprint": dhcp_fingerprint, "hostname": device_hostname, "mac": mac}
    logger.debug("fingerbank data: %s", data)

    url = base_url + 'key=' + api_key
    logger.info("Fingerbank request sent")
    r = requests.get(url, data)
    if r.status_code == 200:
        data = r.json()
        response = {"name": data["device"]["name"]}
        logger.debug("Returned web info: %s %s", device_hostname, response)
        return response
    else:
        logger.warning("Fingerprint not retrieved")
        return {}
