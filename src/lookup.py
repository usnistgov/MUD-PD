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
    print(__name__)
    logger = logging.getLogger(__name__)

    try:
        r = requests.get(mac_url % mac)
    except gaierror as gaierr:
        # print("**Error with Internet connection**")
        # print(gaierr)
        logger.error("No internet connection: %s", gaierr)
        return "No internet connection"
    except requests.exceptions.ConnectionError as cerr:
        # print("**Error with Internet connection**")
        # print(cerr)
        logger.error("No internet connection: %s", cerr)
        return "No internet Connection"
    except Exception as e:
        # print("Exception: ", e)
        # print(type(e))
        logger.error("Problem with internet connection: type(e) %s, %s ", type(e), e)
        return "Problem with connection"
    else:
        try:
            company = json.loads(r.text)['result']['company']
        except:
            # print("**company not found**")
            logger.info("**company not found**")
            return "**company not found**"
        else:
            # print(company)
            logger.info("company: %s", company)
            return company


# Hostname Lookup
def lookup_hostname(ip_addr):
    logger = logging.getLogger(__name__)
    try:
        r = socket.gethostbyaddr(ip_addr)
    except socket.herror as serr:
        if serr.errno != 1:
            # print(serr)
            logger.error(serr)
        else:
            print("**unknown host**")
            logger.debug("**unknown host**")
            return "**unknown host**"
    except requests.exceptions.RequestException as cerr:
        # print("**Error with Internet connection**")
        # print(cerr)
        logger.error("No internet connection: %s", cerr)
        return "No internet Connection"
    except Exception as exception:
        # print(exception)
        logger.error("%s", exception)
    else:
        print(r[0])
        return r[0]


# Fingerbank API Lookup
def lookup_fingerbank(dhcp_fingerprint, device_hostname, mac, api_key):
    logger = logging.getLogger('lookup')  # __name__)
    base_url = "https://api.fingerbank.org/api/v2/combinations/interrogate?"
    data = {"dhcp_fingerprint": dhcp_fingerprint, "hostname": device_hostname, "mac": mac}
    # print(data)
    logger.debug("fingerbank data: %s", data)

    url = base_url + 'key=' + api_key
    # print("Fingerbank request sent")
    logger.info("Fingerbank request sent")
    r = requests.get(url, data)
    if r.status_code == 200:
        data = r.json()
        response = {"name": data["device"]["name"]}
        #print("Returned web info:", device_hostname, response)
        logger.debug("Returned web info: %s %s", device_hostname, response)
        return response
    else:
        # print("Fingerprint not retrieved")
        logger.warning("Fingerprint not retrieved")
        return {}
