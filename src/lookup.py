# Tools for collecting information ***
# MAC Address Lookup
import json
import requests
from socket import gethostbyname, gaierror

#from socket import *

def lookup_mac(mac):
    MAC_URL = 'http://macvendors.co/api/%s'

    try:
        r = requests.get(MAC_URL % mac)
    except gaierror as gaierr:
        print("**Error with Internet connection**")
        print(gaierr)
        return "No internet connection"
    except requests.exceptions.ConnectionError as cerr:#ConnectionError as cerr:
        print("**Error with Internet connection**")
        print(cerr)
        return "No internet Connection"
    except Exception as e:
        print("Exception: ", e)
        print(type(e))
        return "Problem with connection"
    else:
        try:
            company = json.loads(r.text)['result']['company']
        except:
            print("**company not found**")
            return "**company not found**"
        else:
            print(company)
            return company

# Hostname Lookup
import socket


def lookup_hostname(ip_addr):
    try:
        r = socket.gethostbyaddr(ip_addr)
    except socket.herror as serr:
        if serr.errno != 1:
            print(exception)
        else:
            print("**unknown host**")
            return "**unknown host**"
    except requests.exceptions.RequestException as cerr:#ConnectionError as cerr:
        print("**Error with Internet connection**")
        print(cerr)
        return("No internet Connection")
    except Exception as exception:
        print(exception)
    else:
        print(r[0])
        return r[0]

#Fingerbank API Lookup
def lookup_fingerbank(dhcp_fingerprint, device_hostname, mac, api_key):
    BASE_URL = "https://api.fingerbank.org/api/v2/combinations/interrogate?"
    url = BASE_URL + 'key=' + api_key
    data = {"dhcp_fingerprint": dhcp_fingerprint, "hostname": device_hostname, "mac": mac}
    print(data)
    url = BASE_URL + 'key=' + api_key
    print("Fingerbank request sent")
    r = requests.get(url, data)
    if r.status_code == 200:
        data = r.json()
        response = {"name": data["device"]["name"]}
        print("Returned web info:", device_hostname, response)
        return response
    else:
        print("Fingerprint not retrieved")
