import base64
import json
from getpass import getpass
from hashlib import sha256
from pprint import pprint

import requests
import urllib3
from lxml import html

# The router's web interface doesn't provide SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# https://blog.davidventura.com.ar/hacking-the-hg659.html
def _hash(user, password, csrf_param, csrf_token):
    _pwd_hash = sha256(password.encode("utf-8")).hexdigest().encode("ascii")
    _b64 = base64.b64encode(_pwd_hash).decode("ascii")
    _b = user + _b64 + csrf_param + csrf_token
    _b = _b.encode("utf-8")
    return sha256(_b).hexdigest()


def find_csrf(response):
    tree = html.fromstring(response.text)
    csrf_param = tree.xpath("//meta[@name='csrf_param']/@content")[0]
    csrf_token = tree.xpath("//meta[@name='csrf_token']/@content")[0]
    return csrf_param, csrf_token


def parse(response: requests.Response):
    response_clean = response.content.removeprefix(b"while(1); /*").removesuffix(b"*/")
    return json.loads(response_clean)


url = "http://192.168.1.1/"
print("HG630 V2 Router Log-in:")
user = input("Username: ")
password = getpass("Password: ")


with requests.Session() as session:
    session.verify = False  # The router's web interface doesn't provide SSL

    result = session.get(url)
    csrf_param, csrf_token = find_csrf(result)
    login_payload = {
        "csrf": {"csrf_param": csrf_param, "csrf_token": csrf_token},
        "data": {
            "UserName": user,
            "Password": _hash(user, password, csrf_param, csrf_token),
        },
    }
    # headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

    # Login to router
    login_respone = session.post(url + "api/system/user_login", data=json.dumps(login_payload))
    if not (login_respone.ok):
        raise RuntimeError("Failed to login")

    login_content = parse(login_respone)
    err_cat = login_content["errorCategory"]
    if err_cat == "user_pass_err":
        raise RuntimeError(f"Incorrect user name or password.")
    elif err_cat == "Three_time_err":
        login_count = login_content["count"]
        raise RuntimeError(f"You have failed {login_count} times. Please try again in a minute.")

    # Device info
    # NOTE: it used to be possible to get serial number even without login, on older firmaware
    device_info_respone = session.get(url + "api/system/deviceinfo")
    serial_number = parse(device_info_respone)["SerialNumber"]
    print(f"Serial Number: {serial_number[:-8] + '*' * 8}")

    # WLAN basic info
    wlan_basic_respone = session.get(url + "api/ntwk/WlanBasic")
    pprint(parse(wlan_basic_respone)[0])
