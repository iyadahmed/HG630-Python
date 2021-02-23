import urllib3, requests, base64, json
from lxml import html
from hashlib import sha256
from pprint import pprint


# The router's web interface doesn't provide SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# https://blog.davidventura.com.ar/hacking-the-hg659.html
def _hash(user, password, csrf_param, csrf_token):
    _pwd_hash = sha256(password.encode('utf-8')).hexdigest().encode('ascii')
    _b64 = base64.b64encode(_pwd_hash).decode('ascii')
    _b = user + _b64 + csrf_param + csrf_token
    _b = _b.encode('utf-8')
    return sha256(_b).hexdigest()


def find_csrf(response):
    tree = html.fromstring(response.text)
    csrf_param = tree.xpath("//meta[@name='csrf_param']/@content")[0]
    csrf_token = tree.xpath("//meta[@name='csrf_token']/@content")[0]
    return csrf_param, csrf_token


def parse(response):
    # strips while{1}; /* --- */ and parses json
    return json.loads(response.text[12:-2])


url = 'http://192.168.1.1/'
user = ""
password = ""


with requests.Session() as session:
    session.verify = False # The router's web interface doesn't provide SSL
    
    result = session.get(url)
    csrf_param, csrf_token = find_csrf(result)
    login_payload = {
        "csrf": {"csrf_param": csrf_param, "csrf_token": csrf_token},
        "data":
        {
            "UserName": user,
            "Password": _hash(user, password, csrf_param, csrf_token),
        },
    }
    # headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    r = session.get(url + 'api/system/deviceinfo')
    print(parse(r)['SerialNumber'])
    post = session.post(url + 'api/system/user_login', data=json.dumps(login_payload))
    r = session.get(url + 'api/ntwk/WlanBasic')
    pprint(parse(r)[0])

