import re
import socket
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import ssl
import whois
from datetime import datetime

# --- Helper Functions ---

def url_having_ip(url):
    try:
        hostname = urlparse(url).hostname
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
            return 1
        if re.match(r"^\d+$", hostname.replace('.', '')):
            return 1
        return 0
    except:
        return 1  # treat errors as suspicious

def url_length(url):
    l = len(url)
    if l < 54:
        return 0
    elif 54 <= l <= 75:
        return 0.5
    else:
        return 1

def url_short(url):
    shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc"
    return 1 if re.search(shortening_services, url) else 0

def having_at_symbol(url):
    return 1 if "@" in url else 0

def doubleSlash(url):
    last_slash = url.rfind('//')
    return 1 if last_slash < 7 else 0

def prefix_suffix(url):
    domain = urlparse(url).netloc
    return 1 if '-' in domain else 0

def sub_domain(url):
    domain = urlparse(url).netloc
    dots = domain.count('.')
    if dots == 1:
        return 0
    elif dots == 2:
        return 0.5
    else:
        return 1

def SSLfinal_State(url):
    try:
        scheme = urlparse(url).scheme.lower()
        hostname = urlparse(url).hostname
        if scheme != 'https':
            return 1  # Phishing
        # Check certificate age (simplified)
        cert = ssl.get_server_certificate((hostname, 443))
        # If no cert or errors, treat as suspicious
        # For demo purposes, ignore actual parsing
        return 0  # assume trusted HTTPS
    except:
        return 1

def domain_registration(url):
    try:
        domain = urlparse(url).netloc
        w = whois.whois(domain)
        exp_date = w.expiration_date
        if isinstance(exp_date, list):
            exp_date = exp_date[0]
        if not exp_date or (exp_date - datetime.now()).days <= 365:
            return 1
        return 0
    except:
        return 1

def favicon(url):
    try:
        r = requests.get(url, timeout=3)
        return 1 if f"{urlparse(url).netloc}/favicon.ico" not in r.text else 0
    except:
        return 1

def port(url):
    p = urlparse(url).port
    return 1 if p not in [None, 80, 443] else 0

def https_token(url):
    domain = urlparse(url).netloc
    return 1 if 'https' in domain else 0

def request_url(url):
    try:
        r = requests.get(url, timeout=3)
        external_links = re.findall(r'src="(http[s]?://.*?)"', r.text)
        if not external_links:
            return 0
        outside = sum(1 for l in external_links if urlparse(l).netloc != urlparse(url).netloc)
        percent = outside / len(external_links) * 100
        if percent < 22:
            return 0
        elif 22 <= percent < 61:
            return 0.5
        else:
            return 1
    except:
        return 1

def url_of_anchor(url):
    try:
        r = requests.get(url, timeout=3)
        soup = BeautifulSoup(r.text, 'html.parser')
        anchors = [a.get('href') for a in soup.find_all('a', href=True)]
        if not anchors:
            return 1
        outside = sum(1 for a in anchors if urlparse(a).netloc != urlparse(url).netloc)
        percent = outside / len(anchors) * 100
        if percent < 31:
            return 0
        elif 31 <= percent < 67:
            return 0.5
        else:
            return 1
    except:
        return 1

def Links_in_tags(url):
    try:
        r = requests.get(url, timeout=3)
        soup = BeautifulSoup(r.text, 'html.parser')
        tags = soup.find_all(['script', 'link', 'meta'])
        outside = sum(1 for t in tags if t.get('src') and urlparse(t.get('src')).netloc != urlparse(url).netloc)
        if not tags:
            return 0
        percent = outside / len(tags) * 100
        if percent < 17:
            return 0
        elif 17 <= percent < 81:
            return 0.5
        else:
            return 1
    except:
        return 1

def sfh(url):
    try:
        r = requests.get(url, timeout=3)
        forms = re.findall(r'<form[^>]+action="([^"]+)"', r.text)
        if not forms:
            return 1
        outside = sum(1 for f in forms if urlparse(f).netloc != urlparse(url).netloc)
        if outside > 0:
            return 0.5
        return 0
    except:
        return 1

def email_submit(url):
    try:
        r = requests.get(url, timeout=3)
        return 1 if "mailto:" in r.text else 0
    except:
        return 1

def abnormal_url(url):
    hostname = urlparse(url).hostname
    return 0 if hostname else 1

def redirect(url):
    redirects = url.count('//')
    if redirects <= 1:
        return 1
    elif 2 <= redirects < 4:
        return 0.5
    else:
        return 0

def on_mouseover(url):
    try:
        r = requests.get(url, timeout=3)
        return 1 if 'onmouseover' in r.text else 0
    except:
        return 1

def rightClick(url):
    try:
        r = requests.get(url, timeout=3)
        return 1 if 'contextmenu' in r.text else 0
    except:
        return 1

def popup(url):
    try:
        r = requests.get(url, timeout=3)
        return 1 if 'alert(' in r.text else 0
    except:
        return 1

def iframe(url):
    try:
        r = requests.get(url, timeout=3)
        return 1 if '<iframe' in r.text else 0
    except:
        return 1

def age_of_domain(url):
    try:
        domain = urlparse(url).netloc
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if not creation:
            return 0
        age_months = (datetime.now() - creation).days / 30
        return 0 if age_months <= 6 else 1
    except:
        return 1

def check_dns(url):
    try:
        hostname = urlparse(url).hostname
        socket.gethostbyname(hostname)
        return 0
    except:
        return 1

def web_traffic(url):
    # Placeholder: real implementation would use Alexa/SimilarWeb rank
    rank = 200000  # dummy value
    if rank <= 100000:
        return 0
    elif rank <= 200000:
        return 0.5
    else:
        return 1

def page_rank(url):
    pr = 0.1  # dummy
    return 1 if pr < 0.2 else 0

def google_index(url):
    indexed = True  # dummy
    return 0 if indexed else 1

def links_pointing(url):
    links = 0  # dummy
    if links == 0:
        return 1
    elif links <= 2:
        return 0.5
    else:
        return 0

def statistical(url):
    phishing_ip = False  # dummy
    return 1 if phishing_ip else 0

# --- Main Feature Extraction ---
def extract_url_features(url):
    return {
        'url_having_ip': url_having_ip(url),
        'url_length': url_length(url),
        'url_short': url_short(url),
        'having_at_symbol': having_at_symbol(url),
        'doubleSlash': doubleSlash(url),
        'prefix_suffix': prefix_suffix(url),
        'sub_domain': sub_domain(url),
        'SSLfinal_State': SSLfinal_State(url),
        'domain_registration': domain_registration(url),
        'favicon': favicon(url),
        'port': port(url),
        'https_token': https_token(url),
        'request_url': request_url(url),
        'url_of_anchor': url_of_anchor(url),
        'Links_in_tags': Links_in_tags(url),
        'sfh': sfh(url),
        'email_submit': email_submit(url),
        'abnormal_url': abnormal_url(url),
        'redirect': redirect(url),
        'on_mouseover': on_mouseover(url),
        'rightClick': rightClick(url),
        'popup': popup(url),
        'iframe': iframe(url),
        'age_of_domain': age_of_domain(url),
        'check_dns': check_dns(url),
        'web_traffic': web_traffic(url),
        'page_rank': page_rank(url),
        'google_index': google_index(url),
        'links_pointing': links_pointing(url),
        'statistical': statistical(url)
    }
