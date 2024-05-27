# $NAMESPACE will be replaced with the namespace of the test case.

import logging
import os
import requests
import sys
from bs4 import BeautifulSoup

logging.basicConfig(
    level='DEBUG',
    format="%(asctime)s %(levelname)s: %(message)s",
    stream=sys.stdout)

namespace = sys.argv[1]
tls = os.environ['OIDC_USE_TLS']

session = requests.Session()

# Open Druid web UI which will redirect to OIDC login
login_page = session.get("https://druid-router-default:9088/unified-console.html", verify=False, headers={'Content-type': 'application/json'})
keycloak_base_url = f"https://keycloak.{namespace}.svc.cluster.local:8443" if tls == 'true' else f"http://keycloak.{namespace}.svc.cluster.local:8080"
assert login_page.ok, "Redirection from Druid to Keycloak failed"
assert login_page.url.startswith(f"{keycloak_base_url}/realms/test/protocol/openid-connect/auth?scope=openid+profile+email&response_type=code&redirect_uri=https%3A%2F%2Fdruid-router-default%3A9088%2Fdruid-ext%2Fdruid-pac4j%2Fcallback&state="), \
    "Redirection to Keycloak expected"

# Login to keycloak with test user
login_page_html = BeautifulSoup(login_page.text, 'html.parser')
authenticate_url = login_page_html.form['action']
welcome_page = session.post(authenticate_url, data={
    'username': "jane.doe",
    'password': "T8mn72D9"
})

assert welcome_page.ok, "Login failed"
assert welcome_page.url == "https://druid-router-default:9088/unified-console.html", \
    "Redirection to the Druid web UI expected"
