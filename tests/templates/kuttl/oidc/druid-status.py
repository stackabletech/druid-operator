import logging
import requests
import json
import urllib3


def test_redirect_to_keycloak(login_url):
    result = requests.get(
        login_url,
        verify=False,
        allow_redirects=False,
    )

    result.raise_for_status()

    code = result.status_code
    location = result.headers.get('Location', default="")
    if not (code == 302 and location.startswith("http://keycloak:8080/realms/stackable/protocol/openid-connect/auth")):
        raise ValueError(f"Expected redirect to Keycloak but got code [{code}] and location [{location}]")


def test_page_with_token(kc_token_url, product_page):
    result = requests.post(
        kc_token_url,
        data={
            "client_id": "keycloak-client-druid",
            "client_secret": "keycloak-client-druid-secret",
            "username": "stackable",
            "password": "stackable",
            "grant_type": "password",
            "scope": "openid",
        },
    )

    result.raise_for_status()

    id_token = json.loads(result.text)["id_token"]

    result = requests.get(
        product_page,
        headers={"Authorization": f"Bearer {id_token}"},
        verify=False,
    )

    result.raise_for_status()

    if "true" != result.text:
        raise ValueError(result.text)


def main():
    logging.basicConfig(level=logging.INFO)
    # disable a warning (InsecureRequestWarning) because it's just noise here
    urllib3.disable_warnings()

    test_redirect_to_keycloak("https://druid-router:9088/unified-console.html")

    test_page_with_token(
        "http://keycloak:8080/realms/stackable/protocol/openid-connect/token",
        "https://druid-router:9088/status/health",
    )

    logging.info("Success!")


if __name__ == "__main__":
    main()
