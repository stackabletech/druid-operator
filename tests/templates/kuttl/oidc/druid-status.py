import logging
import requests
import json
import urllib3


def main():
    logging.basicConfig(level=logging.INFO)
    # disable a warning (InsecureRequestWarning) because it's just noise here
    urllib3.disable_warnings()

    result = requests.post(
        "http://keycloak:8080/realms/stackable/protocol/openid-connect/token",
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
        "https://druid-router:9088/status/health",
        headers={"Authorization": f"Bearer {id_token}"},
        verify=False,
    )

    result.raise_for_status()

    if "true" != result.text:
        raise ValueError(result.text)
    else:
        logging.info("Success!")


if __name__ == "__main__":
    main()
