import requests
import sys
import logging

USER_NAME = "integrationtest"
USER_PASSWORD = "bindPasswordWithSpecialCharacter\\@<&>\"'"


def main():
    result = 0

    druid_cluster_name = "derby-druid"

    druid_role_ports = {
        "broker": 8282,
        "coordinator": 8281,
        "middlemanager": 8291,
        "historical": 8283,
        "router": 9088,
    }
    log_level = "INFO"
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s %(levelname)s: %(message)s",
        stream=sys.stdout,
    )

    for role, port in druid_role_ports.items():
        url = f"https://{druid_cluster_name}-{role}-default-metrics:{port}/status"
        # make an authorized request -> return 401 expected
        logging.info(f"making unauthorized request to {role}.")
        res = requests.get(url, verify=False)
        if res.status_code != 401:
            logging.error(f"expected 401 but got {res.status_code}")
            result = 1
            break
        else:
            logging.info("success")
        # make an authorized request -> return 200 expected
        logging.info(f"making request as LDAP user [{USER_NAME}] to {role}")
        res = requests.get(url, auth=(USER_NAME, USER_PASSWORD), verify=False)
        if res.status_code != 200:
            logging.error(f"expected 200 but got {res.status_code}")
            result = 1
            break
        else:
            logging.info("success")
        # make an unauthorized request -> return 401 expected
        # eve is not an ldap user
        logging.info(f"making request as unknown user [eve] to {role}")
        res = requests.get(url, auth=("eve", "wrong-password"), verify=False)
        if res.status_code != 401:
            logging.error(f"expected 401 but got {res.status_code}")
            result = 1
            break
        else:
            logging.info("success")

    return result


if __name__ == "__main__":
    sys.exit(main())
