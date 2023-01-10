import requests
import sys
import logging


def main():
    result = 0

    proto = "http"
    druid_cluster_name = "derby-druid"

    druid_ports = {
        "coordinator": 8081,
        # "broker": 8082,
        # "middlemanager": 8091,
        # "historical": 8083,
        # "router": 8888
    }
    log_level = 'INFO'
    logging.basicConfig(level=log_level, format='%(asctime)s %(levelname)s: %(message)s', stream=sys.stdout)

    for role, port in druid_ports.items():
        url = f"{proto}://{druid_cluster_name}-{role}-default:{port}/status"
        # make an authorized request -> return 401 expected
        logging.info(f"making unauthorized request to {role}.")
        res = requests.get(url)
        if res.status_code != 401:
            logging.error(f"expected 401 but got {res.status_code}")
            result = 1
            break
        else:
            logging.info("success")
        # make an authorized request -> return 200 expected
        logging.info(f"making request as LDAP user [alice] to {role}")
        res = requests.get(url, auth=("alice", "alice"))
        if res.status_code != 200:
            logging.error(f"expected 200 but got {res.status_code}")
            result = 1
            break
        else:
            logging.info("success")
        # make an unauthorized request -> return 403 expected
        # eve is not an ldap user
        logging.info(f"making request as unknown user [eve] to {role}")
        res = requests.get(url, auth=("eve", "eve"))
        if res.status_code != 401:
            logging.error(f"expected 401 but got {res.status_code}")
            result = 1
            break
        else:
            logging.info("success")

    return result


if __name__ == "__main__":
    sys.exit(main())
