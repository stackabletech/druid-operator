import requests
import sys
import logging

if __name__ == "__main__":
    result = 0

    log_level = 'DEBUG'  # if args.debug else 'INFO'
    logging.basicConfig(level=log_level, format='%(asctime)s %(levelname)s: %(message)s', stream=sys.stdout)

    druid_cluster_name = "derby-druid"
    druid_roles = [
        "broker",
        "coordinator",
        "middlemanager",
        "historical",
        "router"
    ]
    druid_ports = {
        "broker": 8082,
        "coordinator": 8081,
        "middlemanager": 8091,
        "historical": 8083,
        "router": 8888
    }

    for role in druid_roles:
        url = f"http://{druid_cluster_name}-{role}-default:{druid_ports[role]}/status/health"
        res = requests.get(url)
        if res.status_code != 200 or res.text.lower() != "true":
            result = 1
            break

    sys.exit(result)
