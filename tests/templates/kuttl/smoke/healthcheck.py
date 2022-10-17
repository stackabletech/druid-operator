import requests
import sys
import logging
import time

if __name__ == "__main__":
    result = 0

    log_level = 'DEBUG'  # if args.debug else 'INFO'
    logging.basicConfig(level=log_level, format='%(asctime)s %(levelname)s: %(message)s', stream=sys.stdout)

    druid_cluster_name = "druid"
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
        count = 1

        # As this script is intended to be executed by Kuttl which is in charge of overall test timeouts it is ok
        # to loop infinitely here - or until all tests succeed
        # The script iterates over all known ports and services and checks that the ports are available
        # The timeout for this connection attempt is configured to 5 seconds, to ensure frequent retries that are
        # not handled internally by the requests library, because it was unclear when or if dns entries are cached
        # internally during retry handling.
        # By issuing a new call to .get() we are trying to ensure a new dns lookup for the target.
        #
        # Any errors are logged and retried until either the test succeeds or Kuttl kills this script due to
        # the timeout.
        while True:
            try:
                count = count + 1
                print(f"Checking role [{role}] on url [{url}]")
                res = requests.get(url, timeout=5)
                code = res.status_code
                if res.status_code == 200 and res.text.lower() == "true":
                    break
                else:
                    print(f"Got non 200 status code [{res.status_code}] or non-true response [{res.text.lower()}], retrying attempt no [{count}] ....")
            except requests.exceptions.Timeout:
                print(f"Connection timed out, retrying attempt no [{count}] ....")
            except requests.ConnectionError as e:
                print(f"Connection Error: {str(e)}")
            except requests.RequestException as e:
                print(f"General Error: {str(e)}")
            except Exception:
                print(f"Unhandled error occurred, retrying attempt no [{count}] ....")

            # Wait a little bit before retrying
            time.sleep(1)
    sys.exit(0)
