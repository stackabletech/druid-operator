import requests
import sys
import logging

coordinator_host = "derby-druid-coordinator-default-headless"
coordinator_port = "8281"
authenticator_name = "MyBasicMetadataAuthenticator"


def create_user(user_name):
    requests.post(
        f"https://{coordinator_host}:{coordinator_port}/druid-ext/basic-security/authentication/db/{authenticator_name}/users/{user_name}",
        auth=("admin", "password1"),
        verify=False,
    )
    data = f'{{"password": "{user_name}"}}'
    headers = {
        "Content-Type": "application/json",
    }
    requests.post(
        f"https://{coordinator_host}:{coordinator_port}/druid-ext/basic-security/authentication/db/{authenticator_name}/users/{user_name}/credentials",
        headers=headers,
        data=data,
        auth=("admin", "password1"),
        verify=False,
    )


if __name__ == "__main__":
    result = 0

    log_level = "DEBUG"
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s %(levelname)s: %(message)s",
        stream=sys.stdout,
    )

    print("CREATING USERS")
    create_user("alice")
    create_user("eve")
    print("USERS CREATED!")

    druid_cluster_name = sys.argv[1]

    druid_role_ports = {
        "broker": 8282,
        "coordinator": 8281,
        "middlemanager": 8291,
        "historical": 8283,
        "router": 9088,
    }

    for role, port in druid_role_ports.items():
        url = f"https://{druid_cluster_name}-{role}-default-headless:{port}/status"
        # make an authorized request -> return 401 expected
        print("Checking Unauthorized")
        res = requests.get(url, verify=False)
        if res.status_code != 401:
            result = 1
            break
        # make an authorized request -> return 200 expected
        print("Checking Alice")
        res = requests.get(url, auth=("alice", "alice"), verify=False)
        if res.status_code != 200:
            result = 1
            break
        # make an unauthorized request -> return 403 expected
        print("Checking Eve")
        res = requests.get(url, auth=("eve", "eve"), verify=False)
        if res.status_code != 403:
            result = 1
            break

    sys.exit(result)
