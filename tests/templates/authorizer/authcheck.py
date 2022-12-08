import requests
import sys
import logging

coordinator_host = "derby-druid-coordinator-default"
coordinator_port = "8081"
authenticator_name = "MyBasicMetadataAuthenticator"


def create_user(user_name):
    requests.post(
        f"http://{coordinator_host}:{coordinator_port}/druid-ext/basic-security/authentication/db/{authenticator_name}/users/{user_name}",
        auth=("admin", "password1")
    )
    data = f"{{\"password\": \"{user_name}\"}}"
    headers = {
        'Content-Type': 'application/json',
    }
    requests.post(f"http://{coordinator_host}:{coordinator_port}/druid-ext/basic-security/authentication/db/{authenticator_name}/users/{user_name}/credentials", headers=headers, data=data, auth=('admin', 'password1'))


if __name__ == "__main__":
    result = 0

    log_level = 'DEBUG'
    logging.basicConfig(level=log_level, format='%(asctime)s %(levelname)s: %(message)s', stream=sys.stdout)

    print("CREATING USERS")
    create_user("alice")
    create_user("eve")
    print("USERS CREATED!")

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
        url = f"http://{druid_cluster_name}-{role}-default:{druid_ports[role]}/status"
        # make an authorized request -> return 401 expected
        print("Checking Unauthorized")
        res = requests.get(url)
        if res.status_code != 401:
            result = 1
            break
        # make an authorized request -> return 200 expected
        print("Checking Alice")
        res = requests.get(url, auth=("alice", "alice"))
        if res.status_code != 200:
            result = 1
            break
        # make an unauthorized request -> return 403 expected
        print("Checking Eve")
        res = requests.get(url, auth=("eve", "eve"))
        if res.status_code != 403:
            result = 1
            break

    sys.exit(result)
