import urllib

import requests
import http
import sys
import json
import time


class DruidClient:
    def __init__(self, cert, verify):
        self.session = requests.Session()
        self.session.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
        self.session.cert = cert
        self.session.verify = verify

        http.client.HTTPConnection.debuglevel = 1

    def get(self, url):
        response = self.session.get(url)
        assert response.status_code == 200
        return response.text

    def get_tasks(self, url):
        response = self.session.get(url)
        assert response.status_code == 200
        return response.text

    def post_task(self, url, input):
        response = self.session.post(url, data=open(input, 'rb'))
        assert response.status_code == 200
        return response.text

    def check_rc(self, url):
        response = self.session.get(url)
        return response.status_code

    def query_datasource(self, url, sql, expected, iterations):
        loop = 0
        while True:
            response = self.session.post(url, json=sql)
            assert response.status_code == 200
            actual = list(json.loads(response.text)[0].values())[0]
            if (actual == expected) | (loop == iterations):
                break
            time.sleep(5)
            loop += 1
        return actual


namespace = sys.argv[1]
druid_cluster_name = sys.argv[2]
security = sys.argv[3]

if security == "insecure":
    protocol = "http"
    coordinator_port = "8081"
    broker_port = "8082"
    cert = None
    verify = False
elif security == "secure":
    protocol = "https"
    coordinator_port = "8281"
    broker_port = "8282"
    cert = None
    verify = "/tmp/tls/ca.crt"
elif security == "secure_auth":
    protocol = "https"
    coordinator_port = "8281"
    broker_port = "8282"
    cert = ("/tmp/tls_auth/tls.crt", "/tmp/tls_auth/tls.key")
    verify = "/tmp/tls_auth/ca.crt"
else:
    sys.exit("Usage: python ./ingestioncheck.py <namespace> <cluster_name> <insecure|secure|secure_auth>")


druid = DruidClient(cert, verify)

print('''
Query tasks
===========''')
tasks = druid.get_tasks(
    url=f"{protocol}://{druid_cluster_name}-coordinator-default-0.{druid_cluster_name}-coordinator-default.{namespace}.svc.cluster.local:{coordinator_port}/druid/indexer/v1/tasks",
)
task_count = len(json.loads(tasks))
print(f'existing tasks: {task_count}')

print('''
Start ingestion task
====================''')
ingestion = druid.post_task(
    url=f"{protocol}://{druid_cluster_name}-coordinator-default-0.{druid_cluster_name}-coordinator-default.{namespace}.svc.cluster.local:{coordinator_port}/druid/indexer/v1/task",
    input='/tmp/druid-quickstartimport.json'
)
task_id = json.loads(ingestion)["task"]
url_encoded_taskid = urllib.parse.quote(task_id, safe='')
print(f"TASKID: [{task_id}]")
print('''
Re-query tasks
==============''')
tasks = druid.get_tasks(
    url=f"{protocol}://{druid_cluster_name}-coordinator-default-0.{druid_cluster_name}-coordinator-default.{namespace}.svc.cluster.local:{coordinator_port}/druid/indexer/v1/tasks",
)
new_task_count = len(json.loads(tasks))
print(f'new tasks: {new_task_count}')
print(f'assert {new_task_count} == {task_count+1}')
assert new_task_count == task_count + 1

print('''
Wait for ingestion task to succeed
======================================''')
job_finished = False
while not job_finished:
    time.sleep(5)
    task = druid.get(
        url=f"{protocol}://{druid_cluster_name}-coordinator-default-0.{druid_cluster_name}-coordinator-default.{namespace}.svc.cluster.local:{coordinator_port}/druid/indexer/v1/task/{url_encoded_taskid}/status",
    )
    task_status = json.loads(task)["status"]["statusCode"]
    print(f"Current task status: [{task_status}]")
    assert task_status == "RUNNING" or task_status == "SUCCESS", f"Taskstatus not running or succeeeded: {task_status}"
    job_finished = task_status == "SUCCESS"

print('''
Wait for broker to indicate all segments are fully online
======================================''')
broker_ready = False
while not broker_ready:
    time.sleep(2)
    broker_ready_rc = druid.check_rc(f"{protocol}://{druid_cluster_name}-broker-default-0.{druid_cluster_name}-broker-default.{namespace}.svc.cluster.local:{broker_port}/druid/broker/v1/readiness")
    broker_ready = broker_ready_rc == 200
    print(f"Broker respondend with [{broker_ready_rc}] to readiness check")

print('''
Datasource SQL
==============''')
sample_data_size = 39244
result = druid.query_datasource(
    url=f"{protocol}://{druid_cluster_name}-broker-default-0.{druid_cluster_name}-broker-default.{namespace}.svc.cluster.local:{broker_port}/druid/v2/sql",
    sql={"query": "select count(*) as c from \"wikipedia-2015-09-12\""},
    expected=sample_data_size,
    iterations=12
)
print(f'results: {result}')
print(f'assert {sample_data_size} == {result}')
assert sample_data_size == result
