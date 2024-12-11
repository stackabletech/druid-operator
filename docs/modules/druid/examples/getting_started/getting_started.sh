#!/usr/bin/env bash
set -euo pipefail

# DO NOT EDIT THE SCRIPT
# Instead, update the j2 template, and regenerate it for dev with `make render-docs`.

# The getting started guide script
# It uses tagged regions which are included in the documentation
# https://docs.asciidoctor.org/asciidoc/latest/directives/include-tagged-regions/
#
# There are two variants to go through the guide - using stackablectl or helm
# The script takes either 'stackablectl' or 'helm' as an argument
#
# The script can be run as a test as well, to make sure that the tutorial works
# It includes some assertions throughout, and at the end especially.

if [ $# -eq 0 ]
then
  echo "Installation method argument ('helm' or 'stackablectl') required."
  exit 1
fi

cd "$(dirname "$0")"

case "$1" in
"helm")
echo "Adding 'stackable-dev' Helm Chart repository"
# tag::helm-add-repo[]
helm repo add stackable-dev https://repo.stackable.tech/repository/helm-dev/
# end::helm-add-repo[]
echo "Updating Helm repo"
helm repo update
echo "Installing Operators with Helm"
# tag::helm-install-operators[]
helm install --wait commons-operator stackable-dev/commons-operator --version 0.0.0-dev
helm install --wait secret-operator stackable-dev/secret-operator --version 0.0.0-dev
helm install --wait listener-operator stackable-dev/listener-operator --version 0.0.0-dev
helm install --wait zookeeper-operator stackable-dev/zookeeper-operator --version 0.0.0-dev
helm install --wait hdfs-operator stackable-dev/hdfs-operator --version 0.0.0-dev
helm install --wait druid-operator stackable-dev/druid-operator --version 0.0.0-dev
# end::helm-install-operators[]
;;
"stackablectl")
echo "installing Operators with stackablectl"
# tag::stackablectl-install-operators[]
stackablectl operator install \
  commons=0.0.0-dev \
  secret=0.0.0-dev \
  listener=0.0.0-dev \
  zookeeper=0.0.0-dev \
  hdfs=0.0.0-dev \
  druid=0.0.0-dev
# end::stackablectl-install-operators[]
;;
*)
echo "Need to give 'helm' or 'stackablectl' as an argument for which installation method to use!"
exit 1
;;
esac

echo "Installing ZooKeeper from zookeeper.yaml"
# tag::install-zookeeper[]
kubectl apply -f zookeeper.yaml
# end::install-zookeeper[]

for (( i=1; i<=15; i++ ))
do
  echo "Waiting for ZookeeperCluster to appear ..."
  if eval kubectl get statefulset simple-zk-server-default; then
    break
  fi

  sleep 1
done

echo "Awaiting ZooKeeper rollout finish"
# tag::watch-zookeeper-rollout[]
kubectl rollout status --watch statefulset/simple-zk-server-default --timeout=300s
# end::watch-zookeeper-rollout[]

echo "Installing HDFS from hdfs.yaml"
# tag::install-hdfs[]
kubectl apply -f hdfs.yaml
# end::install-hdfs[]

for (( i=1; i<=15; i++ ))
do
  echo "Waiting for HdfsCluster to appear ..."
  if eval kubectl get statefulset simple-hdfs-datanode-default; then
    break
  fi

  sleep 1
done

echo "Awaiting HDFS rollout finish"
# tag::watch-hdfs-rollout[]
kubectl rollout status --watch statefulset/simple-hdfs-datanode-default --timeout=300s
kubectl rollout status --watch statefulset/simple-hdfs-journalnode-default --timeout=300s
kubectl rollout status --watch statefulset/simple-hdfs-namenode-default --timeout=300s
# end::watch-hdfs-rollout[]

echo "Install DruidCluster from druid.yaml"
# tag::install-druid[]
kubectl apply --server-side -f druid.yaml
# end::install-druid[]

for (( i=1; i<=15; i++ ))
do
  echo "Waiting for DruidCluster to appear ..."
  if eval kubectl get statefulset simple-druid-broker-default; then
    break
  fi

  sleep 1
done

echo "Awaiting Druid rollout finish"
# tag::watch-druid-rollout[]
kubectl rollout status --watch statefulset/simple-druid-broker-default --timeout=300s
kubectl rollout status --watch statefulset/simple-druid-coordinator-default --timeout=300s
kubectl rollout status --watch statefulset/simple-druid-historical-default --timeout=300s
kubectl rollout status --watch statefulset/simple-druid-middlemanager-default --timeout=300s
kubectl rollout status --watch statefulset/simple-druid-router-default --timeout=300s
# end::watch-druid-rollout[]

echo "Starting port-forwarding of port 8888"
# shellcheck disable=2069 # we want all output to be blackholed
# tag::port-forwarding[]
kubectl port-forward svc/simple-druid-router 8888 > /dev/null 2>&1 &
# end::port-forwarding[]
PORT_FORWARD_PID=$!
# shellcheck disable=2064 # we want the PID evaluated now, not at the time the trap is
trap "kill $PORT_FORWARD_PID" EXIT
sleep 5

submit_job() {
# tag::submit-job[]
curl -s -X 'POST' -H 'Content-Type:application/json' -d @ingestion_spec.json http://localhost:8888/druid/indexer/v1/task
# end::submit-job[]
}

echo "Submitting job"
task_id=$(submit_job | sed -e 's/.*":"\([^"]\+\).*/\1/g')

request_job_status() {
  curl -s "http://localhost:8888/druid/indexer/v1/task/${task_id}/status" | sed -e 's/.*statusCode":"\([^"]\+\).*/\1/g'
}

while [ "$(request_job_status)" == "RUNNING" ]; do
  echo "Task still running..."
  sleep 5
done

task_status=$(request_job_status)

if [ "$task_status" == "SUCCESS" ]; then
  echo "Task finished successfully!"
else
  echo "Task not successful: $task_status"
  exit 1
fi

segment_load_status() {
 curl -s http://localhost:8888/druid/coordinator/v1/loadstatus | sed -e 's/.*wikipedia":\([0-9\.]\+\).*/\1/g'
}

while [ "$(segment_load_status)" != "100.0" ]; do
  echo "Segments still loading..."
  sleep 5
done

query_data() {
# tag::query-data[]
curl -s -X 'POST' -H 'Content-Type:application/json' -d @query.json http://localhost:8888/druid/v2/sql
# end::query-data[]
}

echo "Querying data..."
query_result=$(query_data)

if [ "$query_result" == "$(cat expected_query_result.json)" ]; then
  echo "Query result is as expected!"
else
  echo "Query result differs from expected result."
  echo "Query: $query_result"
  echo "Expected: $(cat expected_query_result.json)"
  exit 1
fi
