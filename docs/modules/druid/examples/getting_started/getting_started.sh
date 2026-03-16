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

echo "Waiting for node(s) to be ready..."
kubectl wait node --all --for=condition=Ready --timeout=120s

cd "$(dirname "$0")"

case "$1" in
"helm")
echo "Installing Operators with Helm"
# tag::helm-install-operators[]
helm install --wait commons-operator oci://oci.stackable.tech/sdp-charts/commons-operator --version 26.3.0
helm install --wait secret-operator oci://oci.stackable.tech/sdp-charts/secret-operator --version 26.3.0
helm install --wait listener-operator oci://oci.stackable.tech/sdp-charts/listener-operator --version 26.3.0 --set preset=stable-nodes
helm install --wait zookeeper-operator oci://oci.stackable.tech/sdp-charts/zookeeper-operator --version 26.3.0
helm install --wait hdfs-operator oci://oci.stackable.tech/sdp-charts/hdfs-operator --version 26.3.0
helm install --wait druid-operator oci://oci.stackable.tech/sdp-charts/druid-operator --version 26.3.0
# end::helm-install-operators[]
;;
"stackablectl")
echo "installing Operators with stackablectl"
# tag::stackablectl-install-operators[]
stackablectl operator install \
  commons=26.3.0 \
  secret=26.3.0 \
  listener=26.3.0 \
  zookeeper=26.3.0 \
  hdfs=26.3.0 \
  druid=26.3.0
# end::stackablectl-install-operators[]
;;
*)
echo "Need to give 'helm' or 'stackablectl' as an argument for which installation method to use!"
exit 1
;;
esac

# TODO: Remove once https://github.com/stackabletech/issues/issues/828 has been implemented (see that issue for details).
until kubectl get crd druidclusters.druid.stackable.tech >/dev/null 2>&1; do echo "Waiting for CRDs to be installed" && sleep 1; done

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
kubectl rollout status --watch statefulset/simple-hdfs-datanode-default --timeout=600s
kubectl rollout status --watch statefulset/simple-hdfs-journalnode-default --timeout=600s
kubectl rollout status --watch statefulset/simple-hdfs-namenode-default --timeout=600s
# end::watch-hdfs-rollout[]

echo "Installing PostgreSQL for Druid"
# tag::helm-install-postgres[]
helm install postgresql-druid oci://registry-1.docker.io/bitnamicharts/postgresql \
  --version 16.5.0 \
  --set image.repository=bitnamilegacy/postgresql \
  --set volumePermissions.image.repository=bitnamilegacy/os-shell \
  --set metrics.image.repository=bitnamilegacy/postgres-exporter \
  --set global.security.allowInsecureImages=true \
  --set auth.database=druid \
  --set auth.username=druid \
  --set auth.password=druid \
  --wait
# end::helm-install-postgres[]

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
kubectl rollout status --watch statefulset/simple-druid-broker-default --timeout=600s
kubectl rollout status --watch statefulset/simple-druid-coordinator-default --timeout=600s
kubectl rollout status --watch statefulset/simple-druid-historical-default --timeout=600s
kubectl rollout status --watch statefulset/simple-druid-middlemanager-default --timeout=600s
kubectl rollout status --watch statefulset/simple-druid-router-default --timeout=600s
# end::watch-druid-rollout[]

COORDINATOR="simple-druid-coordinator-default-headless.default.svc.cluster.local"
BROKER="simple-druid-broker-default-headless.default.svc.cluster.local"

submit_job() {
  # tag::submit-job[]
  kubectl exec simple-druid-coordinator-default-0 -i -- \
    curl -s -k -X POST -H 'Content-Type:application/json' --data-binary @- \
    "https://${COORDINATOR}:8281/druid/indexer/v1/task" < ingestion_spec.json
  # end::submit-job[]
}

echo "Submitting job"
task_id=$(submit_job | sed -e 's/.*":"\([^"]\+\).*/\1/g')

request_job_status() {
  kubectl exec simple-druid-coordinator-default-0 -- \
    curl -s -k "https://${COORDINATOR}:8281/druid/indexer/v1/task/${task_id}/status" \
  | sed -e 's/.*statusCode":"\([^"]\+\).*/\1/g'
}

while [ "$(request_job_status)" == "RUNNING" ]; do
  echo "Task still running..."
  sleep 10
done

task_status=$(request_job_status)

if [ "$task_status" == "SUCCESS" ]; then
  echo "Task finished successfully!"
else
  echo "Task not successful: $task_status"
  exit 1
fi

segment_load_status() {
  kubectl exec simple-druid-coordinator-default-0 -- \
    curl -s -k "https://${COORDINATOR}:8281/druid/coordinator/v1/loadstatus" \
  | sed -e 's/.*wikipedia":\([0-9\.]\+\).*/\1/g'
}

while [ "$(segment_load_status)" != "100.0" ]; do
  echo "Segments still loading..."
  sleep 10
done

query_data() {
  # tag::query-data[]
  kubectl exec simple-druid-broker-default-0 -i -- \
    curl -s -k -X POST -H 'Content-Type:application/json' --data-binary @- \
    "https://${BROKER}:8282/druid/v2/sql" < query.json
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
