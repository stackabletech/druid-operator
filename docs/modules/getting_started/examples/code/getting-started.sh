#!/bin/bash

# The getting started guide script
# It uses tagged regions which are included in the documentation
# https://docs.asciidoctor.org/asciidoc/latest/directives/include-tagged-regions/
#
# There are two variants to go through the guide - using stackablectl or helm
# The script takes either 'stackablectl' or 'helm' as an argument

case "$1" in
"helm")
echo "Adding 'stackable' Helm Chart repository"
# tag::helm-add-repo[]
helm repo add stackable https://repo.stackable.tech/repository/helm-stable/
# end::helm-add-repo[]
echo "Installing Druid and ZooKeeper Operators with Helm"
# tag::helm-install-operators[]
helm install commons-operator stackable/commons-operator
helm install secret-operator stackable/secret-operator
helm install zookeeper-operator stackable/zookeeper-operator
helm install hdfs-operator stackable/hdfs-operator
helm install druid-operator stackable/druid-operator
# end::helm-install-operators[]
;;
"stackablectl")
echo "installing Operators with stackablectl"
# tag::stackablectl-install-operators[]
stackablectl operator install commons secret zookeeper hdfs druid
# end::stackablectl-install-operators[]
;;
esac

echo "Installing ZooKeeper from zookeeper.yaml"
# tag::install-zookeeper[]
kubectl apply -f zookeeper.yaml
# end::install-zookeeper[]

echo "Awaiting ZooKeeper rollout finish"
# tag::watch-zookeeper-rollout[]
kubectl rollout status --watch statefulset/simple-zk-server-default
# end::watch-zookeeper-rollout[]

echo "Installing HDFS from hdfs.yaml"
# tag::install-hdfs[]
kubectl apply -f hdfs.yaml
# end::install-hdfs[]

echo "Awaiting HDFS rollout finish"
# tag::watch-hdfs-rollout[]
kubectl rollout status --watch statefulset/simple-hdfs-datanode-default
kubectl rollout status --watch statefulset/simple-hdfs-journalnode-default
kubectl rollout status --watch statefulset/simple-hdfs-namenode-default
# end::watch-hdfs-rollout[]

echo "Install DruidCluster from druid.yaml"
# tag::install-druid[]
kubectl apply -f druid.yaml
# end::install-druid[]

echo "Awaiting Druid rollout finish"
# tag::watch-druid-rollout[]
kubectl rollout status --watch statefulset/simple-druid-broker-default
kubectl rollout status --watch statefulset/simple-druid-coordinator-default
kubectl rollout status --watch statefulset/simple-druid-historical-default
kubectl rollout status --watch statefulset/simple-druid-middlemanager-default
kubectl rollout status --watch statefulset/simple-druid-router-default
# end::watch-druid-rollout[]


# next, make sure everything is up and running, then open the port-forwarding

# kubectl port-forward svc/simple-druid-router 8888


# TODO I think HDFS is missing. And Postgres might not be necessary, it looks like derby works