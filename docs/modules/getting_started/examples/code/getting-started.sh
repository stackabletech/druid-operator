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
helm install druid-operator stackable/druid-operator
# end::helm-install-operators[]
;;
"stackablectl")
echo "installing Operators with stackablectl"
# tag::stackablectl-install-operators[]
stackablectl operator install commons secret zookeeper druid
# end::stackablectl-install-operators[]
;;
esac

echo "Adding Helm bitnami repo"
# tag::add-helm-bitnami-repo[]
helm repo add bitnami https://charts.bitnami.com/bitnami
# end::add-helm-bitnami-repo[]

echo "Installing ZooKeeper from zookeeper.yaml"
# tag::install-zookeeper[]
kubectl apply -f zookeeper.yaml
# end::install-zookeeper[]

echo "Installing HDFS from hdfs.yaml"
# tag::install-hdfs[]
kubectl apply -f hdfs.yaml
# end::install-hdfs[]

echo "Installing the Postgres database"
# tag::install-bitnami-postgres[]
helm install druid bitnami/postgresql \
--version=11 \
--set auth.username=druid \
--set auth.password=druid \
--set auth.database=druid
# end::install-bitnami-postgres[]

echo "Install DruidCluster from druid.yaml"
# tag::install-druid[]
kubectl apply -f druid.yaml
# end::install-druid[]


# TODO I think HDFS is missing. And Postgres might not be necessary, it looks like derby works