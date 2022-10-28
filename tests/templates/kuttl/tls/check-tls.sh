#!/usr/bin/env bash
# Usage: check-tls.sh namespace

NAMESPACE=$1
HOST=https://derby-druid-router-default-0.derby-druid-router-default.${NAMESPACE}.svc.cluster.local:9088/status/health

# should work with insecure
curl -X 'GET' --insecure $HOST
# should not work without insecure

curl -X 'GET' --insecure $HOST

# should work without insecure but with certificate
curl -X 'GET' $HOST --cacert /tmp/tls/ca.crt

# should not work with wrong certificate
curl -X 'GET' $HOST --cacert /tmp/tls/bad_ca.crt