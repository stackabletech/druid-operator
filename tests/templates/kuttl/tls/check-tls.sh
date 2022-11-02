#!/usr/bin/env bash
# Usage: check-tls.sh namespace protocol

NAMESPACE=$1
PROTOCOL=$2

if [[ $PROTOCOL == "http" ]]
then
  HOST=${PROTOCOL}://derby-druid-router-default-0.derby-druid-router-default.${NAMESPACE}.svc.cluster.local:8888/status/health

  # should work
  echo "Test non TLS access"
  if [[ $(curl $HOST &> /dev/null) == "true" ]]
  then
    echo "[SUCCESS] Could establish connection to unprotected server!"
  else
    echo "[ERROR] Could not establish connection to unprotected server! Something went wrong..."
    exit 1
  fi
fi

if [[ $PROTOCOL == "https" ]]
then
  HOST=${PROTOCOL}://derby-druid-router-default-0.derby-druid-router-default.${NAMESPACE}.svc.cluster.local:9088/status/health

  # Should not work without --insecure
  echo "Test TLS without insecure access"
  if [[ $(curl $HOST &> /dev/null) == "true" ]]
  then
    echo "[ERROR] Could establish connection to untrusted server. Should not be happening!"
    exit 1
  else
    echo "[SUCCESS] Could not establish connection to untrusted server!"
  fi

  # should work with insecure
  echo "Test TLS with insecure access"
  if ! curl --insecure $HOST &> /dev/null
  then
    echo "[ERROR] Could not establish connection to server. Should not be happening!"
    exit 1
  else
    echo "[SUCCESS] Could establish connection to server disregarding certificate!"
  fi

  # should work without insecure but with certificate
  echo "Test TLS with trusted certificate"
  if ! curl $HOST --cacert /tmp/tls/ca.crt &> /dev/null
  then
    echo "[ERROR] Could not establish connection to server with trusted certificate. Should not be happening!"
    exit 1
  else
    echo "[SUCCESS] Could establish connection to server with trusted certificate!"
  fi

  # should not work with wrong certificate
  echo "Test TLS with untrusted certificate"
  if curl $HOST --cacert /tmp/tls/untrusted-ca.crt &> /dev/null
  then
    echo "[ERROR] Could establish connection to server with untrusted certificate. Should not be happening!"
    exit 1
  else
    echo "[SUCCESS] Could not establish connection to server with untrusted certificate!"
  fi
fi