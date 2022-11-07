#!/usr/bin/env bash
# Usage: check-tls.sh namespace type [insecure,secure,secure_auth]

NAMESPACE=$1
TYPE=$2

# No encryption
if [[ $TYPE == "insecure" ]]
then
  HOST=http://derby-druid-router-default-0.derby-druid-router-default.${NAMESPACE}.svc.cluster.local:8888/status/health

  # should work
  echo "[NO_TLS] Test unsecured access"
  if curl "$HOST" &> /dev/null
  then
    echo "[SUCCESS] Could establish connection to unsecured server!"
  else
    echo "[ERROR] Could not establish connection to unsecured server! Should not be happening!"
    exit 1
  fi
fi

# Only encryption
if [[ $TYPE == "secure" ]]
then
  HOST=https://derby-druid-router-default-0.derby-druid-router-default.${NAMESPACE}.svc.cluster.local:9088/status/health

  # should not work without --insecure
  echo "[TLS_ENCRYPTION] Test TLS without trusted CA and without insecure access"
  if curl "$HOST" &> /dev/null
  then
    echo "[ERROR] Could establish connection to untrusted server. Should not be happening!"
    exit 1
  else
    echo "[SUCCESS] Could not establish connection to untrusted server!"
  fi

  # should work with insecure
  echo "[TLS_ENCRYPTION] Test TLS without trusted CA but with insecure access"
  if curl --insecure "$HOST" &> /dev/null
  then
    echo "[SUCCESS] Could establish connection to server disregarding certificate!"
  else
    echo "[ERROR] Could not establish connection to server. Should not be happening!"
    exit 1
  fi

  # should work without insecure but with certificate
  echo "[TLS_ENCRYPTION] Test TLS with trusted certificate"
  if curl --cacert /tmp/tls/ca.crt "$HOST" &> /dev/null
  then
    echo "[SUCCESS] Could establish connection to server with trusted certificate!"
  else
    echo "[ERROR] Could not establish connection to server with trusted certificate. Should not be happening!"
    exit 1
  fi

  # should not work with wrong certificate
  echo "[TLS_ENCRYPTION] Test TLS with untrusted certificate"
  if curl --cacert /tmp/tls/untrusted-ca.crt "$HOST" &> /dev/null
  then
    echo "[ERROR] Could establish connection to server with untrusted certificate. Should not be happening!"
    exit 1
  else
    echo "[SUCCESS] Could not establish connection to server with untrusted certificate!"
  fi
fi

# Encryption and TLS client auth
if [[ $TYPE == "secure_auth" ]]
then
  HOST=https://derby-druid-router-default-0.derby-druid-router-default.${NAMESPACE}.svc.cluster.local:9088/status/health

  # Should fail
  echo "[TLS_AUTH] Test insecure access"
  if curl --insecure "$HOST" &> /dev/null
  then
    echo "[ERROR] Could establish insecure connection to server! This should not be happening!"
    exit 1
  else
    echo "[SUCCESS] Could not establish insecure connection to server!"
  fi

  # Should fail
  echo "[TLS_AUTH] Test access providing CA"
  if curl --cacert  "$HOST" &> /dev/null
  then
    echo "[ERROR] Could establish insecure connection to server! This should not be happening!"
    exit 1
  else
    echo "[SUCCESS] Could not establish connection providing only CA to server!"
  fi

  # Should fail
  echo "[TLS_AUTH] Test access providing wrong ca, cert and key"
  if curl --cacert /tmp/tls/ca.crt --cert /tmp/tls/tls.crt --key /tmp/tls/tls.key "$HOST" &> /dev/null
  then
    echo "[ERROR] Could establish authenticated connection to server with wrong credentials! This should not be happening!"
    exit 1
  else
    echo "[SUCCESS] Could not establish authenticated connection with wrong credentials to server!"
  fi

  # Should work
  echo "[TLS_AUTH] Test access providing correct ca, cert and key"
  if curl --cacert /tmp/tls_auth/ca.crt --cert /tmp/tls_auth/tls.crt --key /tmp/tls_auth/tls.key "$HOST" &> /dev/null
  then
    echo "[SUCCESS] Could establish authenticated connection to server!"
  else
    echo "[ERROR] Could not establish authenticated connection to server! This should not be happening!"
    exit 1
  fi
fi
