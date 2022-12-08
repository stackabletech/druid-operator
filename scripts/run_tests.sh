#!/usr/bin/env bash
set -e

# Register absolute paths to pass to Ansible so the location of the role is irrelevant
# for the run
TESTDIR="$(pwd)/tests"
WORKDIR="$(pwd)/tests/_work"

cd "$TESTDIR"

curl -L "https://github.com/stackabletech/beku/releases/download/wip/beku" -o "beku"
chmod +x beku

./beku -d test-definition.yaml -t templates/kuttl -o _work/tests

# Run tests
pushd _work
kubectl kuttl test "$@"

