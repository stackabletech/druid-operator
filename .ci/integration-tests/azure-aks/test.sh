#!/bin/bash
git clone -b "$GIT_BRANCH" https://github.com/stackabletech/druid-operator.git
(cd druid-operator/ && ./scripts/run_tests.sh)
exit_code=$?
./operator-logs.sh druid > /target/druid-operator.log
exit $exit_code
