#!/usr/bin/env bash
set -euo pipefail

test_dir="$(dirname "$0")/../tests"
work_dir="_work"

cd "$test_dir"

curl -L "https://github.com/stackabletech/beku/releases/download/wip/beku" -o "beku"
chmod +x beku

./beku --definition test-definition.yaml \
       --templates templates \
       --kuttl-test kuttl-test.yaml.jinja2 \
       --out "$work_dir"

# Run tests
pushd "$work_dir"
kubectl kuttl test "$@"

