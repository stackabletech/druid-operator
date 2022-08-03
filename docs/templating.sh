#!/usr/bin/env bash
set -euo pipefail

# dependencies
# pip install jinja2-cli

for file in $(find | grep .j2\$)
do
  new_file_name=$(echo $file | sed 's/\(.*\).j2/\1/g')  # cut of the '.j2'
  jinja2 $file templating_vars.yaml -o $new_file_name
done