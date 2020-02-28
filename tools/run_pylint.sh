#!/usr/bin/env bash

SUCCESS=0

# Ensure we are at the project root directory
cd $(readlink -f $(dirname $0))/..

for file in `find . ! -path "./third_party/*" -type f -name '*.py'`
do
  # Output header for our custom matcher on Github workflow
  echo "PYLINT:${file}"
  if ! pylint --rcfile=.pylintrc --score=n "$file"
  then
    SUCCESS=1
  fi
done

exit $SUCCESS
