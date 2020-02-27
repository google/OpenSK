#!/bin/bash

env

PYLINT_CMD=pylint --score=n${INPUT_CONFIG_FILE:+ --rcfile=${INPUT_CONFIG_FILE}}
EXCLUDE_PATH=${INPUT_EXCLUDE_PATH:-}
EXCLUDE_FILES=${INPUT_EXCLUDE_PATH:-}

SUCCESS=0
for file in ${FILES}
do
  fname=$(basename $file)
  directory=$(dirname $file)
  if [[ "$directory" =~ "^${EXCLUDE_PATH}" ]]
  then
    echo "Ignoring file '$file' (reason: matching exclude-path parameter)"
    continue
  fi
  if [[ "$fname" =~ "${EXCLUDE_FILES}" ]]
  then
    echo "Ignoring file '$file' (reason: matching exclude-files parameter)"
    continue
  fi
  # Just to trigger the custom matcher
  echo PYLINT:$file
  if ! $PYLINT_CMD $file
  then
    SUCCESS=1
  fi
done

exit $SUCCESS
