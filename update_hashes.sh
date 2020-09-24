#!/bin/bash

set -eux

mkdir -p tmp

for OS in macos-10.15 ubuntu-18.04
do
  unzip reproduced-$OS.zip -d tmp/reproduced-$OS/
  tar -C tmp/reproduced-$OS/ -xvf tmp/reproduced-$OS/reproduced.tar
  cp tmp/reproduced-$OS/reproducible/binaries.sha256sum reproducible/reference_binaries_$OS.sha256sum
  cp tmp/reproduced-$OS/reproducible/elf2tab.txt reproducible/reference_elf2tab_$OS.txt
done

rm -R tmp
