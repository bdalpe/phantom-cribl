#!/bin/sh
rm phcribl.tgz
tar -zcvf phcribl.tgz -X phcribl/exclude_files.txt --exclude='exclude_files.txt' --disable-copyfile phcribl/