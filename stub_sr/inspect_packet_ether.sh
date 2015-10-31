#!/bin/bash

if [ "$1" = '' ]
then
    echo $0 path/to/logfile
    exit 1
fi

tcpdump -r $1 -e -vvv -xx
