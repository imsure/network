#!/bin/bash

if [ "$1" = '' ]
then
    echo $0 keyword_to_search
    exit 1
fi

find . -name '*.[ch]' | xargs grep $1
