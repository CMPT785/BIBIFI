#!/bin/sh
if [ "$1" = "test" ]; then
    ./test_runner
else
    exec /bin/bash
fi
