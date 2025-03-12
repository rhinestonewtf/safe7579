#!/bin/bash

# generates lcov.info
forge coverage --ir-minimum \
    --report lcov

if ! command -v lcov &>/dev/null; then
    echo "lcov is not installed. Installing..."
    sudo apt-get install lcov
fi

lcov --version

EXCLUDE="*test* *mocks* *node_modules* *script*"
lcov \
    --rc branch_coverage=1 \
    --remove lcov.info $EXCLUDE \
    --output-file forge-pruned-lcov.info \
    --ignore-errors source,inconsistent,category

if [ "$CI" != "true" ]; then
    genhtml forge-pruned-lcov.info \
        --rc branch_coverage=1 \
        --output-directory coverage \
        --ignore-errors source,inconsistent,category
    open coverage/index.html
fi