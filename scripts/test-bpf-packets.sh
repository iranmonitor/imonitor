#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
TEST_BIN=$(mktemp "${TMPDIR:-/tmp}/imonitor-packet-test.XXXXXX")
trap 'rm -f "$TEST_BIN"' EXIT INT TERM
"${CC:-cc}" -O2 tests/bpf_packet_tests.c -o "$TEST_BIN"
"$TEST_BIN"
