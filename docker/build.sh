#!/bin/bash
# Build the fuzzing image. Run from anywhere; uses this dir's Dockerfile.
set -e
cd "$(dirname "$0")"
docker build -f Dockerfile.fuzz -t vra-fuzz:latest .
echo "built vra-fuzz:latest — run with:"
echo "  docker run --rm -it -v \$HOME/vuln-research-agent:/work vra-fuzz"
