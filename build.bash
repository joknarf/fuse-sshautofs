#!/bin/bash
# go get bazil.org/fuse
set -e

go build -trimpath -ldflags="-s -w" -o sshautofs main.go

echo "Build complete: ./sshautofs"
