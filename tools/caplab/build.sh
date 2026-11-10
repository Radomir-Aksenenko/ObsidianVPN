#!/bin/bash
# build.sh <version>: build lab binaries from the repo HEAD with the lab hooks.
set -e
export PATH=$PATH:/root/sdk/go/bin
v=$1
rm -rf ~/capw/$v; mkdir -p ~/capw/$v; cd ~/capw/$v
git -C /mnt/e/Projects/tets_vpn archive HEAD | tar -x
cp tools/caplab/labhooks/zz_lab.go.txt cmd/server/zz_lab.go
CGO_ENABLED=0 go build -o ~/capw/out/server-$v ./cmd/server
CGO_ENABLED=0 go build -o ~/capw/out/caph-$v ./tools/caplab/caph
cp tools/caplab/*.sh tools/caplab/*.py ~/capw/
