#!/bin/bash
set -e
echo $CR_PAT | docker login ghcr.io -u USERNAME --password-stdin
docker build -t realityctrl/tf-parliament .
docker tag realityctrl/tf-parliament:latest ghcr.io/realityctrl/tf-parliament:latest
docker push ghcr.io/realityctrl/tf-parliament:latest
