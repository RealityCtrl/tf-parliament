#!/bin/bash
set -e
#$(aws ecr get-login --no-include-email --region us-east-1 --profile qa)
docker build -t managed-content/tf-parliament .
docker tag managed-content/tf-parliament:latest 549050352176.dkr.ecr.us-east-1.amazonaws.com/managed-content/tf-parliament:latest
docker push 549050352176.dkr.ecr.us-east-1.amazonaws.com/managed-content/tf-parliament:latest
