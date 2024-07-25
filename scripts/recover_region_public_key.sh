#!/bin/bash
echo "recover the current public key of the specified AWS region"
echo "returns (key id, public key)"
region=$1

token1=`aws sts get-session-token --region $region | python3 -c 'import json,sys;obj=json.load(sys.stdin);print(obj["Credentials"]["SessionToken"])'`
token2=`aws sts get-session-token --region $region | python3 -c 'import json,sys;obj=json.load(sys.stdin);print(obj["Credentials"]["SessionToken"])'`

python3 ../STS-session.py $token1 $token2


