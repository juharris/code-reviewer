#!/bin/bash

# nginx is used to serve the warmup request that Azure App Service sends.
echo "Starting nginx"
nginx

echo "Starting run.py"
python3 src/run.py config.yml
