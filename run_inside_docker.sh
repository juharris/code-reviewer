#!/bin/bash

# nginx is used to serve the warmup request that Azure App Service sends.
echo "Starting nginx"
nginx

# Add Poetry to the path.
export PATH="$HOME/.local/bin:$PATH"

echo "Starting run.py"
poetry run python3 src/run.py config.yml
