#!/bin/bash
set -e

# Paths
PROJECT_DIR="/home/simar/Documents/UEBA/UEBA_BACKEND"
DIST_DIR="$PROJECT_DIR/dist"

# Clean old dist
rm -rf "$DIST_DIR"

# Run Docker build
docker run --rm -it \
  -v "$PROJECT_DIR":/work \
  -w /work \
  python:3.12-bullseye bash -c "
    pip install -r requirements.txt &&
    pip install pyinstaller &&
    pyinstaller --clean ueba_client.spec &&
    pyinstaller --clean ueba_server.spec
  "
