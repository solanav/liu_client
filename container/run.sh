#!/bin/bash

IMAGE_NAME=liu_client
DIR="${0%/*}"
BUILD=/home/solanav/Projects/liu/build

# Move the latest liu_client to folder
cp $BUILD/src/liu_client $DIR/files/liu_client

# Build the docker image
docker build . -t $IMAGE_NAME

# Run it
docker run -ti --cap-add=NET_ADMIN --device=/dev/net/tun $IMAGE_NAME
