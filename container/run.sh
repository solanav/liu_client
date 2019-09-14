#!/bin/bash

IMAGE_NAME=liu_client
DIR="${0%/*}"
BUILD=../build/

# Move the latest liu_client to folder
cp $BUILD/src/liu_client $DIR/files/liu_client

# Create a private network to swim
docker network create --driver bridge private

# Build the docker image
docker build . -t $IMAGE_NAME

# Run it
docker run -ti --net=private $IMAGE_NAME
