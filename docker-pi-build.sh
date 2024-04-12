#/bin/bash
docker buildx create --use
docker buildx build --platform linux/arm64 --tag architectingsoftware/sysstream:v1  -f ./Dockerfile . --push