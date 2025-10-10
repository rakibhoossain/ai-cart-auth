#!/bin/bash

# AI-Cart-Auth Multi-Platform Build Script
# This script builds the ai-cart-auth binary for multiple platforms

set -e

VERSION=${VERSION:-"1.0.0"}
BUILD_DIR="build"
APP_NAME="ai-cart-auth"

echo "Building ${APP_NAME} v${VERSION} for multiple platforms..."

# Clean previous builds
rm -rf ${BUILD_DIR}
mkdir -p ${BUILD_DIR}

# Build for different platforms
platforms=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
)

for platform in "${platforms[@]}"; do
    platform_split=(${platform//\// })
    GOOS=${platform_split[0]}
    GOARCH=${platform_split[1]}
    
    output_name="${BUILD_DIR}/${APP_NAME}-${GOOS}-${GOARCH}"
    
    if [ $GOOS = "windows" ]; then
        output_name+='.exe'
    fi
    
    echo "Building for ${GOOS}/${GOARCH}..."
    
    env GOOS=$GOOS GOARCH=$GOARCH go build \
        -ldflags="-s -w -X main.Version=${VERSION}" \
        -o $output_name \
        .
    
    if [ $? -ne 0 ]; then
        echo "Error building for ${GOOS}/${GOARCH}"
        exit 1
    fi

    echo "✓ Built ${output_name}"
done

echo ""
echo "Build complete! Binaries are in the ${BUILD_DIR} directory:"
ls -lh ${BUILD_DIR}

