#!/bin/bash

# Build Docker images for Auth and Backend services

set -e

echo "Building Docker images..."

# Build Auth service
if [ -f "Auth/dockerfile" ]; then
    echo "Building Auth service..."
    docker build -t auth-service ./Auth -f ./Auth/dockerfile
    echo "Auth service built successfully"
else
    echo "Warning: Auth/Dockerfile not found"
fi

# Build Backend service
if [ -f "Backend/dockerfile" ]; then
    echo "Building Backend service..."
    docker build -t backend-service ./Backend -f ./Backend/dockerfile
    echo "Backend service built successfully"
else
    echo "Warning: Backend/Dockerfile not found"
fi

#Build Frontend service
if [ -f "Frontend/dockerfile" ]; then
    echo "Building Frontend service..."
    docker build -t frontend-service ./Frontend -f ./Frontend/dockerfile
    echo "Frontend service built successfully"
else
    echo "Warning: Frontend/Dockerfile not found"
fi

echo "All Docker images built successfully!"

