#!/bin/bash

# installer for OpenWebfilemgr

# Copyright (C) 2026 AXV (AhmedXV-V12)
# OpenWebfilemgr is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.

echo "Welcome to OpenWebfilemgr-installer"
sleep 0.5

echo "Opening config.json for editing..."
sleep 0.5
nano config.json

echo "Opening docker-compose.yml for editing..."
sleep 0.5
nano docker-compose.yml

read -p "Do you need to edit style.css? (y/N): " style_choice
if [[ "$style_choice" =~ ^[Yy]$ ]]; then
    nano style.css
else
    echo "Skipping style.css"
fi

read -p "Do you need to edit index.html? (y/N): " html_choice
if [[ "$html_choice" =~ ^[Yy]$ ]]; then
    nano index.html
else
    echo "Skipping index.html"
fi

read -p "Do you need to edit app.py? (y/N): " app_choice
if [[ "$app_choice" =~ ^[Yy]$ ]]; then
    nano app.py
else
    echo "Skipping app.py"
fi

read -p "Build docker image now? (y/N): " build_choice
if [[ "$build_choice" =~ ^[Yy]$ ]]; then
    echo "Building docker image..."
    docker compose build
    read -p "Start OpenWebfilemgr now? (y/N): " start_choice
    if [[ "$start_choice" =~ ^[Yy]$ ]]; then
        docker compose up -d
        sleep 3
        echo "If you left the password empty, a new one was generated:"
        docker compose logs openwebfilemgr | grep -i "password" || true
    fi
else
    echo "Installation finished without building."
fi
