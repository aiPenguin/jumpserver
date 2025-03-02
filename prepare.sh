#!/bin/bash

# List of files to be moved to /usr/local/bin
BIN_FILES=(
    "add-admin"
    "add-user"
    "del-user"
    "list-users"
    "set-expiry"
    "add-pubkey"
    "secure-home"
    "batch-expiry"
)

# Check if running with sudo
if [ "$EUID" -ne 0 ]; then 
    echo "Please run with sudo"
    exit 1
fi

# Create directories if they don't exist
mkdir -p /usr/local/bin
mkdir -p /etc/profile.d
mkdir -p /etc/skel

# Copy files to /usr/local/bin and make them executable
for file in "${BIN_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "Copying $file to /usr/local/bin/"
        cp "$file" /usr/local/bin/
        chmod +x "/usr/local/bin/$file"
        echo "Made $file executable"
    else
        echo "Warning: $file not found"
    fi
done

# Handle special files
if [ -f "jumpbox-security.sh" ]; then
    echo "Copying jumpbox-security.sh to /etc/profile.d/"
    cp "jumpbox-security.sh" /etc/profile.d/
    chmod +x /etc/profile.d/jumpbox-security.sh
else
    echo "Warning: jumpbox-security.sh not found"
fi

if [ -f ".bashrc_jumpbox" ]; then
    echo "Copying .bashrc_jumpbox to /etc/skel/"
    cp ".bashrc_jumpbox" /etc/skel/
else
    echo "Warning: .bashrc_jumpbox not found"
fi

echo "Operation completed"





