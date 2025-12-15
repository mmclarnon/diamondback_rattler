#!/bin/bash
VERSION_FILE="VERSION.txt"

# Read the current version from the file
current_version=$(<"$VERSION_FILE")

# Split the version into major, minor, and patch components
IFS='.' read -r major minor patch <<< "$current_version"

# Increment the patch version
((patch++))

# Format the new version string
new_version="${major}.${minor}.${patch}"

# Write the new version back to the file
echo "$new_version" > "$VERSION_FILE"

echo "Version updated to: $new_version"