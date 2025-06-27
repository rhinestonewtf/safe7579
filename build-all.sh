#!/bin/bash

# Array of contract names to build
CONTRACTS=(
    "./src/Safe7579.sol"
    "./src/Safe7579Launchpad.sol"
  )
# Loop through the contracts and run build-artifacts.sh for each
for CONTRACT in "${CONTRACTS[@]}"; do
    echo "Building artifacts for $CONTRACT..."
    ./build-artifacts.sh "$CONTRACT"
    
    # Check the exit status of the previous command
    if [ $? -eq 0 ]; then
        echo "Successfully built artifacts for $CONTRACT"
    else
        echo "Failed to build artifacts for $CONTRACT"
        # Optionally, you can choose to exit the script on first failure
        # exit 1
    fi
done

echo "Artifact build process completed."
