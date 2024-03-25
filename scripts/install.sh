#/bin/sh

# usage:
# curl -sSL https://raw.githubusercontent.com/ITISFoundation/service-activity-monitor/main/scripts/install.sh | bash -s <TAG>



# http://redsymbol.net/articles/unofficial-bash-strict-mode/
set -o errexit  # abort on nonzero exitstatus
set -o nounset  # abort on unbound variable
set -o pipefail # don't hide errors within pipes
IFS=$'\n\t'




GITHUB_USER="ITISFoundation"
REPO_NAME="service-activity-monitor"

# Function to display usage information
usage() {
    echo "Usage: $0 <release_tag>"
    echo "Example: $0 v1.0.0"
    exit 1
}

# Check for the release tag argument
if [ $# -ne 1 ]; then
    usage
fi

# Extract release tag from command-line argument
RELEASE_TAG="$1"

# Specify the name of the release archive
RELEASE_ARCHIVE="$REPO_NAME-$RELEASE_TAG.tar.gz"

# Specify the URL to download the release archive
RELEASE_URL="https://github.com/$GITHUB_USER/$REPO_NAME/releases/download/$RELEASE_TAG/$RELEASE_ARCHIVE"

# Temporary directory to extract the release archive
TEMP_DIR="/tmp/$REPO_NAME-$RELEASE_TAG"

# Function to clean up temporary files
cleanup() {
    rm -rf "$TEMP_DIR"
}

# Trap cleanup function on EXIT
trap cleanup EXIT

# Download and extract the release archive
echo "Downloading release archive..."
mkdir -p "$TEMP_DIR"
wget -q -O "$TEMP_DIR/$RELEASE_ARCHIVE" "$RELEASE_URL" || { echo "Failed to download release archive"; exit 1; }
tar -xf "$TEMP_DIR/$RELEASE_ARCHIVE" -C "$TEMP_DIR" || { echo "Failed to extract release archive"; exit 1; }

# Copy files to /usr/local/bin
echo "Installing files to /usr/local/bin..."
sudo cp -r "$TEMP_DIR/"* /usr/local/bin/ || { echo "Failed to copy files to /usr/local/bin"; exit 1; }

# Set permissions for the files
sudo chmod +x /usr/local/bin/*

echo "Installation completed successfully."
