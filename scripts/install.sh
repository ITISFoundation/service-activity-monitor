#/bin/sh

# usage:
# curl -sSL https://raw.githubusercontent.com/ITISFoundation/service-activity-monitor/main/scripts/install.sh | bash -s <TAG>



# http://redsymbol.net/articles/unofficial-bash-strict-mode/
set -o errexit  # abort on nonzero exitstatus
set -o nounset  # abort on unbound variable
set -o pipefail # don't hide errors within pipes
IFS=$'\n\t'


# Function to display usage information
usage() {
    echo "Usage: $0 <tag>"
    echo "Example: $0 v.0.0.1"
    exit 1
}

# Check if tag argument is provided
if [ $# -ne 1 ]; then
    usage
fi


# Download and install
TAG=$1
URL="https://github.com/ITISFoundation/service-activity-monitor/releases/download/$TAG/release_archive_$TAG.zip"
echo "Downloading release $TAG..."
curl -sSL -o /tmp/release.zip "$URL"

echo "Installing..."

# python scripts
mkdir -p /usr/local/bin/service-monitor
unzip -q /tmp/release.zip -d /usr/local/bin/service-monitor
# requirements
pip install psutil

echo "Installation complete."

# Cleanup
rm /tmp/release.zip
echo "Done!"
