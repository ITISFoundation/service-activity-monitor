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
    echo "Example: $0 v.0.0.9-debug"
    exit 1
}

# Check if tag argument is provided
if [ $# -ne 1 ]; then
    usage
fi

TAG=$1
URL="https://github.com/ITISFoundation/service-activity-monitor/releases/download/$TAG/release_archive_$TAG.zip"

# Download and install
echo "Downloading release $TAG..."
curl -sSL -o /tmp/release.zip "$URL"

echo "Extracting files..."
unzip -q /tmp/release.zip -d /tmp/release
mkdir -p /user/local/bin/service-monitor
mv --force /tmp/release/src /user/local/bin/service-monitor

echo "Installing..."
# Here you can write your installation steps, for now let's just echo the installation is complete
echo "Installation complete."

# Cleanup
rm /tmp/release.zip
rm -rf /tmp/release

echo "Done!"
