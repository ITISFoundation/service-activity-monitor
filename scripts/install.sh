#/bin/sh

# usage:
# curl -o- https://raw.githubusercontent.com/ITISFoundation/service-activity-monitor/main/scripts/install.sh | bash

# http://redsymbol.net/articles/unofficial-bash-strict-mode/
set -o errexit  # abort on nonzero exitstatus
set -o nounset  # abort on unbound variable
set -o pipefail # don't hide errors within pipes
IFS=$'\n\t'

curl -o https://raw.githubusercontent.com/ITISFoundation/service-activity-monitor/main/src/activity.py 