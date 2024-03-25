#/bin/sh

# http://redsymbol.net/articles/unofficial-bash-strict-mode/
set -o errexit  # abort on nonzero exitstatus
set -o nounset  # abort on unbound variable
set -o pipefail # don't hide errors within pipes
IFS=$'\n\t'


install() {
  make .venv  
  source .venv/bin/activate
  make install-test
  pip list --verbose
}

test() {
  # shellcheck source=/dev/null
  source .venv/bin/activate
  make tests-ci
}