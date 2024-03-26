#/bin/sh

# http://redsymbol.net/articles/unofficial-bash-strict-mode/
set -o errexit  # abort on nonzero exitstatus
set -o nounset  # abort on unbound variable
set -o pipefail # don't hide errors within pipes
IFS=$'\n\t'


install() {
  make .venv  
  source .venv/bin/activate
  pip install -r requirements/test.in
  pip list --verbose
}

test() {
  # shellcheck source=/dev/null
  source .venv/bin/activate
  make tests-ci
}

# Check if the function exists (bash specific)
if declare -f "$1" >/dev/null; then
  # call arguments verbatim
  "$@"
else
  # Show a helpful error
  echo "'$1' is not a known function name" >&2
  exit 1
fi