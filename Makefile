SHELL = /bin/sh
.DEFAULT_GOAL := help


.PHONY: devenv
.venv:
	@python3 --version
	python3 -m venv $@
	# upgrading package managers
	$@/bin/pip install --upgrade \
		pip \
		wheel \
		setuptools

devenv: .venv  ## create a python virtual environment with tools to dev, run and tests cookie-cutter
	# installing extra tools
	@$</bin/pip3 install pip-tools
	# your dev environment contains
	@$</bin/pip3 list
	@echo "To activate the virtual environment, run 'source $</bin/activate'"


requirements: devenv ## runs pip-tools to compile dependencies
	# freezes requirements
	pip-compile requirements/test.in --resolver=backtracking --output-file requirements/test.txt


.PHONY: install-test
install-test:	## install dependencies for testing
	pip install -r requirements/test.txt

.PHONY: tests-dev
tests-dev:	## run tests in development mode
	.venv/bin/pytest --pdb -vvv tests

.PHONY: tests-ci
tests-ci:	## run testds in the CI
	.venv/bin/pytest -vvv --color=yes --cov-report term --cov=activity_monitor tests 

.PHONY: help
help: ## this colorful help
	@echo "Recipes for '$(notdir $(CURDIR))':"
	@echo ""
	@awk 'BEGIN {FS = ":.*?## "} /^[[:alpha:][:space:]_-]+:.*?## / {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
