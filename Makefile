# Evan Widloski - 2019-03-04
# makefile for building/testing passhole

# run all lines in target in single shell, quit on error
.ONESHELL:
.SHELLFLAGS = -ec

version := $(shell python -c "exec(open('passhole/version.py').read());print(__version__)")

.PHONY: man
man:
	pandoc \
		-s \
		-t man \
		MANUAL.rst \
		-o passhole.1 \
		-M date="`date "+%B %e, %Y"`"

.PHONY: dist
dist:
	python setup.py sdist

.PHONY: release
release: dist man
	# check that changelog is updated.  only look at first 3 parts of semver
	version=$(version)
	stripped=$$(echo $${version} | cut -d . -f -3 | cut -d '-' -f 1)
	if ! grep $${stripped} CHANGELOG.rst
	then
		echo "Changelog doesn't seem to be updated! Quitting..."
		exit 1
	fi
	# generate release notes from changelog
	awk "BEGIN{p=0}; /^$${stripped}/{next}; /---/{p=1;next}; /^$$/{exit}; p {print}" CHANGELOG.rst > TMPNOTES
	gh release create --latest --verify-tag v$(version) dist/passhole-$(version)* -F TMPNOTES
	twine upload dist/passhole-$(version).tar.gz

.PHONY: release_nonotes
release_nonotes: dist man
	gh release create --latest --verify-tag v$(version) dist/psashole-$(version)*
	twine upload dist/passhole-$(version).tar.gz

.PHONY: lock
lock:
	# run tests then make a requirements.txt lockfile
	rm -rf .venv_lock
	virtualenv .venv_lock
	. .venv_lock/bin/activate
	pip install .
	python test/tests.py
	pip freeze > requirements.txt

.PHONY: tag
tag:
	# tag git commit
	git add requirements.txt
	git add setup.py
	git add CHANGELOG.rst
	git commit -m "bump version" --allow-empty
	git tag -a v$(version) -m "version $(version)"
	git push --tags
	git push

# ----- Docker -----

nocache_docker_debian:
	docker build \
		-t "passhole:debian" \
		-f test/Dockerfile_debian . \
		--build-arg CACHEBUST=$(date)
	docker run \
		-it "passhole:debian" \
		/bin/bash

docker_debian:
	podman build \
		-t "passhole:debian" \
		-f test/Dockerfile_debian .
	podman run \
		-it "passhole:debian" \
		/bin/bash
