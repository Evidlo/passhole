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

.PHONY: pypi
pypi: dist man
	twine upload dist/passhole-$(version).tar.gz

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
