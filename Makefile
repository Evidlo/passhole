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

.PHONY: test_install_arch
install_arch:
	docker build \
		-t "passhole:arch" \
		-f test/Dockerfile_arch .
	docker run \
		-it "passhole:arch" \
		/bin/bash

.PHONY: test_install_debian
install_debian:
	docker build \
		-t "passhole:debian" \
		-f test/Dockerfile_debian .
	docker run \
		-it "passhole:debian" \
		/bin/bash
