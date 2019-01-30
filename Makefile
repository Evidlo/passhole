.ONESHELL:

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
