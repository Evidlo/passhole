version := $(shell python -c "exec(open('passhole/version.py').read());print(__version__)")

man:
	pandoc -s -t man MANUAL.rst -o passhole.1

dist:
	python setup.py sdist

pypi: dist man
	twine upload dist/passhole-$(version).tar.gz
