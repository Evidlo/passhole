1.9 - 2019-09-09
----------------
- use background thread for caching databases, removed `--gpgkey` option
- added `--no-cache` option to prevent background thread caching
- added `--fields` option to `add` command for custom fields
- display created/modified time in `show` output
- only open databases as needed, instead of all
- `type` now accepts 'name' option for choosing database to type from


1.8.2 - 2019-02-10
------------------
- auto generate config
- added dockerfiles for testing


1.8.0 - 2019-02-10
------------------
- removed `--no-keyfile`, `--no-cache` options.  these are implicitly given by omitting `--keyfile` and `--cache`
- added multi database support
- added configuration file at ~/.config/passhole.ini
