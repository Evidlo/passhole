1.10.1 - 2024-01-30
-------------------
- add `eval` command
- better totp handling

1.10.0 - 2023-09-08
-------------------

1.9.10 - 2023-09-05
-------------------

1.9.9 - 2022-06-21
------------------
- added --totp flag to `show` command
- added `restart` command

1.9.8 - 2022-04-22
------------------
- fix #51 - fix `--username` for type command
- allow database name to start with @

1.9.6 - 2021-05-22
------------------
- TOTP support

1.9.5 - 2021
------------------
- switch to podman for testing
- change default database and key location
- add 'kill' command
- allow 'init' to work noninteractively
- fix #46
- fix #42 - exit with error code 1 on error

1.9.4 - 2020-01-20
------------------
- add --cache-timeout

1.9.2 - 2019-01-18
------------------
- fix 'edit' protecting password text

1.9.1 - 2019-11-20
------------------
- catch pynput xorg error
- don't unlock all databases when access an entry

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
