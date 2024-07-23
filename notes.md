# todo

- add `ph regen foobar -w` to regenerate password
- add `ph mkdir` command?
- make `ph edit foobar --field newfield` work with nonexisting fields
- make `ph grep slack` work for folders.  list all subentries/groups
- make `ph grep field` grep for fields
- add copy command
- [x] add `otp` as default field for `add` command

# ----------- command examples --------------

open acm

    ph ls @acm/

open all

    ph ls

open default

    ph show foobar/foo

type specific

    ph type @acm --prog dmenu

type all

    ph type

# ----------- finished converting ---------
open_database
show
grep
add
remove
edit
list_entries
type_entries
dump
move - interdatabase move disabled

# ----------- new prompt_open --------------
# actions
list_cached
get_from_cache
prompt_creds
open_from_file
open_from_cache

# stories
- if path in list_cached -> get_from_cache
- if path not in list_cached and no_cache -> open_from_file
- if path not in list_cached and not no_cache -> open_from_cache

if not path:
    error - db does not exist

if not no_cache and path in list_cached:
    get_from_cache

prompt_creds
if no_cache:
    open_from_file
else:
    open_from_cache


# ---------- new get_database ---------------
# arguments
keyfile
no_cache
no_password
database
all
path
# return
open_database(all=True)   ->   [('passhole', kp1), ('bar', kp2)]


# get_database
if database:
    prompt_creds
    return open_database(path, path)
else:
    exists_config
    read_config
    check_config
        - database

    if all:
        dbs = []
        for name in config:
            db = open_database(name, config[name][database])
            if section.default:
                dbs.prepend(db)
            else:
                dbs.append(db)
        return dbs
    # elif name:
    #     return open_database(name, config[name][database])
    elif path:
        name = get_database
        return open_database(name, config[name][database])
    else:
        for name in config:
            if section.default:
                return open_database(name, config[name][database])
        else:
            error - no default
