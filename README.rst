Passhole
========

``passhole`` is a CLI interface for KeePass 1.x (v3) and 2.x (v4) databases with support for dmenu inspired by `pass`_.

.. _pass: https://www.passwordstore.org

Features
------------

With ``passhole``, you can:

- add existing passwords
- generate new passwords
- autofill selected forms via keyboard shortcut (using the ``type`` command)
- generate `correct horse battery staple`_ style passwords

.. _correct horse battery staple: http://xkcd.com/936

``passhole`` makes use of gpg-agent to securely cache your database password for a few minutes.

See below for examples and the `manual`_ for a complete list of commands and options.

.. _manual: MANUAL.rst

.. image:: https://i.imgur.com/U7q5jxJ.gif

Setup
------------

.. code:: bash

   pip install passhole
   ph init

Example Usage
--------------

.. code:: bash

   # add a new entry with manually created password
   >>> ph add github
   Username: Evidlo
   Password: 
   Confirm: 
   URL: github.com

   # add an entry with a generated alphanumeric password
   >>> ph add neopets -a
   Username: Evidlo
   URL: neopets.com

   # add a new group
   >>> ph add social/
   
   # add an entry to `social/` with a 32 character password (alphanumeric + symbols)
   >>> ph add social/facebook -s 32
   Username: evan@evanw.org
   URL: facebook.com

   # add an entry to `social/` with a correct-horse-battery-staple type password
   >>> ph add social/twitter -w
   Username: evan@evanw.org
   URL: twitter.com

   # list all entries
   >>> ph list
   github
   neopets
   [social]
   ├── facebook
   └── twitter

   # display contents of entry
   >>> ph show social/twitter
   Title: twitter
   Username: Evidlo
   Password: inns.ambien.travelling.throw.force
   URL: twitter.com

   # retrieve contents of specific field for use in scripts
   >>> ph show social/twitter --field password
   inns.ambien.travelling.throw.force

Example i3wm config for filling forms.

.. code:: bash

   # select entry using dmenu, then send password to keyboard
   bindsym $mod+p exec ph type dmenu
   # select entry using dmenu, then send username + password to keyboard
   bindsym $mod+Shift+p exec ph type dmenu --tabbed


