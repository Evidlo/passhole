Passhole
========

Passhole is a simple CLI and dmenu interface for KeePass 1.x (v3) and 2.x (v4) files.

Passhole allows you to edit and generate passwords much in the same way as the popular `pass`_ utility.

.. _pass: https://www.passwordstore.org

Passhole can also generate `correct horse battery staple`_ style passwords, which have plenty of entropy (when using 5 or more words) and are easier to type out manually than random alphanumeric passwords.

.. _correct horse battery staple: http://xkcd.com/936

Dependencies
------------

- PyUserInput
- pykeepass

Installation
------------

Install through pip

.. code:: bash

   pip install passhole

Example Usage
--------------

.. code:: bash

   # initialize the database
   >>> passhole init
   Creating database at /home/evan/.passhole.kdbx
   Enter your desired database password
   Password: 
   Confirm:

   # add a new entry with manual created password
   >>> passhole add github
   Username: Evidlo
   Password: 
   Confirm: 
   URL: github.com

   # add an entry with a generated alphanumeric password
   >>> passhole add neopets -a
   Username: Evidlo
   URL: neopets.com

   # add a new group
   >>> passhole add social/
   
   # add an entry to `social/` with a 32 character password (alphanumeric + symbols)
   >>> passhole add social/facebook -s 32

   # add an entry to `social/` with a correct-horse-battery-staple type password
   >>> passhole add social/twitter -w

   # list all entries
   >>> passhole list
   github
   neopets
   [social]
   ├── facebook
   └── twitter

   # display contents of entry
   >>> passhole show social/twitter
   Title: twitter
   Username: Evidlo
   Password: inns-ambien-travelling-throw-force
   URL: twitter.com

   # select entry using dmenu, then send password to keyboard
   >>> passhole dmenu dmenu
   inns-ambien-travelling-throw-force

   # select entry using dmenu, then send username and password to keyboard, separated by a tab
   >>> passhole dmenu dmenu --tabbed
   Evidlo	inns-ambien-travelling-throw-force


  
