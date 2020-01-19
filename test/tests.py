

"""
Tests

  - show
    - human readable
    - specific field
  - add
    - password generation
  - remove
  - list
  - init
  - optional args
    - cache path
    - no cache
    - cache timeout
    - gpgkey
    - keyfile
    - no keyfile
    - db path
    - version
"""
import unittest


class ShowTests(unittest.TestCase):

    def setUp(self):
        shutil.copy(os.path.join(base_dir, 'test.kdbx'), os.path.join(base_dir, '/change_creds.kdbx'))
