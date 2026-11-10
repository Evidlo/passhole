

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
from passhole import passhole


class ShowTests(unittest.TestCase):

    def setUp(self):
        shutil.copy(os.path.join(base_dir, 'test.kdbx'), os.path.join(base_dir, '/change_creds.kdbx'))

class HelperTests(unittest.TestCase):

    def test_parse_path(self):
        db, path, type_ = passhole.parse_path(None)
        self.assertEqual((db, path, type_), (None, None, None))
        db, path, type_ = passhole.parse_path('/')
        self.assertEqual((db, path, type_), (None, [''], 'group'))
        db, path, type_ = passhole.parse_path('/test')
        self.assertEqual((db, path, type_), (None, ['test'], 'entry'))
        db, path, type_ = passhole.parse_path('@db/test')
        self.assertEqual((db, path, type_), ('db', ['test'], 'entry'))

class ParsePathEdgeTests(unittest.TestCase):

    def test_parse_bare_at_sign(self):
        # a bare '@' names no database; it must not produce an
        # empty-string database name
        self.assertEqual(passhole.parse_path('@'), (None, None, None))
        self.assertEqual(passhole.parse_path('@/'), (None, None, None))

    def test_parse_named_database(self):
        self.assertEqual(passhole.parse_path('@db'), ('db', None, 'database'))

if __name__ == '__main__':
    unittest.main()
