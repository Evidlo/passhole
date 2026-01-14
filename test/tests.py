

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
  - expiration
    - parse_expiry_date
    - show expiry
    - add with expiry
    - edit expiry
    - expired command
"""
import unittest
import os
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock
from io import StringIO

from passhole import passhole


base_dir = os.path.dirname(os.path.realpath(__file__))


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


class ParseExpiryDateTests(unittest.TestCase):
    """Tests for the parse_expiry_date function"""

    def test_parse_expiry_date_none(self):
        """Test that None input returns None"""
        result = passhole.parse_expiry_date(None)
        self.assertIsNone(result)

    def test_parse_expiry_date_empty_string(self):
        """Test that empty string returns None"""
        result = passhole.parse_expiry_date('')
        self.assertIsNone(result)

    def test_parse_expiry_date_never(self):
        """Test that 'never' returns None"""
        result = passhole.parse_expiry_date('never')
        self.assertIsNone(result)

    def test_parse_expiry_date_never_case_insensitive(self):
        """Test that 'NEVER' (uppercase) returns None"""
        result = passhole.parse_expiry_date('NEVER')
        self.assertIsNone(result)

    def test_parse_expiry_date_iso_date(self):
        """Test parsing ISO format date (date only)"""
        result = passhole.parse_expiry_date('2026-12-31')
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2026)
        self.assertEqual(result.month, 12)
        self.assertEqual(result.day, 31)
        self.assertEqual(result.hour, 23)
        self.assertEqual(result.minute, 59)
        self.assertEqual(result.second, 59)
        self.assertIsNotNone(result.tzinfo)

    def test_parse_expiry_date_iso_datetime(self):
        """Test parsing ISO format datetime"""
        result = passhole.parse_expiry_date('2026-06-15T14:30:00')
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2026)
        self.assertEqual(result.month, 6)
        self.assertEqual(result.day, 15)
        self.assertEqual(result.hour, 14)
        self.assertEqual(result.minute, 30)
        self.assertEqual(result.second, 0)

    def test_parse_expiry_date_relative_days(self):
        """Test parsing relative days format (+30d)"""
        now = datetime.now(timezone.utc)
        result = passhole.parse_expiry_date('+30d')
        self.assertIsNotNone(result)
        # Allow 1 second tolerance for test execution time
        expected = now + timedelta(days=30)
        self.assertAlmostEqual(result.timestamp(), expected.timestamp(), delta=2)

    def test_parse_expiry_date_relative_weeks(self):
        """Test parsing relative weeks format (+2w)"""
        now = datetime.now(timezone.utc)
        result = passhole.parse_expiry_date('+2w')
        self.assertIsNotNone(result)
        expected = now + timedelta(weeks=2)
        self.assertAlmostEqual(result.timestamp(), expected.timestamp(), delta=2)

    def test_parse_expiry_date_relative_months(self):
        """Test parsing relative months format (+6m)"""
        now = datetime.now(timezone.utc)
        result = passhole.parse_expiry_date('+6m')
        self.assertIsNotNone(result)
        expected = now + timedelta(days=6 * 30)
        self.assertAlmostEqual(result.timestamp(), expected.timestamp(), delta=2)

    def test_parse_expiry_date_relative_years(self):
        """Test parsing relative years format (+1y)"""
        now = datetime.now(timezone.utc)
        result = passhole.parse_expiry_date('+1y')
        self.assertIsNotNone(result)
        expected = now + timedelta(days=365)
        self.assertAlmostEqual(result.timestamp(), expected.timestamp(), delta=2)

    def test_parse_expiry_date_invalid_relative_format(self):
        """Test that invalid relative format exits"""
        with self.assertRaises(SystemExit):
            passhole.parse_expiry_date('+30x')

    def test_parse_expiry_date_invalid_date_format(self):
        """Test that invalid date format exits"""
        with self.assertRaises(SystemExit):
            passhole.parse_expiry_date('not-a-date')

    def test_parse_expiry_date_timezone_aware(self):
        """Test that result is timezone-aware"""
        result = passhole.parse_expiry_date('2026-12-31')
        self.assertIsNotNone(result.tzinfo)

    def test_parse_expiry_date_relative_single_digit(self):
        """Test parsing single digit relative format (+5d)"""
        now = datetime.now(timezone.utc)
        result = passhole.parse_expiry_date('+5d')
        self.assertIsNotNone(result)
        expected = now + timedelta(days=5)
        self.assertAlmostEqual(result.timestamp(), expected.timestamp(), delta=2)

    def test_parse_expiry_date_relative_large_number(self):
        """Test parsing large number relative format (+365d)"""
        now = datetime.now(timezone.utc)
        result = passhole.parse_expiry_date('+365d')
        self.assertIsNotNone(result)
        expected = now + timedelta(days=365)
        self.assertAlmostEqual(result.timestamp(), expected.timestamp(), delta=2)


class ExpirationIntegrationTests(unittest.TestCase):
    """Integration tests for expiration functionality with actual database"""

    def setUp(self):
        """Create a temporary database for testing"""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, 'test.kdbx')
        # Copy the blank database template
        template_db = os.path.join(os.path.dirname(base_dir), 'passhole', 'blank.kdbx')
        shutil.copy(template_db, self.db_path)

        # Open and set up the database with a known password
        from pykeepass import PyKeePass
        self.kp = PyKeePass(self.db_path, password='password')
        self.kp.password = 'testpassword'
        self.kp.save()

    def tearDown(self):
        """Clean up temporary files"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_entry_expiration_set(self):
        """Test setting expiration on an entry"""
        from pykeepass import PyKeePass
        kp = PyKeePass(self.db_path, password='testpassword')

        # Add an entry
        entry = kp.add_entry(kp.root_group, 'test_entry', 'user', 'pass')

        # Set expiration
        expiry_time = datetime.now(timezone.utc) + timedelta(days=30)
        entry.expires = True
        entry.expiry_time = expiry_time
        kp.save()

        # Reload and verify
        kp2 = PyKeePass(self.db_path, password='testpassword')
        entry2 = kp2.find_entries(title='test_entry', first=True)
        self.assertTrue(entry2.expires)
        self.assertIsNotNone(entry2.expiry_time)

    def test_entry_expiration_disabled(self):
        """Test disabling expiration on an entry"""
        from pykeepass import PyKeePass
        kp = PyKeePass(self.db_path, password='testpassword')

        # Add an entry with expiration
        entry = kp.add_entry(kp.root_group, 'test_entry', 'user', 'pass')
        entry.expires = True
        entry.expiry_time = datetime.now(timezone.utc) + timedelta(days=30)
        kp.save()

        # Disable expiration
        kp2 = PyKeePass(self.db_path, password='testpassword')
        entry2 = kp2.find_entries(title='test_entry', first=True)
        entry2.expires = False
        kp2.save()

        # Reload and verify
        kp3 = PyKeePass(self.db_path, password='testpassword')
        entry3 = kp3.find_entries(title='test_entry', first=True)
        self.assertFalse(entry3.expires)

    def test_entry_expired_check(self):
        """Test checking if an entry is expired"""
        from pykeepass import PyKeePass
        kp = PyKeePass(self.db_path, password='testpassword')

        # Add an expired entry
        entry = kp.add_entry(kp.root_group, 'expired_entry', 'user', 'pass')
        entry.expires = True
        entry.expiry_time = datetime.now(timezone.utc) - timedelta(days=1)
        kp.save()

        # Reload and check
        kp2 = PyKeePass(self.db_path, password='testpassword')
        entry2 = kp2.find_entries(title='expired_entry', first=True)
        self.assertTrue(entry2.expires)
        self.assertTrue(entry2.expiry_time <= datetime.now(timezone.utc))

    def test_entry_expiring_soon_check(self):
        """Test checking if an entry is expiring soon"""
        from pykeepass import PyKeePass
        kp = PyKeePass(self.db_path, password='testpassword')

        # Add an entry expiring in 7 days
        entry = kp.add_entry(kp.root_group, 'expiring_soon', 'user', 'pass')
        entry.expires = True
        entry.expiry_time = datetime.now(timezone.utc) + timedelta(days=7)
        kp.save()

        # Reload and check
        kp2 = PyKeePass(self.db_path, password='testpassword')
        entry2 = kp2.find_entries(title='expiring_soon', first=True)
        self.assertTrue(entry2.expires)
        # Check it's within 30 days
        self.assertTrue(entry2.expiry_time <= datetime.now(timezone.utc) + timedelta(days=30))
        # But not expired yet
        self.assertTrue(entry2.expiry_time > datetime.now(timezone.utc))


class ExpiredCommandTests(unittest.TestCase):
    """Tests for the expired command argument parsing"""

    def test_expired_parser_exists(self):
        """Test that expired command is registered in parser"""
        parser = passhole.create_parser()
        # This should not raise an error
        args = parser.parse_args(['expired'])
        self.assertEqual(args.func, passhole.expired)

    def test_expired_parser_days_option(self):
        """Test that --days option is parsed correctly"""
        parser = passhole.create_parser()
        args = parser.parse_args(['expired', '--days', '30'])
        self.assertEqual(args.days, 30)

    def test_expired_parser_days_short_option(self):
        """Test that -d short option is parsed correctly"""
        parser = passhole.create_parser()
        args = parser.parse_args(['expired', '-d', '14'])
        self.assertEqual(args.days, 14)

    def test_expired_parser_default_days_none(self):
        """Test that default days is None"""
        parser = passhole.create_parser()
        args = parser.parse_args(['expired'])
        self.assertIsNone(args.days)


class ShowExpiryTests(unittest.TestCase):
    """Tests for show command expiry option"""

    def test_show_parser_expiry_option(self):
        """Test that --expiry option is registered"""
        parser = passhole.create_parser()
        args = parser.parse_args(['show', 'test/entry', '--expiry'])
        self.assertTrue(args.expiry)

    def test_show_parser_expiry_default_false(self):
        """Test that --expiry defaults to False"""
        parser = passhole.create_parser()
        args = parser.parse_args(['show', 'test/entry'])
        self.assertFalse(args.expiry)


class AddExpiresTests(unittest.TestCase):
    """Tests for add command expires option"""

    def test_add_parser_expires_option(self):
        """Test that --expires option is registered"""
        parser = passhole.create_parser()
        args = parser.parse_args(['add', 'test/entry', '--expires', '2026-12-31'])
        self.assertEqual(args.expires, '2026-12-31')

    def test_add_parser_expires_relative(self):
        """Test that --expires with relative date is accepted"""
        parser = passhole.create_parser()
        args = parser.parse_args(['add', 'test/entry', '--expires', '+30d'])
        self.assertEqual(args.expires, '+30d')

    def test_add_parser_expires_default_none(self):
        """Test that --expires defaults to None"""
        parser = passhole.create_parser()
        args = parser.parse_args(['add', 'test/entry'])
        self.assertIsNone(args.expires)


class EditExpiresTests(unittest.TestCase):
    """Tests for edit command expires option"""

    def test_edit_parser_expires_option(self):
        """Test that --expires option is registered"""
        parser = passhole.create_parser()
        args = parser.parse_args(['edit', 'test/entry', '--expires', '2026-12-31'])
        self.assertEqual(args.expires, '2026-12-31')

    def test_edit_parser_expires_never(self):
        """Test that --expires with 'never' is accepted"""
        parser = passhole.create_parser()
        args = parser.parse_args(['edit', 'test/entry', '--expires', 'never'])
        self.assertEqual(args.expires, 'never')

    def test_edit_parser_expires_default_none(self):
        """Test that --expires defaults to None"""
        parser = passhole.create_parser()
        args = parser.parse_args(['edit', 'test/entry'])
        self.assertIsNone(args.expires)


if __name__ == '__main__':
    unittest.main()
