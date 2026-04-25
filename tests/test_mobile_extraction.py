#!/usr/bin/env python3
"""Tests for mobile device user extraction in DeviceDiscovery."""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock
from device_discovery import DeviceDiscovery


@pytest.fixture
def discovery():
    return DeviceDiscovery(Mock())


class TestDeviceInfoParser:
    """Test Cellebrite DeviceInfo.txt parsing."""
    
    def test_extract_owner_from_deviceinfo(self, discovery):
        dev = {"metadata": {}}
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Device Model:iPhone 11 (N104AP)\n")
            f.write("OS Version:iOS 17.1\n")
            f.write("Device owner:John's iPhone\n")
            f.write("Vendor:Apple\n")
            f.flush()
            
            discovery._enrich_from_deviceinfo(dev, f.name)
        
        assert dev["owner"] == "John"
        assert dev["owner_confidence"] == "HIGH"
        assert dev["device_type"] == "ios_mobile"
        assert dev["metadata"]["vendor"] == "Apple"
    
    def test_extract_owner_with_smart_quotes(self, discovery):
        dev = {"metadata": {}}
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Device owner:This Is\u2019s iPhone\n")
            f.flush()
            
            discovery._enrich_from_deviceinfo(dev, f.name)
        
        assert dev["owner"] == "This Is"
        assert dev["owner_confidence"] == "HIGH"


class TestBuildPropParser:
    """Test Android build.prop parsing."""
    
    def test_extract_from_build_prop(self, discovery):
        dev = {"metadata": {}}
        with tempfile.NamedTemporaryFile(mode='w', suffix='.prop', delete=False) as f:
            f.write("ro.product.model=Pixel 7\n")
            f.write("ro.build.version.release=14\n")
            f.write("ro.build.user=android-build\n")
            f.write("ro.product.manufacturer=Google\n")
            f.flush()
            
            discovery._extract_build_prop(dev, f.name)
        
        assert dev["device_type"] == "Pixel 7"
        assert dev["os_version"] == "14"
        assert dev["os_type"] == "android"
        assert dev["owner"] == "android-build"
        assert dev["owner_confidence"] == "MEDIUM"
    
    def test_build_prop_missing_file(self, discovery):
        dev = {"metadata": {}}
        discovery._extract_build_prop(dev, "/nonexistent/build.prop")
        assert "owner" not in dev or dev.get("owner") is None


class TestIOSAccounts:
    """Test iOS account extraction."""
    
    def test_extract_ios_accounts_no_db(self, discovery):
        dev = {"metadata": {}}
        with tempfile.TemporaryDirectory() as tmpdir:
            discovery._extract_ios_accounts(dev, tmpdir)
            assert dev.get("user_accounts") is None or dev["user_accounts"] == []


class TestAndroidUsers:
    """Test Android user extraction."""
    
    def test_extract_android_users_no_db(self, discovery):
        dev = {"metadata": {}}
        with tempfile.TemporaryDirectory() as tmpdir:
            discovery._extract_android_users(dev, tmpdir)
            assert dev.get("user_accounts") is None or dev["user_accounts"] == []


class TestIOSKeychain:
    """Test iOS keychain extraction."""
    
    def test_extract_ios_keychain_no_db(self, discovery):
        dev = {"metadata": {}}
        with tempfile.TemporaryDirectory() as tmpdir:
            discovery._extract_ios_keychain(dev, tmpdir)
            assert "keychain_entries" not in dev["metadata"]
    
    def test_extract_ios_keychain_with_db(self, discovery, tmp_path):
        """Test keychain extraction with mocked SQLite DB."""
        import sqlite3
        
        # Create a mock keychain-2.db
        db_path = tmp_path / "keychain-2.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE genp (service TEXT, account TEXT)")
        conn.execute("INSERT INTO genp VALUES ('com.apple.mail', 'user@example.com')")
        conn.execute("INSERT INTO genp VALUES ('com.apple.mobilemail', 'test@icloud.com')")
        conn.commit()
        conn.close()
        
        dev = {"metadata": {}}
        discovery._extract_ios_keychain(dev, str(tmp_path))
        
        assert "keychain_entries" in dev["metadata"]
        assert len(dev["metadata"]["keychain_entries"]) == 2
        assert dev["metadata"]["keychain_entries"][0]["service"] == "com.apple.mail"


class TestIOSPlistAccounts:
    """Test iOS plist Apple ID extraction."""
    
    def test_extract_ios_plist_accounts_no_id(self, discovery):
        dev = {"metadata": {}}
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.plist', delete=False) as f:
            import plistlib
            plistlib.dump({"Device Name": "Test iPhone"}, f)
            f.flush()
            
            discovery._extract_ios_plist_accounts(dev, f.name)
        
        assert "apple_id" not in dev["metadata"]
    
    def test_extract_ios_plist_accounts_with_apple_id(self, discovery):
        dev = {"metadata": {}}
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.plist', delete=False) as f:
            import plistlib
            plistlib.dump({
                "Device Name": "Test iPhone",
                "AppleID": "user@example.com"
            }, f)
            f.flush()
            
            discovery._extract_ios_plist_accounts(dev, f.name)
        
        assert dev["metadata"]["apple_id"] == "user@example.com"
    
    def test_extract_ios_plist_accounts_with_itunes_id(self, discovery):
        dev = {"metadata": {}}
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.plist', delete=False) as f:
            import plistlib
            plistlib.dump({
                "Device Name": "Test iPhone",
                "iTunesAppleID": "itunes@example.com"
            }, f)
            f.flush()
            
            discovery._extract_ios_plist_accounts(dev, f.name)
        
        assert dev["metadata"]["apple_id"] == "itunes@example.com"


class TestAndroidContacts:
    """Test Android contacts extraction."""
    
    def test_extract_android_contacts_no_db(self, discovery):
        dev = {"metadata": {}}
        with tempfile.TemporaryDirectory() as tmpdir:
            discovery._extract_android_contacts(dev, tmpdir)
            assert "contacts" not in dev["metadata"]
    
    def test_extract_android_contacts_with_db(self, discovery, tmp_path):
        """Test contacts extraction with mocked SQLite DB."""
        import sqlite3
        
        # Create a mock contacts2.db
        db_path = tmp_path / "contacts2.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE data (display_name TEXT, phone_number TEXT)")
        conn.execute("INSERT INTO data VALUES ('John Doe', '555-1234')")
        conn.execute("INSERT INTO data VALUES ('Jane Smith', '555-5678')")
        conn.execute("INSERT INTO data VALUES ('Bob Wilson', '555-9999')")
        conn.commit()
        conn.close()
        
        dev = {"metadata": {}}
        discovery._extract_android_contacts(dev, str(tmp_path))
        
        assert "contacts" in dev["metadata"]
        assert len(dev["metadata"]["contacts"]) == 3
        assert dev["metadata"]["contacts"][0]["name"] == "John Doe"
        assert dev["metadata"]["contacts"][0]["phone"] == "555-1234"
    
    def test_extract_android_contacts_limit_50(self, discovery, tmp_path):
        """Test that contacts are limited to 50 entries."""
        import sqlite3
        
        # Create a mock contacts2.db with 60 entries
        db_path = tmp_path / "contacts2.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE data (display_name TEXT, phone_number TEXT)")
        for i in range(60):
            conn.execute("INSERT INTO data VALUES (?, ?)", (f"Contact {i}", f"555-{i:04d}"))
        conn.commit()
        conn.close()
        
        dev = {"metadata": {}}
        discovery._extract_android_contacts(dev, str(tmp_path))
        
        assert "contacts" in dev["metadata"]
        assert len(dev["metadata"]["contacts"]) == 50
