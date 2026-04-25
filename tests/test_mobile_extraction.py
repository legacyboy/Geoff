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
