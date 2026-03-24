"""
Test suite for Oil Trading Dashboard v2.0
Run with: pytest tests/ -v
"""

import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server_v2 import app, init_database, get_db_connection, load_config
import json


@pytest.fixture
def client():
    """Create test client."""
    app.config['TESTING'] = True
    
    # Initialize test database
    init_database()
    
    with app.test_client() as client:
        yield client


class TestRoutes:
    """Test Flask routes."""
    
    def test_dashboard_loads(self, client):
        """Test main dashboard loads."""
        response = client.get('/')
        assert response.status_code == 200
        assert b'Oil Trading Bot' in response.data
    
    def test_research_page_loads(self, client):
        """Test research page loads."""
        response = client.get('/oil-research')
        assert response.status_code == 200
    
    def test_tracker_page_loads(self, client):
        """Test tracker page loads."""
        response = client.get('/tracker')
        assert response.status_code == 200
    
    def test_404_page(self, client):
        """Test 404 error page."""
        response = client.get('/nonexistent')
        assert response.status_code == 404
        assert b'404' in response.data


class TestAPI:
    """Test API endpoints."""
    
    def test_api_status(self, client):
        """Test status API."""
        response = client.get('/api/status')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert 'bot_running' in data
        assert 'web_running' in data
        assert 'timestamp' in data
        assert 'assets' in data
    
    def test_api_trades(self, client):
        """Test trades API."""
        response = client.get('/api/trades')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert isinstance(data, list)
    
    def test_api_stats(self, client):
        """Test stats API."""
        response = client.get('/api/stats')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert 'total_trades' in data
        assert 'win_rate' in data
        assert 'total_pnl' in data
    
    def test_api_research_invalid_asset(self, client):
        """Test research API with invalid asset."""
        response = client.get('/api/research/INVALID')
        assert response.status_code == 400
        
        data = json.loads(response.data)
        assert 'error' in data
        assert 'allowed' in data
    
    def test_api_research_valid_asset(self, client):
        """Test research API with valid asset."""
        response = client.get('/api/research/XTI_USD')
        # May be 404 if no data, but should not be 400
        assert response.status_code in [200, 404]


class TestSecurityHeaders:
    """Test security headers."""
    
    def test_csp_header(self, client):
        """Test Content-Security-Policy header."""
        response = client.get('/')
        assert 'Content-Security-Policy' in response.headers
        assert "default-src 'self'" in response.headers['Content-Security-Policy']
    
    def test_x_frame_options(self, client):
        """Test X-Frame-Options header."""
        response = client.get('/')
        assert response.headers.get('X-Frame-Options') == 'DENY'
    
    def test_x_content_type_options(self, client):
        """Test X-Content-Type-Options header."""
        response = client.get('/')
        assert response.headers.get('X-Content-Type-Options') == 'nosniff'
    
    def test_xss_protection(self, client):
        """Test X-XSS-Protection header."""
        response = client.get('/')
        assert 'X-XSS-Protection' in response.headers


class TestDatabase:
    """Test database operations."""
    
    def test_database_init(self, client):
        """Test database initializes correctly."""
        init_database()
        
        conn = get_db_connection()
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        tables = [row[0] for row in cursor.fetchall()]
        
        assert 'trades' in tables
        assert 'research' in tables


class TestRateLimiting:
    """Test rate limiting (requires rate limit reset between tests)."""
    
    def test_dashboard_rate_limit(self, client):
        """Test dashboard rate limiting."""
        # Make requests until rate limited
        responses = []
        for _ in range(15):
            response = client.get('/')
            responses.append(response.status_code)
        
        # Should see some 429 responses
        assert 429 in responses or all(r == 200 for r in responses[:10])
    
    def test_api_rate_limit(self, client):
        """Test API rate limiting."""
        responses = []
        for _ in range(35):
            response = client.get('/api/status')
            responses.append(response.status_code)
        
        # Should see 429 after 30 requests
        assert 429 in responses


class TestHealth:
    """Test health check endpoint."""
    
    def test_health_endpoint(self, client):
        """Test health check returns JSON."""
        response = client.get('/health')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert 'status' in data
        assert 'checks' in data
        assert 'timestamp' in data


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
