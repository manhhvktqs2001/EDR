"""
Unit tests for EDR API endpoints
"""

import unittest
import json
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from run_server import EDRServer
from database.connection import DatabaseConnection

class TestEDRAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Set up test environment"""
        cls.server = EDRServer()
        cls.app = cls.server.create_app()
        cls.app.config['TESTING'] = True
        cls.client = cls.app.test_client()
        
        # Register blueprints
        cls.server.register_blueprints()
        cls.server.setup_routes()
        cls.server.setup_error_handlers()
    
    def setUp(self):
        """Set up before each test"""
        self.headers = {'Content-Type': 'application/json'}
    
    def test_root_endpoint(self):
        """Test root endpoint"""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertIn('message', data)
        self.assertIn('EDR Server', data['message'])
    
    def test_health_endpoint(self):
        """Test health check endpoint"""
        response = self.client.get('/health')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertIn('status', data)
        self.assertIn('components', data)
    
    def test_agents_endpoint(self):
        """Test agents endpoint"""
        response = self.client.get('/agents')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertIn('status', data)
        self.assertEqual(data['status'], 'success')
        self.assertIn('data', data)
    
    def test_agents_summary(self):
        """Test agents summary endpoint"""
        response = self.client.get('/agents/summary')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertIn('status', data)
        self.assertIn('data', data)
        self.assertIn('total_agents', data['data'])
    
    def test_alerts_endpoint(self):
        """Test alerts endpoint"""
        response = self.client.get('/alerts')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertIn('status', data)
        self.assertEqual(data['status'], 'success')
        self.assertIn('data', data)
    
    def test_alerts_stats(self):
        """Test alerts statistics endpoint"""
        response = self.client.get('/alerts/stats')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertIn('status', data)
        self.assertIn('data', data)
    
    def test_rules_endpoint(self):
        """Test rules endpoint"""
        response = self.client.get('/rules')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertIn('status', data)
        self.assertEqual(data['status'], 'success')
        self.assertIn('data', data)
    
    def test_rules_types(self):
        """Test rule types endpoint"""
        response = self.client.get('/rules/types')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertIn('status', data)
        self.assertIn('data', data)
    
    def test_dashboard_summary(self):
        """Test dashboard summary endpoint"""
        response = self.client.get('/dashboard/summary')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertIn('status', data)
        self.assertIn('data', data)
        self.assertIn('agents', data['data'])
        self.assertIn('alerts', data['data'])
        self.assertIn('rules', data['data'])
    
    def test_logs_endpoint(self):
        """Test logs endpoint"""
        response = self.client.get('/logs')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertIn('status', data)
        self.assertEqual(data['status'], 'success')
        self.assertIn('data', data)
    
    def test_logs_stats(self):
        """Test logs statistics endpoint"""
        response = self.client.get('/logs/stats')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertIn('status', data)
        self.assertIn('data', data)
    
    def test_create_agent(self):
        """Test creating an agent"""
        agent_data = {
            'hostname': 'test-agent-001',
            'os_type': 'Windows',
            'os_version': 'Windows 10',
            'agent_version': '1.0.0',
            'ip_address': '192.168.1.100'
        }
        
        response = self.client.post('/agents/register', 
                                  data=json.dumps(agent_data),
                                  headers=self.headers)
        
        # Should succeed or already exist
        self.assertIn(response.status_code, [200, 201, 409])
    
    def test_create_rule(self):
        """Test creating a rule"""
        rule_data = {
            'rule_name': 'Test Rule API',
            'rule_type': 'Process',
            'description': 'Test rule created via API',
            'severity': 'Medium',
            'action': 'Alert',
            'is_active': True
        }
        
        response = self.client.post('/rules',
                                  data=json.dumps(rule_data),
                                  headers=self.headers)
        
        # Should succeed or already exist
        self.assertIn(response.status_code, [200, 201, 409])
    
    def test_create_alert(self):
        """Test creating an alert"""
        alert_data = {
            'hostname': 'test-agent-001',
            'rule_id': 1,
            'alert_type': 'Test Alert',
            'severity': 'Medium',
            'title': 'Test Alert via API',
            'description': 'This is a test alert created via API'
        }
        
        response = self.client.post('/alerts',
                                  data=json.dumps(alert_data),
                                  headers=self.headers)
        
        # Should succeed or fail with validation error
        self.assertIn(response.status_code, [200, 201, 400, 404])
    
    def test_filter_agents(self):
        """Test filtering agents"""
        # Test OS type filter
        response = self.client.get('/agents?os_type=Windows')
        self.assertEqual(response.status_code, 200)
        
        # Test status filter
        response = self.client.get('/agents?status=Online')
        self.assertEqual(response.status_code, 200)
        
        # Test limit
        response = self.client.get('/agents?limit=5')
        self.assertEqual(response.status_code, 200)
    
    def test_filter_alerts(self):
        """Test filtering alerts"""
        # Test severity filter
        response = self.client.get('/alerts?severity=Critical')
        self.assertEqual(response.status_code, 200)
        
        # Test status filter
        response = self.client.get('/alerts?status=New')
        self.assertEqual(response.status_code, 200)
        
        # Test time range
        response = self.client.get('/alerts?hours=24')
        self.assertEqual(response.status_code, 200)
    
    def test_filter_rules(self):
        """Test filtering rules"""
        # Test rule type filter
        response = self.client.get('/rules?rule_type=Process')
        self.assertEqual(response.status_code, 200)
        
        # Test severity filter
        response = self.client.get('/rules?severity=High')
        self.assertEqual(response.status_code, 200)
        
        # Test active filter
        response = self.client.get('/rules?is_active=true')
        self.assertEqual(response.status_code, 200)
    
    def test_invalid_endpoints(self):
        """Test invalid endpoints return 404"""
        response = self.client.get('/invalid-endpoint')
        self.assertEqual(response.status_code, 404)
        
        response = self.client.get('/agents/invalid-action')
        self.assertEqual(response.status_code, 404)
    
    def test_invalid_methods(self):
        """Test invalid HTTP methods"""
        # DELETE on read-only endpoint
        response = self.client.delete('/dashboard/summary')
        self.assertEqual(response.status_code, 405)
        
        # PUT without ID
        response = self.client.put('/agents')
        self.assertEqual(response.status_code, 405)
    
    def test_invalid_json(self):
        """Test invalid JSON data"""
        response = self.client.post('/agents/register',
                                  data='invalid-json',
                                  headers=self.headers)
        self.assertEqual(response.status_code, 400)
    
    def test_missing_required_fields(self):
        """Test missing required fields"""
        # Missing hostname
        agent_data = {
            'os_type': 'Windows'
        }
        
        response = self.client.post('/agents/register',
                                  data=json.dumps(agent_data),
                                  headers=self.headers)
        self.assertEqual(response.status_code, 400)
    
    def test_pagination(self):
        """Test pagination parameters"""
        response = self.client.get('/alerts?limit=10&offset=0')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertIn('data', data)
    
    def test_export_functionality(self):
        """Test export endpoints"""
        # Test alerts export
        response = self.client.get('/alerts/export?format=json')
        self.assertEqual(response.status_code, 200)
        
        # Test rules export
        response = self.client.get('/rules/export?format=json')
        self.assertEqual(response.status_code, 200)
        
        # Test logs export
        response = self.client.get('/logs/export')
        self.assertEqual(response.status_code, 200)
    
    def test_search_functionality(self):
        """Test search endpoints"""
        # Test dashboard search
        response = self.client.get('/dashboard/search?q=test')
        self.assertEqual(response.status_code, 200)
        
        # Test logs search
        response = self.client.get('/logs/search?q=process')
        self.assertEqual(response.status_code, 200)
    
    def test_bulk_operations(self):
        """Test bulk operations"""
        # Test bulk alert update
        bulk_data = {
            'alert_ids': [1, 2, 3],
            'action': 'mark_resolved'
        }
        
        response = self.client.post('/alerts/bulk-update',
                                  data=json.dumps(bulk_data),
                                  headers=self.headers)
        
        # Should handle gracefully even if alerts don't exist
        self.assertIn(response.status_code, [200, 404])
    
    def test_specific_agent_endpoints(self):
        """Test agent-specific endpoints"""
        hostname = 'test-agent'
        
        # Test agent details
        response = self.client.get(f'/agents/{hostname}')
        # 404 is acceptable if agent doesn't exist
        self.assertIn(response.status_code, [200, 404])
        
        # Test agent rules
        response = self.client.get(f'/agents/{hostname}/rules')
        self.assertIn(response.status_code, [200, 404])
        
        # Test agent logs
        response = self.client.get(f'/logs/agents/{hostname}')
        self.assertIn(response.status_code, [200, 404])
    
    def test_dashboard_widgets(self):
        """Test dashboard widget endpoints"""
        response = self.client.get('/dashboard/widgets')
        self.assertEqual(response.status_code, 200)
        
        response = self.client.get('/dashboard/metrics')
        self.assertEqual(response.status_code, 200)
        
        response = self.client.get('/dashboard/timeline')
        self.assertEqual(response.status_code, 200)
    
    def test_content_types(self):
        """Test different content types"""
        # JSON response
        response = self.client.get('/agents', headers={'Accept': 'application/json'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content_type, 'application/json')
        
        # CSV export
        response = self.client.get('/logs/export')
        self.assertEqual(response.status_code, 200)
        self.assertIn('text/csv', response.content_type)

class TestAPIErrorHandling(unittest.TestCase):
    """Test API error handling"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment"""
        cls.server = EDRServer()
        cls.app = cls.server.create_app()
        cls.app.config['TESTING'] = True
        cls.client = cls.app.test_client()
        
        cls.server.register_blueprints()
        cls.server.setup_routes()
        cls.server.setup_error_handlers()
    
    def test_database_error_handling(self):
        """Test database error scenarios"""
        # This would require mocking database failures
        pass
    
    def test_validation_errors(self):
        """Test input validation errors"""
        # Invalid data types
        invalid_data = {
            'hostname': 123,  # Should be string
            'os_type': 'InvalidOS'  # Should be valid OS
        }
        
        response = self.client.post('/agents/register',
                                  data=json.dumps(invalid_data),
                                  headers={'Content-Type': 'application/json'})
        
        self.assertEqual(response.status_code, 400)
    
    def test_rate_limiting(self):
        """Test rate limiting (if implemented)"""
        # Would require implementing rate limiting first
        pass

class TestAPIPerformance(unittest.TestCase):
    """Test API performance"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment"""
        cls.server = EDRServer()
        cls.app = cls.server.create_app()
        cls.app.config['TESTING'] = True
        cls.client = cls.app.test_client()
        
        cls.server.register_blueprints()
        cls.server.setup_routes()
        cls.server.setup_error_handlers()
    
    def test_response_times(self):
        """Test API response times"""
        import time
        
        endpoints = [
            '/',
            '/health',
            '/agents',
            '/alerts',
            '/rules',
            '/dashboard/summary'
        ]
        
        for endpoint in endpoints:
            start_time = time.time()
            response = self.client.get(endpoint)
            end_time = time.time()
            
            response_time = end_time - start_time
            
            # Response should be under 5 seconds
            self.assertLess(response_time, 5.0, 
                          f"Endpoint {endpoint} took {response_time:.2f}s")
            self.assertEqual(response.status_code, 200)
    
    def test_large_datasets(self):
        """Test handling of large datasets"""
        # Test with large limit
        response = self.client.get('/alerts?limit=10000')
        self.assertEqual(response.status_code, 200)
        
        response = self.client.get('/logs?limit=5000')
        self.assertEqual(response.status_code, 200)

def run_api_tests():
    """Run all API tests"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestEDRAPI))
    suite.addTests(loader.loadTestsFromTestCase(TestAPIErrorHandling))
    suite.addTests(loader.loadTestsFromTestCase(TestAPIPerformance))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()

if __name__ == '__main__':
    # Run tests
    success = run_api_tests()
    
    if success:
        print("\n✅ All API tests passed!")
    else:
        print("\n❌ Some API tests failed!")
        exit(1)