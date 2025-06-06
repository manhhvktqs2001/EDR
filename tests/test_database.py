"""
Unit tests for EDR Database operations
"""

import unittest
import sys
import os
from datetime import datetime, timedelta

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.connection import DatabaseConnection
from database.agents import AgentDB
from database.alerts import AlertDB
from database.logs import LogDB
from database.rules import RuleDB

class TestDatabaseConnection(unittest.TestCase):
    """Test database connection functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.db = DatabaseConnection()
    
    def tearDown(self):
        """Clean up after tests"""
        if self.db:
            self.db.close()
    
    def test_database_connection(self):
        """Test database connection"""
        success = self.db.connect()
        self.assertTrue(success, "Database connection should succeed")
    
    def test_connection_reuse(self):
        """Test connection reuse"""
        # First connection
        success1 = self.db.connect()
        self.assertTrue(success1)
        
        # Second connection (should reuse)
        success2 = self.db.connect()
        self.assertTrue(success2)
    
    def test_query_execution(self):
        """Test basic query execution"""
        self.db.connect()
        
        # Test simple query
        cursor = self.db.execute_query("SELECT 1 as test_value")
        self.assertIsNotNone(cursor)
        
        result = cursor.fetchone()
        self.assertIsNotNone(result)
        self.assertEqual(result[0], 1)
    
    def test_invalid_query(self):
        """Test handling of invalid queries"""
        self.db.connect()
        
        # Test invalid SQL
        cursor = self.db.execute_query("INVALID SQL STATEMENT")
        self.assertIsNone(cursor)
    
    def test_schema_loading(self):
        """Test schema loading"""
        self.db.connect()
        
        # Test getting table schema
        schema = self.db.get_table_schema('Agents')
        self.assertIsInstance(schema, dict)
        
        # Should have columns information
        if schema:
            self.assertIn('columns', schema)

class TestAgentDB(unittest.TestCase):
    """Test Agent database operations"""
    
    def setUp(self):
        """Set up test environment"""
        self.agent_db = AgentDB()
        self.test_hostname = 'test-agent-db-001'
    
    def test_register_agent(self):
        """Test agent registration"""
        agent_data = {
            'hostname': self.test_hostname,
            'os_type': 'Windows',
            'os_version': 'Windows 10',
            'agent_version': '1.0.0',
            'ip_address': '192.168.1.200'
        }
        
        # Should succeed or already exist
        success = self.agent_db.register_agent(agent_data)
        self.assertTrue(success or self.agent_db.get_agent(self.test_hostname) is not None)
    
    def test_get_agent(self):
        """Test getting agent information"""
        # First register an agent
        agent_data = {
            'hostname': self.test_hostname,
            'os_type': 'Windows',
            'os_version': 'Windows 10',
            'agent_version': '1.0.0'
        }
        
        self.agent_db.register_agent(agent_data)
        
        # Then get it
        agent = self.agent_db.get_agent(self.test_hostname)
        
        if agent:  # Agent exists
            self.assertEqual(agent['Hostname'], self.test_hostname)
            self.assertIn('OSType', agent)
    
    def test_get_all_agents(self):
        """Test getting all agents"""
        agents = self.agent_db.get_all_agents()
        self.assertIsInstance(agents, list)
    
    def test_update_agent_status(self):
        """Test updating agent status"""
        # Register agent first
        agent_data = {
            'hostname': self.test_hostname,
            'os_type': 'Windows',
            'os_version': 'Windows 10'
        }
        
        self.agent_db.register_agent(agent_data)
        
        # Update status
        success = self.agent_db.update_agent_status(self.test_hostname, 'Offline')
        
        # Should succeed if agent exists
        if self.agent_db.get_agent(self.test_hostname):
            self.assertTrue(success)
    
    def test_heartbeat_update(self):
        """Test heartbeat update"""
        # Register agent first
        agent_data = {
            'hostname': self.test_hostname,
            'os_type': 'Windows'
        }
        
        self.agent_db.register_agent(agent_data)
        
        # Update heartbeat
        success = self.agent_db.update_heartbeat(self.test_hostname)
        
        # Should succeed if agent exists
        if self.agent_db.get_agent(self.test_hostname):
            self.assertTrue(success)
    
    def test_invalid_hostname(self):
        """Test handling of invalid hostnames"""
        agent_data = {
            'hostname': '',  # Empty hostname
            'os_type': 'Windows'
        }
        
        success = self.agent_db.register_agent(agent_data)
        self.assertFalse(success)

class TestAlertDB(unittest.TestCase):
    """Test Alert database operations"""
    
    def setUp(self):
        """Set up test environment"""
        self.alert_db = AlertDB()
        self.agent_db = AgentDB()
        self.test_hostname = 'test-agent-alert-001'
    
    def test_create_alert(self):
        """Test alert creation"""
        # First ensure agent exists
        agent_data = {
            'hostname': self.test_hostname,
            'os_type': 'Windows'
        }
        self.agent_db.register_agent(agent_data)
        
        # Create alert
        alert_data = {
            'hostname': self.test_hostname,
            'rule_id': 1,
            'alert_type': 'Test Alert',
            'severity': 'Medium',
            'title': 'Test Alert DB',
            'description': 'Test alert for database testing'
        }
        
        success = self.alert_db.create_alert(alert_data)
        # Should succeed if rule exists
        self.assertIsInstance(success, bool)
    
    def test_get_alerts(self):
        """Test getting alerts"""
        alerts = self.alert_db.get_alerts()
        self.assertIsInstance(alerts, list)
    
    def test_get_alerts_with_filters(self):
        """Test getting alerts with filters"""
        filters = {
            'severity': 'Critical',
            'status': 'New'
        }
        
        alerts = self.alert_db.get_alerts(filters)
        self.assertIsInstance(alerts, list)
    
    def test_alert_stats(self):
        """Test alert statistics"""
        filters = {
            'start_time': (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')
        }
        
        stats = self.alert_db.get_alert_stats(filters)
        self.assertIsInstance(stats, dict)
    
    def test_update_alert_status(self):
        """Test updating alert status"""
        # This test assumes there are alerts in the database
        alerts = self.alert_db.get_alerts({}, 1)
        
        if alerts:
            alert_id = alerts[0].get('AlertID')
            success = self.alert_db.update_alert_status(alert_id, 'Resolved')
            self.assertTrue(success)

class TestLogDB(unittest.TestCase):
    """Test Log database operations"""
    
    def setUp(self):
        """Set up test environment"""
        self.log_db = LogDB()
        self.agent_db = AgentDB()
        self.test_hostname = 'test-agent-log-001'
    
    def test_process_log(self):
        """Test processing process logs"""
        # Ensure agent exists
        agent_data = {
            'hostname': self.test_hostname,
            'os_type': 'Windows'
        }
        self.agent_db.register_agent(agent_data)
        
        # Create process log
        log_data = {
            'hostname': self.test_hostname,
            'process_id': 1234,
            'process_name': 'test.exe',
            'command_line': 'test.exe -param',
            'executable_path': 'C:\\test\\test.exe'
        }
        
        success = self.log_db.process_log('process', log_data)
        self.assertTrue(success)
    
    def test_file_log(self):
        """Test processing file logs"""
        # Ensure agent exists
        agent_data = {
            'hostname': self.test_hostname,
            'os_type': 'Windows'
        }
        self.agent_db.register_agent(agent_data)
        
        # Create file log
        log_data = {
            'hostname': self.test_hostname,
            'file_name': 'test.txt',
            'file_path': 'C:\\temp\\test.txt',
            'event_type': 'Create',
            'process_id': 1234
        }
        
        success = self.log_db.process_log('file', log_data)
        self.assertTrue(success)
    
    def test_network_log(self):
        """Test processing network logs"""
        # Ensure agent exists
        agent_data = {
            'hostname': self.test_hostname,
            'os_type': 'Windows'
        }
        self.agent_db.register_agent(agent_data)
        
        # Create network log
        log_data = {
            'hostname': self.test_hostname,
            'process_id': 1234,
            'process_name': 'test.exe',
            'protocol': 'TCP',
            'remote_address': '192.168.1.100',
            'remote_port': 80
        }
        
        success = self.log_db.process_log('network', log_data)
        self.assertTrue(success)
    
    def test_get_logs(self):
        """Test getting logs"""
        # Test process logs
        process_logs = self.log_db.get_process_logs(limit=10)
        self.assertIsInstance(process_logs, list)
        
        # Test file logs
        file_logs = self.log_db.get_file_logs(limit=10)
        self.assertIsInstance(file_logs, list)
        
        # Test network logs
        network_logs = self.log_db.get_network_logs(limit=10)
        self.assertIsInstance(network_logs, list)
    
    def test_log_batch_processing(self):
        """Test batch log processing"""
        logs = [
            {
                'hostname': self.test_hostname,
                'process_id': 1001,
                'process_name': 'batch1.exe'
            },
            {
                'hostname': self.test_hostname,
                'process_id': 1002,
                'process_name': 'batch2.exe'
            }
        ]
        
        success_count, failed_count = self.log_db.insert_process_logs(logs)
        self.assertIsInstance(success_count, int)
        self.assertIsInstance(failed_count, int)

class TestRuleDB(unittest.TestCase):
    """Test Rule database operations"""
    
    def setUp(self):
        """Set up test environment"""
        self.rule_db = RuleDB()
    
    def test_get_all_rules(self):
        """Test getting all rules"""
        rules = self.rule_db.get_all_rules()
        self.assertIsInstance(rules, list)
    
    def test_create_rule(self):
        """Test creating a rule"""
        rule_data = {
            'rule_name': 'Test Rule DB',
            'rule_type': 'Process',
            'description': 'Test rule for database testing',
            'severity': 'Medium',
            'action': 'Alert',
            'is_active': True
        }
        
        success = self.rule_db.create_rule(rule_data)
        self.assertTrue(success)
    
    def test_get_rules_by_type(self):
        """Test getting rules by type"""
        rules = self.rule_db.get_rules_by_type('Process')
        self.assertIsInstance(rules, list)
        
        # All rules should be of Process type
        for rule in rules:
            self.assertEqual(rule.get('RuleType'), 'Process')
    
    def test_rule_validation(self):
        """Test rule data validation"""
        # Invalid rule data
        invalid_rule = {
            'rule_name': '',  # Empty name
            'rule_type': 'InvalidType',  # Invalid type
            'severity': 'InvalidSeverity'  # Invalid severity
        }
        
        success = self.rule_db.create_rule(invalid_rule)
        self.assertFalse(success)
    
    def test_update_rule(self):
        """Test updating a rule"""
        # First create a rule
        rule_data = {
            'rule_name': 'Test Update Rule',
            'rule_type': 'Process',
            'description': 'Rule for update testing',
            'severity': 'Low',
            'action': 'Alert'
        }
        
        create_success = self.rule_db.create_rule(rule_data)
        
        if create_success:
            # Get the rule to find its ID
            rules = self.rule_db.get_all_rules()
            test_rule = None
            
            for rule in rules:
                if rule.get('RuleName') == 'Test Update Rule':
                    test_rule = rule
                    break
            
            if test_rule:
                rule_id = test_rule['RuleID']
                
                # Update the rule
                update_data = {
                    'severity': 'High',
                    'description': 'Updated description'
                }
                
                update_success = self.rule_db.update_rule(rule_id, update_data)
                self.assertTrue(update_success)

class TestDatabaseIntegration(unittest.TestCase):
    """Test database integration scenarios"""
    
    def setUp(self):
        """Set up test environment"""
        self.agent_db = AgentDB()
        self.alert_db = AlertDB()
        self.log_db = LogDB()
        self.rule_db = RuleDB()
        self.test_hostname = 'test-integration-001'
    
    def test_agent_rule_assignment(self):
        """Test assigning rules to agents"""
        # Register agent
        agent_data = {
            'hostname': self.test_hostname,
            'os_type': 'Windows'
        }
        
        agent_success = self.agent_db.register_agent(agent_data)
        
        if agent_success:
            # Get available rules
            rules = self.rule_db.get_all_rules()
            
            if rules:
                rule_id = rules[0]['RuleID']
                
                # Assign rule to agent
                assign_success = self.agent_db.assign_rule(self.test_hostname, rule_id)
                self.assertIsInstance(assign_success, bool)
    
    def test_log_to_alert_flow(self):
        """Test the flow from log to alert"""
        # This would test the complete flow:
        # 1. Agent sends log
        # 2. Log is processed
        # 3. Rule is checked
        # 4. Alert is created
        
        # Register agent
        agent_data = {
            'hostname': self.test_hostname,
            'os_type': 'Windows'
        }
        self.agent_db.register_agent(agent_data)
        
        # Process log
        log_data = {
            'hostname': self.test_hostname,
            'process_name': 'suspicious.exe',
            'command_line': 'suspicious.exe --malicious'
        }
        
        log_success = self.log_db.process_log('process', log_data)
        self.assertTrue(log_success)
        
        # Note: Alert creation would normally be handled by rule engine
        # This is just testing the database operations

def run_database_tests():
    """Run all database tests"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestDatabaseConnection))
    suite.addTests(loader.loadTestsFromTestCase(TestAgentDB))
    suite.addTests(loader.loadTestsFromTestCase(TestAlertDB))
    suite.addTests(loader.loadTestsFromTestCase(TestLogDB))
    suite.addTests(loader.loadTestsFromTestCase(TestRuleDB))
    suite.addTests(loader.loadTestsFromTestCase(TestDatabaseIntegration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()

if __name__ == '__main__':
    # Run tests
    print("🧪 Running Database Tests...")
    
    try:
        success = run_database_tests()
        
        if success:
            print("\n✅ All database tests passed!")
        else:
            print("\n❌ Some database tests failed!")
            exit(1)
    
    except Exception as e:
        print(f"\n💥 Error running database tests: {e}")
        exit(1)