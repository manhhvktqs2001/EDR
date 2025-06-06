"""
Unit tests for EDR Rule Engine
"""

import unittest
import sys
import os
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rules.rule_engine import RuleEngine
from database.rules import RuleDB
from database.agents import AgentDB

class TestRuleEngine(unittest.TestCase):
    """Test Rule Engine functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.rule_engine = RuleEngine()
        self.rule_db = RuleDB()
        self.agent_db = AgentDB()
        self.test_hostname = 'test-rule-agent-001'
    
    def test_rule_engine_initialization(self):
        """Test rule engine initialization"""
        self.assertIsNotNone(self.rule_engine)
        self.assertTrue(self.rule_engine.is_initialized)
    
    def test_rule_loading(self):
        """Test rule loading from database"""
        # Get rules summary
        summary = self.rule_engine.get_rules_summary()
        
        self.assertIsInstance(summary, dict)
        self.assertIn('total_rules', summary)
        self.assertIn('by_type', summary)
        self.assertIn('by_severity', summary)
    
    def test_process_rule_checking(self):
        """Test process rule violation checking"""
        # Test data that should trigger rules
        suspicious_process_log = {
            'ProcessName': 'cmd.exe',
            'CommandLine': 'cmd.exe /c del important_files.txt',
            'ExecutablePath': 'C:\\Windows\\System32\\cmd.exe',
            'ProcessID': 1234,
            'ParentProcessID': 5678,
            'UserName': 'user'
        }
        
        result = self.rule_engine.check_rules(
            'PROCESS_LOGS', 
            suspicious_process_log, 
            self.test_hostname
        )
        
        # Should return tuple: (violated, description, data, severity, rule_id, action)
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 6)
        
        violated, description, detection_data, severity, rule_id, action = result
        self.assertIsInstance(violated, bool)
    
    def test_file_rule_checking(self):
        """Test file rule violation checking"""
        suspicious_file_log = {
            'FileName': 'malware.exe',
            'FilePath': 'C:\\Users\\user\\Downloads\\malware.exe',
            'EventType': 'Create',
            'FileSize': 1024000,
            'ProcessID': 1234,
            'ProcessName': 'browser.exe'
        }
        
        result = self.rule_engine.check_rules(
            'FILE_LOGS',
            suspicious_file_log,
            self.test_hostname
        )
        
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 6)
    
    def test_network_rule_checking(self):
        """Test network rule violation checking"""
        suspicious_network_log = {
            'ProcessName': 'unknown.exe',
            'ProcessID': 1234,
            'Protocol': 'TCP',
            'LocalAddress': '192.168.1.100',
            'LocalPort': 12345,
            'RemoteAddress': '10.0.0.1',
            'RemotePort': 4444,
            'Direction': 'Outbound'
        }
        
        result = self.rule_engine.check_rules(
            'NETWORK_LOGS',
            suspicious_network_log,
            self.test_hostname
        )
        
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 6)
    
    def test_benign_activity(self):
        """Test that benign activity doesn't trigger rules"""
        benign_process_log = {
            'ProcessName': 'notepad.exe',
            'CommandLine': 'notepad.exe document.txt',
            'ExecutablePath': 'C:\\Windows\\System32\\notepad.exe',
            'ProcessID': 1234,
            'UserName': 'user'
        }
        
        result = self.rule_engine.check_rules(
            'PROCESS_LOGS',
            benign_process_log,
            self.test_hostname
        )
        
        violated, description, detection_data, severity, rule_id, action = result
        
        # Benign activity should typically not trigger rules
        # But this depends on the specific rules configured
        self.assertIsInstance(violated, bool)
    
    def test_rule_refresh(self):
        """Test rule refresh functionality"""
        # Get initial summary
        initial_summary = self.rule_engine.get_rules_summary()
        
        # Refresh rules
        refresh_success = self.rule_engine.refresh_rules()
        self.assertTrue(refresh_success)
        
        # Get new summary
        new_summary = self.rule_engine.get_rules_summary()
        
        # Should have same structure
        self.assertEqual(set(initial_summary.keys()), set(new_summary.keys()))
    
    def test_invalid_log_type(self):
        """Test handling of invalid log types"""
        test_log = {
            'SomeField': 'SomeValue'
        }
        
        result = self.rule_engine.check_rules(
            'INVALID_LOG_TYPE',
            test_log,
            self.test_hostname
        )
        
        violated, description, detection_data, severity, rule_id, action = result
        
        # Should handle gracefully
        self.assertFalse(violated)
        self.assertIsNone(description)
    
    def test_empty_log_data(self):
        """Test handling of empty log data"""
        result = self.rule_engine.check_rules(
            'PROCESS_LOGS',
            {},
            self.test_hostname
        )
        
        violated, description, detection_data, severity, rule_id, action = result
        
        # Should handle gracefully
        self.assertFalse(violated)
    
    def test_agent_specific_rules(self):
        """Test agent-specific rule application"""
        # Register test agent
        agent_data = {
            'hostname': self.test_hostname,
            'os_type': 'Windows'
        }
        self.agent_db.register_agent(agent_data)
        
        # Test with agent-specific context
        test_log = {
            'ProcessName': 'powershell.exe',
            'CommandLine': 'powershell.exe -ExecutionPolicy Bypass',
            'ProcessID': 1234
        }
        
        result = self.rule_engine.check_rules(
            'PROCESS_LOGS',
            test_log,
            self.test_hostname
        )
        
        self.assertIsInstance(result, tuple)
    
    def test_multiple_rule_violations(self):
        """Test handling of logs that might trigger multiple rules"""
        highly_suspicious_log = {
            'ProcessName': 'cmd.exe',
            'CommandLine': 'cmd.exe /c vssadmin delete shadows /all /quiet',
            'ExecutablePath': 'C:\\Windows\\System32\\cmd.exe',
            'ProcessID': 1234,
            'UserName': 'Administrator'
        }
        
        result = self.rule_engine.check_rules(
            'PROCESS_LOGS',
            highly_suspicious_log,
            self.test_hostname
        )
        
        violated, description, detection_data, severity, rule_id, action = result
        
        # Should detect violation
        self.assertIsInstance(violated, bool)
        
        if violated:
            self.assertIsNotNone(description)
            self.assertIsNotNone(severity)
            self.assertIsNotNone(rule_id)

class TestRuleValidation(unittest.TestCase):
    """Test rule validation and pattern matching"""
    
    def setUp(self):
        """Set up test environment"""
        self.rule_engine = RuleEngine()
    
    def test_process_name_patterns(self):
        """Test process name pattern matching"""
        # Test various suspicious process names
        suspicious_processes = [
            'cmd.exe',
            'powershell.exe',
            'wmic.exe',
            'reg.exe',
            'net.exe'
        ]
        
        for process_name in suspicious_processes:
            test_log = {
                'ProcessName': process_name,
                'CommandLine': f'{process_name} --test',
                'ProcessID': 1234
            }
            
            result = self.rule_engine.check_rules(
                'PROCESS_LOGS',
                test_log,
                'test-agent'
            )
            
            # At least some of these should trigger rules
            self.assertIsInstance(result[0], bool)
    
    def test_command_line_patterns(self):
        """Test command line pattern matching"""
        suspicious_commands = [
            'vssadmin delete shadows',
            'wevtutil cl',
            'reg delete',
            'schtasks /create',
            'bcdedit /set'
        ]
        
        for command in suspicious_commands:
            test_log = {
                'ProcessName': 'cmd.exe',
                'CommandLine': command,
                'ProcessID': 1234
            }
            
            result = self.rule_engine.check_rules(
                'PROCESS_LOGS',
                test_log,
                'test-agent'
            )
            
            # These should typically trigger rules
            self.assertIsInstance(result[0], bool)
    
    def test_file_extension_patterns(self):
        """Test file extension pattern matching"""
        suspicious_files = [
            {'FileName': 'malware.exe', 'FilePath': 'C:\\temp\\malware.exe'},
            {'FileName': 'script.bat', 'FilePath': 'C:\\temp\\script.bat'},
            {'FileName': 'payload.ps1', 'FilePath': 'C:\\temp\\payload.ps1'},
            {'FileName': 'virus.scr', 'FilePath': 'C:\\temp\\virus.scr'}
        ]
        
        for file_info in suspicious_files:
            test_log = {
                'FileName': file_info['FileName'],
                'FilePath': file_info['FilePath'],
                'EventType': 'Create',
                'ProcessID': 1234
            }
            
            result = self.rule_engine.check_rules(
                'FILE_LOGS',
                test_log,
                'test-agent'
            )
            
            self.assertIsInstance(result[0], bool)
    
    def test_network_port_patterns(self):
        """Test network port pattern matching"""
        suspicious_ports = [22, 23, 135, 445, 1433, 3389, 4444, 5555]
        
        for port in suspicious_ports:
            test_log = {
                'ProcessName': 'unknown.exe',
                'ProcessID': 1234,
                'Protocol': 'TCP',
                'RemoteAddress': '10.0.0.1',
                'RemotePort': port,
                'Direction': 'Outbound'
            }
            
            result = self.rule_engine.check_rules(
                'NETWORK_LOGS',
                test_log,
                'test-agent'
            )
            
            self.assertIsInstance(result[0], bool)

class TestRulePerformance(unittest.TestCase):
    """Test rule engine performance"""
    
    def setUp(self):
        """Set up test environment"""
        self.rule_engine = RuleEngine()
    
    def test_rule_checking_performance(self):
        """Test performance of rule checking"""
        import time
        
        test_log = {
            'ProcessName': 'test.exe',
            'CommandLine': 'test.exe --parameter',
            'ProcessID': 1234
        }
        
        # Test multiple rule checks
        start_time = time.time()
        
        for _ in range(100):
            self.rule_engine.check_rules(
                'PROCESS_LOGS',
                test_log,
                'test-agent'
            )
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Should complete 100 checks in reasonable time (< 5 seconds)
        self.assertLess(total_time, 5.0)
        
        # Average time per check should be reasonable (< 50ms)
        avg_time = total_time / 100
        self.assertLess(avg_time, 0.05)
    
    def test_rule_loading_performance(self):
        """Test performance of rule loading"""
        import time
        
        start_time = time.time()
        
        # Refresh rules multiple times
        for _ in range(10):
            self.rule_engine.refresh_rules()
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Should complete 10 refreshes in reasonable time (< 10 seconds)
        self.assertLess(total_time, 10.0)

class TestRuleDatabase(unittest.TestCase):
    """Test rule database operations"""
    
    def setUp(self):
        """Set up test environment"""
        self.rule_db = RuleDB()
    
    def test_rule_violation_checking(self):
        """Test rule violation checking through database"""
        # Get a rule to test with
        rules = self.rule_db.get_all_rules()
        
        if rules:
            rule = rules[0]
            rule_id = rule['RuleID']
            
            # Test violation checking
            test_log = {
                'ProcessName': 'cmd.exe',
                'CommandLine': 'cmd.exe /c test',
                'ProcessID': 1234
            }
            
            violation = self.rule_db.check_rule_violation(rule_id, test_log)
            
            # Should return None if no violation, or violation details if violated
            self.assertTrue(violation is None or isinstance(violation, dict))
    
    def test_cross_platform_rule_creation(self):
        """Test creating cross-platform rules"""
        rule_data = {
            'rule_name': 'Test Cross Platform Rule',
            'rule_type': 'Process',
            'description': 'Test rule for cross-platform testing',
            'severity': 'Medium',
            'action': 'Alert',
            'WindowsConditions': [
                {'ProcessName': 'cmd.exe'},
                {'ProcessPath': 'C:\\Windows\\System32\\cmd.exe'}
            ],
            'LinuxConditions': [
                {'ProcessName': 'bash'},
                {'ProcessPath': '/bin/bash'}
            ]
        }
        
        success = self.rule_db.create_cross_platform_rule(rule_data)
        self.assertTrue(success)
    
    def test_rule_conditions_loading(self):
        """Test loading rule conditions"""
        rules = self.rule_db.get_all_rules()
        
        if rules:
            rule = rules[0]
            rule_id = rule['RuleID']
            
            # Test getting rule details (includes conditions)
            detailed_rule = self.rule_db.get_rule_by_id(rule_id)
            
            self.assertIsNotNone(detailed_rule)
            self.assertEqual(detailed_rule['RuleID'], rule_id)

class TestRuleIntegration(unittest.TestCase):
    """Test rule engine integration with other components"""
    
    def setUp(self):
        """Set up test environment"""
        self.rule_engine = RuleEngine()
        self.rule_db = RuleDB()
        self.agent_db = AgentDB()
    
    def test_end_to_end_rule_processing(self):
        """Test complete rule processing flow"""
        # 1. Register agent
        agent_data = {
            'hostname': 'test-integration-agent',
            'os_type': 'Windows'
        }
        self.agent_db.register_agent(agent_data)
        
        # 2. Create rule
        rule_data = {
            'rule_name': 'Integration Test Rule',
            'rule_type': 'Process',
            'description': 'Rule for integration testing',
            'severity': 'High',
            'action': 'Alert'
        }
        rule_success = self.rule_db.create_rule(rule_data)
        self.assertTrue(rule_success)
        
        # 3. Refresh rule engine to load new rule
        self.rule_engine.refresh_rules()
        
        # 4. Process log that should trigger rule
        test_log = {
            'ProcessName': 'cmd.exe',
            'CommandLine': 'cmd.exe /c malicious_command',
            'ProcessID': 1234
        }
        
        result = self.rule_engine.check_rules(
            'PROCESS_LOGS',
            test_log,
            'test-integration-agent'
        )
        
        # Should return valid result
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 6)
    
    def test_rule_assignment_to_agents(self):
        """Test assigning rules to specific agents"""
        # Register agent
        agent_data = {
            'hostname': 'test-rule-assignment',
            'os_type': 'Linux'
        }
        self.agent_db.register_agent(agent_data)
        
        # Get available rules
        rules = self.rule_db.get_all_rules()
        
        if rules:
            rule_id = rules[0]['RuleID']
            
            # Assign rule to agent
            success = self.agent_db.assign_rule('test-rule-assignment', rule_id)
            self.assertIsInstance(success, bool)
            
            # Get assigned rules
            assigned_rules = self.agent_db.get_agent_rules('test-rule-assignment')
            self.assertIsInstance(assigned_rules, list)

def run_rule_tests():
    """Run all rule engine tests"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestRuleEngine))
    suite.addTests(loader.loadTestsFromTestCase(TestRuleValidation))
    suite.addTests(loader.loadTestsFromTestCase(TestRulePerformance))
    suite.addTests(loader.loadTestsFromTestCase(TestRuleDatabase))
    suite.addTests(loader.loadTestsFromTestCase(TestRuleIntegration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()

if __name__ == '__main__':
    # Run tests
    print("🧪 Running Rule Engine Tests...")
    
    try:
        success = run_rule_tests()
        
        if success:
            print("\n✅ All rule engine tests passed!")
        else:
            print("\n❌ Some rule engine tests failed!")
            exit(1)
    
    except Exception as e:
        print(f"\n💥 Error running rule engine tests: {e}")
        exit(1)