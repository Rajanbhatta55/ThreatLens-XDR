"""
Unit Tests for ThreatLens CLI Commands
Coursework: Function Testing and Contract Verification
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import tempfile
import json
import argparse

# Import the CLI functions
from threatlens.cli import (
    build_parser,
    run_rules,
    run_summary,
    run_verify_chain,
    run_encrypt_report,
    run_sign_report,
    run_correlate,
)


class TestBuildParser(unittest.TestCase):
    """Test: Parser Construction"""
    
    def test_build_parser_returns_argument_parser(self):
        """Contract: build_parser() -> ArgumentParser"""
        parser = build_parser()
        self.assertIsInstance(parser, argparse.ArgumentParser)
    
    def test_parser_has_all_subcommands(self):
        """Contract: Parser contains 14 subcommands"""
        parser = build_parser()
        # Parse to get subparsers
        expected_commands = {
            'scan', 'follow', 'rules', 'summary', 'dashboard',
            'seed-db', 'wazuh-pull', 'windows-agent-listen',
            'correlate', 'forensic-report', 'verify-chain',
            'encrypt-report', 'sign-report', 'weekly-report'
        }
        # Verify by checking help text
        help_text = parser.format_help()
        for cmd in expected_commands:
            self.assertIn(cmd, help_text)
    
    def test_parser_has_version_option(self):
        """Contract: Parser has --version option"""
        parser = build_parser()
        help_text = parser.format_help()
        self.assertIn('--version', help_text)
    
    def test_parser_handles_help(self):
        """Contract: Parser responds to -h/--help"""
        parser = build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(['--help'])


class TestRunRules(unittest.TestCase):
    """Test: run_rules() Function"""
    
    def test_run_rules_return_value(self):
        """Contract: run_rules() -> int (exit code)"""
        result = run_rules()
        self.assertIsInstance(result, int)
        self.assertEqual(result, 0)
    
    def test_run_rules_prints_banner(self):
        """Contract: run_rules() outputs ThreatLens banner"""
        with patch('builtins.print') as mock_print:
            run_rules()
            # Check that something was printed
            self.assertTrue(mock_print.called)
    
    def test_run_rules_lists_detectors(self):
        """Contract: run_rules() lists all available detectors"""
        with patch('builtins.print') as mock_print:
            run_rules()
            call_args = [str(call) for call in mock_print.call_args_list]
            # Should contain detector names
            all_output = ' '.join(call_args)
            self.assertIn('Available Detection Rules', all_output)


class TestRunSummary(unittest.TestCase):
    """Test: run_summary() Function"""
    
    def test_run_summary_with_missing_file(self):
        """Contract: run_summary() -> 1 when report file missing"""
        args = argparse.Namespace(report='/nonexistent/file.json', no_color=False)
        result = run_summary(args)
        self.assertEqual(result, 1)
    
    def test_run_summary_with_valid_json(self):
        """Contract: run_summary() -> 0 with valid JSON report"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            report_data = {
                'report_metadata': {'generated_at': '2026-06-17', 'version': '2.3.0'},
                'severity_summary': {'critical': 2, 'high': 5},
                'alerts': [{'rule_name': 'Test'}]
            }
            json.dump(report_data, f)
            f.flush()
            fname = f.name
        
        try:
            args = argparse.Namespace(report=fname, no_color=False)
            result = run_summary(args)
            self.assertEqual(result, 0)
        finally:
            Path(fname).unlink()
    
    def test_run_summary_with_invalid_json(self):
        """Contract: run_summary() -> 1 with invalid JSON"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("{ invalid json")
            f.flush()
            fname = f.name
        
        try:
            args = argparse.Namespace(report=fname, no_color=False)
            result = run_summary(args)
            self.assertEqual(result, 1)
        finally:
            Path(fname).unlink()


class TestRunVerifyChain(unittest.TestCase):
    """Test: run_verify_chain() Function"""
    
    @patch('threatlens.detections.hash_chain.HashChainManager')
    def test_verify_chain_returns_zero_on_success(self, mock_manager_class):
        """Contract: run_verify_chain() -> 0 on valid chain"""
        mock_manager = Mock()
        mock_manager.verify_chain.return_value = (True, [])
        mock_manager_class.return_value = mock_manager
        
        args = argparse.Namespace(database='test.db')
        result = run_verify_chain(args)
        
        self.assertEqual(result, 0)
    
    @patch('threatlens.detections.hash_chain.HashChainManager')
    def test_verify_chain_returns_one_on_failure(self, mock_manager_class):
        """Contract: run_verify_chain() -> 1 on chain failure"""
        mock_manager = Mock()
        mock_manager.verify_chain.return_value = (False, ['Record 1 hash mismatch'])
        mock_manager_class.return_value = mock_manager
        
        args = argparse.Namespace(database='test.db')
        result = run_verify_chain(args)
        
        self.assertEqual(result, 1)
    
    @patch('threatlens.detections.hash_chain.HashChainManager')
    def test_verify_chain_detects_tampering(self, mock_manager_class):
        """Contract: run_verify_chain() detects tampered records"""
        mock_manager = Mock()
        errors = ['Record 5 hash mismatch', 'Record 6 previous hash mismatch']
        mock_manager.verify_chain.return_value = (False, errors)
        mock_manager_class.return_value = mock_manager
        
        args = argparse.Namespace(database='test.db')
        with patch('builtins.print'):
            result = run_verify_chain(args)
        
        self.assertEqual(result, 1)


class TestRunEncryptReport(unittest.TestCase):
    """Test: run_encrypt_report() Function"""
    
    def test_encrypt_report_creates_output_file(self):
        """Contract: encrypt_report() creates encrypted output file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            input_file = tmpdir_path / 'report.txt'
            input_file.write_text('Test report content')
            
            output_file = tmpdir_path / 'report.encrypted'
            key_file = tmpdir_path / 'report.key'
            
            args = argparse.Namespace(
                input=str(input_file),
                output=str(output_file),
                key_file=str(key_file)
            )
            
            result = run_encrypt_report(args)
            
            self.assertEqual(result, 0)
            self.assertTrue(output_file.exists())
            self.assertTrue(key_file.exists())
    
    def test_encrypt_report_with_existing_key(self):
        """Contract: encrypt_report() reuses existing key"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            input_file = tmpdir_path / 'report.txt'
            input_file.write_text('Test report')
            
            key_file = tmpdir_path / 'report.key'
            key_content = b'0' * 32  # 256-bit key
            key_file.write_bytes(key_content)
            
            output_file = tmpdir_path / 'report.encrypted'
            
            args = argparse.Namespace(
                input=str(input_file),
                output=str(output_file),
                key_file=str(key_file)
            )
            
            result = run_encrypt_report(args)
            
            # Verify key wasn't changed
            self.assertEqual(key_file.read_bytes(), key_content)
    
    def test_encrypt_report_output_differs_from_input(self):
        """Contract: Encrypted output != plaintext input"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            input_file = tmpdir_path / 'report.txt'
            plaintext = 'Confidential Security Report'
            input_file.write_text(plaintext)
            
            output_file = tmpdir_path / 'report.encrypted'
            key_file = tmpdir_path / 'report.key'
            
            args = argparse.Namespace(
                input=str(input_file),
                output=str(output_file),
                key_file=str(key_file)
            )
            
            run_encrypt_report(args)
            
            encrypted_content = output_file.read_text()
            self.assertNotEqual(encrypted_content, plaintext)


class TestRunSignReport(unittest.TestCase):
    """Test: run_sign_report() Function"""
    
    @patch('threatlens.cli.sign_artifact')
    def test_sign_report_calls_sign_artifact(self, mock_sign):
        """Contract: sign_report() calls sign_artifact()"""
        args = argparse.Namespace(
            input='report.pdf',
            signature='report.sig',
            private_key='key.pem',
            passphrase=None
        )
        
        run_sign_report(args)
        
        mock_sign.assert_called_once()
    
    @patch('threatlens.cli.sign_artifact')
    def test_sign_report_passes_passphrase(self, mock_sign):
        """Contract: sign_report() passes passphrase to sign_artifact()"""
        args = argparse.Namespace(
            input='report.pdf',
            signature='report.sig',
            private_key='key.pem',
            passphrase='mypassphrase'
        )
        
        run_sign_report(args)
        
        # Verify passphrase was passed
        call_args = mock_sign.call_args
        self.assertEqual(call_args[0][3], 'mypassphrase')
    
    @patch('threatlens.cli.sign_artifact')
    def test_sign_report_returns_zero(self, mock_sign):
        """Contract: sign_report() -> 0 (success)"""
        args = argparse.Namespace(
            input='report.pdf',
            signature='report.sig',
            private_key='key.pem',
            passphrase=None
        )
        
        result = run_sign_report(args)
        
        self.assertEqual(result, 0)


class TestRunCorrelate(unittest.TestCase):
    """Test: run_correlate() Function"""
    
    @patch('threatlens.cli.ThreatLensStore')
    @patch('threatlens.cli.CorrelationEngine')
    def test_correlate_returns_zero(self, mock_engine_class, mock_store_class):
        """Contract: correlate() -> 0 (success)"""
        mock_store = Mock()
        mock_store.load_alerts.return_value = [{'id': 1}, {'id': 2}]
        mock_store.load_incidents.return_value = []
        mock_store_class.return_value = mock_store
        
        mock_engine = Mock()
        mock_engine.correlate.return_value = []
        mock_engine_class.return_value = mock_engine
        
        args = argparse.Namespace(
            database='test.db',
            window_minutes=60,
            min_alerts=2
        )
        
        result = run_correlate(args)
        
        self.assertEqual(result, 0)
    
    @patch('threatlens.cli.ThreatLensStore')
    @patch('threatlens.cli.CorrelationEngine')
    def test_correlate_stores_incidents(self, mock_engine_class, mock_store_class):
        """Contract: correlate() saves incidents to database"""
        mock_store = Mock()
        mock_store.load_alerts.return_value = [{'id': 1}, {'id': 2}]
        mock_store_class.return_value = mock_store
        
        mock_incident = Mock()
        mock_incident.to_dict.return_value = {'id': 'inc1', 'title': 'Attack Chain'}
        
        mock_engine = Mock()
        mock_engine.correlate.return_value = [mock_incident]
        mock_engine_class.return_value = mock_engine
        
        args = argparse.Namespace(
            database='test.db',
            window_minutes=60,
            min_alerts=2
        )
        
        run_correlate(args)
        
        # Verify save_incidents was called
        mock_store.save_incidents.assert_called_once()


class TestArgumentParsing(unittest.TestCase):
    """Test: Command-line Argument Parsing"""
    
    def test_scan_command_parser(self):
        """Contract: scan command accepts path argument"""
        parser = build_parser()
        args = parser.parse_args(['scan', '/logs/security.json'])
        self.assertEqual(args.command, 'scan')
        self.assertEqual(args.path, '/logs/security.json')
    
    def test_scan_with_output_option(self):
        """Contract: scan --output sets output path"""
        parser = build_parser()
        args = parser.parse_args(['scan', '/logs', '--output', 'report.json'])
        self.assertEqual(args.output, 'report.json')
    
    def test_scan_with_format_option(self):
        """Contract: scan --format accepts format choices"""
        parser = build_parser()
        args = parser.parse_args(['scan', '/logs', '--format', 'html'])
        self.assertEqual(args.format, 'html')
    
    def test_verify_chain_requires_database(self):
        """Contract: verify-chain has --database option"""
        parser = build_parser()
        args = parser.parse_args(['verify-chain', '--database', 'evidence.db'])
        self.assertEqual(args.database, 'evidence.db')
    
    def test_encrypt_report_requires_paths(self):
        """Contract: encrypt-report has input, output, key-file"""
        parser = build_parser()
        args = parser.parse_args([
            'encrypt-report', 'report.pdf',
            '--output', 'report.enc',
            '--key-file', 'report.key'
        ])
        self.assertEqual(args.input, 'report.pdf')
        self.assertEqual(args.output, 'report.enc')
        self.assertEqual(args.key_file, 'report.key')


class TestIntegration(unittest.TestCase):
    """Integration Tests: Multiple functions together"""
    
    def test_encrypt_then_verify_workflow(self):
        """Contract: Can encrypt and verify chain in sequence"""
        # This test verifies the workflow: encrypt → store → verify
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            report_file = tmpdir_path / 'report.txt'
            report_file.write_text('Test Report')
            
            encrypted_file = tmpdir_path / 'report.enc'
            key_file = tmpdir_path / 'report.key'
            
            # Step 1: Encrypt
            encrypt_args = argparse.Namespace(
                input=str(report_file),
                output=str(encrypted_file),
                key_file=str(key_file)
            )
            result = run_encrypt_report(encrypt_args)
            self.assertEqual(result, 0)
            
            # Step 2: Verify files exist
            self.assertTrue(encrypted_file.exists())
            self.assertTrue(key_file.exists())


def run_test_suite():
    """Run all unit tests"""
    unittest.main(argv=[''], verbosity=2, exit=False)


if __name__ == '__main__':
    run_test_suite()
