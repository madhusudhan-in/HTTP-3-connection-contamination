"""
HTTP/3 Connection Contamination Testing Tool

This module provides functionality to test HTTP/3 implementations for
security vulnerabilities related to connection contamination and QUIC protocol security.

Features:
- HTTP/3 support detection
- Connection ID tampering tests
- Packet injection detection
- Version negotiation tests
- Comprehensive test reporting
"""

import asyncio
import logging
import json
import argparse
import os
import ssl
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union

import aiohttp
from aioquic.asyncio.client import connect
from aioquic.asyncio.server import serve
from aioquic.h3.connection import H3_ALPN
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.logger import QuicFileLogger

# Configuration Constants
DEFAULT_PORT: int = 443
DEFAULT_HOST: str = "localhost"
DEFAULT_REPORT_FILE: str = "http3_test_report.json"
DEFAULT_TIMEOUT: int = 10

# QUIC Protocol Constants
QUIC_PACKET_SIZE: int = 1200  # Standard QUIC packet size
INVALID_QUIC_VERSION: int = 0x1a2a3a4a  # Version for testing

# Test Configuration
MAX_RETRIES: int = 3
RETRY_DELAY: float = 1.0

class TestStatus(str, Enum):
    """Enumeration of possible test statuses"""
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    ERROR = "ERROR"

class TestSeverity(str, Enum):
    """Enumeration of test severity levels"""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    ERROR = "ERROR"

class TestError(Exception):
    """Base exception for test-related errors"""
    pass

class ConnectionError(TestError):
    """Exception for connection-related errors"""
    pass

class ValidationError(TestError):
    """Exception for validation-related errors"""
    pass

@dataclass
class TestResult:
    """Data class representing a single test result"""
    test_name: str
    status: TestStatus
    details: str
    timestamp: str
    severity: TestSeverity = TestSeverity.INFO

    @classmethod
    def create(cls, test_name: str, status: TestStatus, details: str, 
               severity: TestSeverity = TestSeverity.INFO) -> 'TestResult':
        """
        Factory method to create a test result with current timestamp.
        
        Args:
            test_name: Name of the test
            status: Test status (PASS, FAIL, etc.)
            details: Detailed result description
            severity: Test result severity level
            
        Returns:
            TestResult: A new test result instance
        """
        return cls(
            test_name=test_name,
            status=status,
            details=details,
            timestamp=datetime.now().isoformat(),
            severity=severity
        )
        
    def to_dict(self) -> Dict[str, str]:
        """
        Convert the test result to a dictionary for serialization.
        
        Returns:
            Dict[str, str]: Dictionary representation of the test result
        """
        return {
            "test_name": self.test_name,
            "status": self.status.value,
            "details": self.details,
            "timestamp": self.timestamp,
            "severity": self.severity.value
        }

class TestReport:
    """
    Manages test results and report generation with enhanced logging and error handling.
    Provides functionality for adding results, generating reports, and saving to file.
    """
    
    def __init__(self):
        """Initialize a new test report with timestamp and logger"""
        self.results: List[TestResult] = []
        self.start_time = datetime.now()
        self._logger = logging.getLogger(__name__)
        
    def add_result(self, result: TestResult) -> None:
        """
        Add a test result with appropriate logging based on severity.
        
        Args:
            result (TestResult): The test result to add
        """
        self.results.append(result)
        
        # Log based on severity
        msg = f"{result.test_name}: {result.status.value} - {result.details}"
        if result.severity in (TestSeverity.HIGH, TestSeverity.CRITICAL):
            self._logger.error(msg)
        elif result.severity == TestSeverity.MEDIUM:
            self._logger.warning(msg)
        else:
            self._logger.info(msg)
            
    def get_statistics(self) -> Dict[str, int]:
        """Get test result statistics"""
        return {
            "total": len(self.results),
            "passed": sum(1 for r in self.results if r.status == TestStatus.PASS),
            "failed": sum(1 for r in self.results if r.status == TestStatus.FAIL),
            "warnings": sum(1 for r in self.results if r.status == TestStatus.WARN),
            "errors": sum(1 for r in self.results if r.status == TestStatus.ERROR)
        }
        
    def generate_report(self) -> Dict[str, Any]:
        """
        Generate a comprehensive test report.
        
        Returns:
            Dict[str, Any]: Complete test report with summary and results
        """
        stats = self.get_statistics()
        return {
            "summary": {
                "start_time": self.start_time.isoformat(),
                "end_time": datetime.now().isoformat(),
                "total_tests": stats["total"],
                "passed": stats["passed"],
                "failed": stats["failed"],
                "warnings": stats["warnings"],
                "errors": stats["errors"]
            },
            "results": [result.to_dict() for result in self.results]
        }
    
    def print_report(self) -> None:
        """Print a formatted report to console with color-coded status indicators"""
        report = self.generate_report()
        stats = self.get_statistics()
        
        print("\n=== HTTP/3 Connection Contamination Test Report ===")
        print(f"Start Time: {report['summary']['start_time']}")
        print(f"End Time: {report['summary']['end_time']}")
        print(f"\nResults Summary:")
        print(f"✓ Total Tests: {stats['total']}")
        print(f"✅ Passed: {stats['passed']}")
        print(f"❌ Failed: {stats['failed']}")
        print(f"⚠️  Warnings: {stats['warnings']}")
        print(f"🔴 Errors: {stats['errors']}")
        
        if stats['failed'] > 0 or stats['errors'] > 0:
            print("\n⛔️ CRITICAL ISSUES FOUND!")
        
        print("\nDetailed Results:")
        for result in self.results:
            status_symbols = {
                TestStatus.PASS: "✅",
                TestStatus.FAIL: "❌",
                TestStatus.WARN: "⚠️",
                TestStatus.ERROR: "🔴"
            }
            symbol = status_symbols.get(result.status, "❓")
            print(f"\n{symbol} {result.test_name}")
            print(f"Status: {result.status.value}")
            print(f"Severity: {result.severity.value}")
            print(f"Details: {result.details}")
    
    def save_report(self, filename: str = DEFAULT_REPORT_FILE) -> None:
        """
        Save the report to a JSON file with error handling.
        
        Args:
            filename (str): Path to save the report
            
        Raises:
            IOError: If there's an error writing to the file
        """
        try:
            with open(filename, "w") as f:
                json.dump(self.generate_report(), f, indent=2)
            self._logger.info(f"Report saved to {filename}")
        except IOError as e:
            self._logger.error(f"Failed to save report to {filename}: {e}")
            raise

class ConnectionContaminationTester:
    """
    Main tester class for HTTP/3 connection contamination tests.
    Handles test execution, result collection, and reporting.
    """

    def __init__(self, host="localhost", port=4433, verify_ssl=False):
        """Initialize the tester with connection parameters"""
        self.host = host
        self.port = port
        self.verify_ssl = verify_ssl
        self.report = TestReport()
        
        # Ensure logs directory exists
        self.logs_dir = os.path.join(os.path.dirname(__file__), "logs")
        os.makedirs(self.logs_dir, exist_ok=True)
        
        # Setup QUIC logging
        log_file = os.path.join(self.logs_dir, f"quic_client_{int(time.time())}.log")
        
        self.configuration = QuicConfiguration(
            alpn_protocols=H3_ALPN,
            is_client=True,
            verify_mode=ssl.CERT_NONE if not verify_ssl else ssl.CERT_REQUIRED,
            quic_logger=QuicFileLogger(self.logs_dir)
        )
        
    async def check_http3_support(self) -> bool:
        """Check if the target supports HTTP/3 before running tests"""
        try:
            ssl_context = ssl.create_default_context() if self.verify_ssl else False
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://{self.host}:{self.port}", 
                    ssl=ssl_context,
                    timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT)
                ) as response:
                    alt_svc = response.headers.get('alt-svc', '')
                    if 'h3' in alt_svc:
                        self.report.add_result(TestResult.create(
                            test_name="HTTP/3 Support Check",
                            status=TestStatus.PASS,
                            details=f"Server advertises HTTP/3 support. Alt-Svc: {alt_svc}",
                            severity=TestSeverity.INFO
                        ))
                        return True
                    else:
                        self.report.add_result(TestResult.create(
                            test_name="HTTP/3 Support Check",
                            status=TestStatus.FAIL,
                            details=f"Server does not advertise HTTP/3 support. Alt-Svc: {alt_svc}",
                            severity=TestSeverity.ERROR
                        ))
                        return False
        except Exception as e:
            self.report.add_result(TestResult.create(
                test_name="HTTP/3 Support Check",
                status=TestStatus.FAIL,
                details=f"Error checking HTTP/3 support: {str(e)}",
                severity=TestSeverity.ERROR
            ))
            return False

    async def test_connection_id_tampering(self):
        """Test for connection ID tampering vulnerability"""
        try:
            async with connect(
                self.host,
                self.port,
                configuration=self.configuration
            ) as protocol:
                # Try to modify connection ID (this should fail)
                try:
                    protocol._quic = QuicConnection(configuration=self.configuration)
                    self.report.add_result(TestResult.create(
                        test_name="Connection ID Tampering",
                        status=TestStatus.FAIL,
                        details="Connection ID tampering possible - Security Risk!",
                        severity=TestSeverity.HIGH
                    ))
                except Exception as e:
                    self.report.add_result(TestResult.create(
                        test_name="Connection ID Tampering",
                        status=TestStatus.PASS,
                        details="Connection ID tampering prevented",
                        severity=TestSeverity.INFO
                    ))
        except Exception as e:
            self.report.add_result(TestResult.create(
                test_name="Connection ID Tampering",
                status=TestStatus.ERROR,
                details=f"Test error: {str(e)}",
                severity=TestSeverity.ERROR
            ))

    async def _test_packet_injection(self):
        """Test for packet injection vulnerability"""
        try:
            async with connect(
                self.host,
                self.port,
                configuration=self.configuration
            ) as protocol:
                try:
                    # Create a fake packet
                    fake_packet = bytes([0x00] * QUIC_PACKET_SIZE)
                    protocol._quic.receive_datagram(fake_packet, ("127.0.0.1", self.port), time.time())
                    self.report.add_result(TestResult.create(
                        test_name="Packet Injection",
                        status=TestStatus.FAIL,
                        details="Packet injection possible - Security Risk!",
                        severity=TestSeverity.HIGH
                    ))
                except Exception as e:
                    self.report.add_result(TestResult.create(
                        test_name="Packet Injection",
                        status=TestStatus.PASS,
                        details=f"Packet injection prevented: {str(e)}",
                        severity=TestSeverity.INFO
                    ))
        except Exception as e:
            self.report.add_result(TestResult.create(
                test_name="Packet Injection",
                status=TestStatus.ERROR,
                details=f"Test error: {str(e)}",
                severity=TestSeverity.ERROR
            ))

    async def _test_version_negotiation(self):
        """Test for version negotiation vulnerability"""
        try:
            # Try with an invalid version
            self.configuration.supported_versions = [INVALID_QUIC_VERSION]
            try:
                async with connect(
                    self.host,
                    self.port,
                    configuration=self.configuration
                ) as protocol:
                    self.report.add_result(TestResult.create(
                        test_name="Version Negotiation",
                        status=TestStatus.FAIL,
                        details="Invalid version accepted - Security Risk!",
                        severity=TestSeverity.HIGH
                    ))
            except Exception as e:
                self.report.add_result(TestResult.create(
                    test_name="Version Negotiation",
                    status=TestStatus.PASS,
                    details="Invalid version properly rejected",
                    severity=TestSeverity.INFO
                ))
        except Exception as e:
            self.report.add_result(TestResult.create(
                test_name="Version Negotiation",
                status=TestStatus.ERROR,
                details=f"Test error: {str(e)}",
                severity=TestSeverity.ERROR
            ))

    async def execute_tests(self):
        """Run all security tests"""
        logging.info(f"Starting security tests for {self.host}:{self.port}")
        
        tests = [
            self._test_version_negotiation(),
            self._test_packet_injection(),
            self.test_connection_id_tampering()
        ]
        
        try:
            await asyncio.gather(*tests)
            logging.info("All tests completed")
        except Exception as e:
            logging.error(f"Error during test execution: {e}")
            self.report.add_result(TestResult.create(
                test_name="Test Suite",
                status=TestStatus.ERROR,
                details=f"Test suite execution error: {str(e)}",
                severity=TestSeverity.ERROR
            ))

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='HTTP/3 Connection Contamination Testing Tool',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('--host', default=DEFAULT_HOST, help='Target host to test')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help='Target port to test')
    parser.add_argument('--verify-ssl', action='store_true', help='Verify SSL certificates')
    parser.add_argument('--output', default=DEFAULT_REPORT_FILE, help='Output file for JSON report')
    parser.add_argument('--skip-h3-check', action='store_true', help='Skip HTTP/3 support check')
    return parser.parse_args()

async def main() -> None:
    """Main entry point"""
    args = parse_arguments()
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Initialize tester
    tester = ConnectionContaminationTester(
        host=args.host,
        port=args.port,
        verify_ssl=args.verify_ssl
    )
    
    # Check for HTTP/3 support first
    if not args.skip_h3_check:
        if not await tester.check_http3_support():
            logging.error("Target does not support HTTP/3 or is not accessible")
            tester.report.save_report(args.output)
            return

    # Run all tests
    await tester.execute_tests()
    
    # Generate and save report
    tester.report.print_report()
    tester.report.save_report(args.output)
    logging.info(f"Detailed report saved to {args.output}")

if __name__ == "__main__":
    asyncio.run(main())