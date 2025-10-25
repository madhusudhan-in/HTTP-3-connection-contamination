# HTTP/3 Connection Contamination Testing Tool

A comprehensive security testing tool for HTTP/3 implementations, focusing on connection contamination vulnerabilities and QUIC protocol security.

## Features

- **Automated HTTP/3 Detection**: Automatically detects HTTP/3 support before testing
- **Comprehensive Security Tests**: Tests multiple attack vectors
- **Flexible Configuration**: Customizable host, port, and SSL settings
- **Detailed Reporting**: Generates structured JSON reports with severity levels
- **QUIC Protocol Analysis**: Deep inspection of QUIC connection handling
- **SSL Verification Options**: Configurable SSL certificate validation

## Prerequisites

- Python 3.8+
- OpenSSL
- Virtual environment (recommended)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/madhusudhan-in/HTTP-3-connection-contamination.git
cd HTTP-3-connection-contamination
```

2. Create and activate a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Command Syntax
```bash
python simple_tester.py [options]
```

### Command Line Options

```
--host HOST           Target host to test (default: localhost)
--port PORT           Target port to test (default: 443)
--verify-ssl          Enable SSL certificate verification
--output FILE         Output file for JSON report (default: http3_test_report.json)
--skip-h3-check      Skip HTTP/3 support check
```

### Example Usage Scenarios

1. Test a public server:
```bash
python simple_tester.py --host example.com --verify-ssl
```

2. Test a local development server:
```bash
python simple_tester.py --host localhost --port 4433 --skip-h3-check
```

3. Custom report location:
```bash
python simple_tester.py --host example.com --output custom_report.json
```

## Security Tests

### 1. HTTP/3 Support Detection
- Verifies HTTP/3 protocol support
- Analyzes Alt-Svc headers
- Checks QUIC version advertisement
- Validates ALPN protocol selection

### 2. Connection ID Security
- Tests Connection ID manipulation resistance
- Verifies ID rotation policies
- Checks ID length compliance
- Tests against ID prediction attacks

### 3. Packet Security
- Tests malformed packet handling
- Verifies packet number validation
- Checks replay attack resistance
- Tests out-of-order packet handling

### 4. Version Negotiation
- Tests invalid version handling
- Verifies downgrade attack protection
- Checks version negotiation patterns
- Tests version compatibility ranges

## Output and Logging

### JSON Report Structure
```json
{
  "summary": {
    "start_time": "2025-10-25T10:00:00",
    "end_time": "2025-10-25T10:01:00",
    "total_tests": 4,
    "passed": 3,
    "failed": 1,
    "warnings": 0
  },
  "results": [
    {
      "test_name": "HTTP/3 Support Check",
      "status": "PASS",
      "details": "Server advertises HTTP/3 support",
      "timestamp": "2025-10-25T10:00:01",
      "severity": "INFO"
    }
  ]
}
```

### Logging
- Detailed QUIC logs stored in `logs/quic_client_*.log`
- Real-time test progress in console output
- Comprehensive error reporting
- Connection trace logging

## Security Considerations

- Always obtain permission before testing production servers
- Use in controlled environments for security research
- Follow responsible disclosure practices
- Be aware of local network security policies

## Troubleshooting

### Common Issues
1. SSL Certificate Errors
   - Use `--verify-ssl` for production servers
   - Configure proper SSL context for local testing

2. Connection Timeouts
   - Check if target host is accessible
   - Verify correct port configuration
   - Check firewall settings

3. HTTP/3 Detection Failures
   - Verify server HTTP/3 support
   - Check Alt-Svc header configuration
   - Use `--skip-h3-check` for testing

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Test Cases

The tool includes several test cases for HTTP/3 connection contamination:

1. Connection ID Manipulation
   - Tests if the server properly validates connection IDs
   - Attempts to modify connection IDs mid-session
   - Checks for proper connection rejection on invalid IDs

2. Packet Injection
   - Tests resistance against malformed packet injection
   - Validates packet sequence number handling
   - Checks for proper packet validation

3. Version Negotiation
   - Tests handling of invalid QUIC versions
   - Validates version negotiation process
   - Checks for proper protocol version enforcement

## Security Considerations

- This tool is for testing purposes only
- Should be used in controlled environments
- Do not use against production servers without permission
- Follow responsible disclosure practices if vulnerabilities are found

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.