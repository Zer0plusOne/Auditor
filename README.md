# WebAuditor

WebAuditor is a Python-based tool designed to perform a comprehensive security audit on a given website. It checks for SSL certificate details, security headers, open ports and their service versions, WHOIS information, common vulnerabilities, and crawls for sensitive files.

## Features

- **SSL Certificate Check**: Verifies the SSL certificate details of the target website.
- **Security Headers Analysis**: Analyzes the security headers of the target website.
- **Open Ports and Service Versions Detection**: Scans for open ports and detects the versions of services running on those ports.
- **WHOIS Information Retrieval**: Retrieves WHOIS information for the target domain.
- **Common Vulnerabilities Check**: Checks for common vulnerabilities.
- **Sensitive Files Crawling**: Crawls the website for potentially sensitive files.
- **Report Generation**: Generates a detailed report of the audit.

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/Zer0plusOne/WebAuditor.git
    cd WebAuditor
    ```

2. Install the required dependencies:
    ```sh
    bash requirements.sh
    ```

## Usage

To run a full audit on a target website, use the following command:
```sh
python main.py <URL>
```
Replace `<URL>` with the target website URL.

## Example

```sh
python main.py https://example.com
```

## Output

The tool generates a detailed report of the audit and saves it to \`audit_report.txt\` in the current directory.

## Dependencies

- `requests`
- `socket`
- `ssl`
- `sys`
- `nmap`
- `whois`
- `datetime`
- `beautifulsoup4`
- `urllib`

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
