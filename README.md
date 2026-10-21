# Phishing URL Detection System Using Python

## Project overview
A beginner-friendly cybersecurity project that checks a URL for selected warning signs and returns a Low, Medium, or High heuristic risk level.

## Features
- Accepts a URL from the user
- Checks for HTTP instead of HTTPS, IP-address hosts, long URLs, multiple hyphens, URL shorteners, `@` in the network location, punycode labels, and suspicious keywords
- Explains which warning signs were found
- Uses Python's standard library; no API key or internet request is required

## Requirements
- Python 3.9 or newer
- VS Code (recommended)
- IBM Bob may be used as a coding assistant

## Run
1. Download or clone this repository.
2. Open the project folder in VS Code.
3. Open a terminal in that folder.
4. Run:

```bash
python app.py
```

5. Enter a URL to analyze. Type `exit` to close the program.

## Example test inputs
- `https://www.example.com`
- `http://192.0.2.10/login`
- `http://bit.ly/verify-account`
- `https://secure-account-login.example.test/confirm`

Use these as demonstration inputs only. Do not visit suspicious links.

## Limitations
This project is an educational heuristic demonstration. It does not query threat-intelligence services, inspect website content, or use a trained machine-learning model. A low-risk result does not mean a URL is safe, and a high-risk result is not proof of phishing. Do not use it to make real-world security decisions.

## Ethical use
Analyze only URLs for learning and defensive awareness. Do not open or interact with suspicious links. Never enter passwords or personal information into unknown websites.

## Project files
- `app.py` — application source code
- `requirements.txt` — dependency list
- `PROJECT_REPORT.md` — project report
- `README.md` — setup and usage guide
- `test_app.py` — basic automated tests

## Author
Sharvari Barage  
Cybersecurity Bootcamp Project — BharatCares  
Date: October 2026
