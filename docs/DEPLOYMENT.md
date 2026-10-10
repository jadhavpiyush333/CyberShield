# Kali Linux Deployment

## Development
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest -q
python app.py
```

## Production-like local service
```bash
./deployment/kali/install_kali.sh
./deployment/kali/start.sh
./deployment/kali/status.sh
```

Default bind is localhost. Only expose CyberShield to a LAN after adding authentication/TLS and an appropriate firewall rule. Do not run the Flask development server as a public service.
