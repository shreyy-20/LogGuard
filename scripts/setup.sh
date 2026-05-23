#!/bin/bash

# LogGuard Service Setup & Installation Script
# Run as root or with sudo

set -e

# Colors for visual cues
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0;34m' # No Color
BLUE='\033[0;36m'

echo -e "${BLUE}===============================================${NC}"
echo -e "${GREEN}      🛡️ LogGuard System Service Installer      ${NC}"
echo -e "${BLUE}===============================================${NC}"

# 1. Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: Please run this installation script as root (sudo bash setup.sh)${NC}"
  exit 1
fi

# 2. Check for python3 and pip
if ! command -v python3 &> /dev/null; then
  echo -e "${RED}Error: python3 could not be found. Please install python3 first.${NC}"
  exit 1
fi

if ! command -v pip3 &> /dev/null; then
  echo -e "${YELLOW}Warning: pip3 not found. Trying to install...${NC}"
  apt-get update && apt-get install -y python3-pip || yum install -y python3-pip
fi

# 3. Create target directories
INSTALL_DIR="/opt/logguard"
echo -e "${BLUE}Creating installation directory at: ${INSTALL_DIR}...${NC}"
mkdir -p "${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}/config"
mkdir -p "${INSTALL_DIR}/logs"

# 4. Copy codebase
echo -e "${BLUE}Copying application files...${NC}"
cp -r src "${INSTALL_DIR}/"
cp config/config.yaml "${INSTALL_DIR}/config/config.yaml"
cp requirements.txt "${INSTALL_DIR}/"

# 5. Install dependencies
echo -e "${BLUE}Installing python requirements...${NC}"
pip3 install -r "${INSTALL_DIR}/requirements.txt"

# 6. Configure Systemd Service
SERVICE_FILE="/etc/systemd/system/logguard.service"
echo -e "${BLUE}Configuring systemd service file at: ${SERVICE_FILE}...${NC}"

cat <<EOF > "${SERVICE_FILE}"
[Unit]
Description=LogGuard Linux Log Monitoring & Analysis Daemon
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/python3 -m src.main
Restart=always
RestartSec=5
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=logguard

[Install]
WantedBy=multi-user.target
EOF

# 7. Reload systemd daemon and activate service
echo -e "${BLUE}Reloading systemd manager configuration...${NC}"
systemctl daemon-reload

echo -e "${BLUE}Enabling LogGuard service...${NC}"
systemctl enable logguard

echo -e "${BLUE}Creating symlink to global bin /usr/local/bin/logguard...${NC}"
cat <<EOF > /usr/local/bin/logguard
#!/bin/bash
cd ${INSTALL_DIR}
python3 -m src.cli.commands "\$@"
EOF
chmod +x /usr/local/bin/logguard

echo -e "${BLUE}===============================================${NC}"
echo -e "${GREEN}🛡️ Installation Completed Successfully!${NC}"
echo -e "${BLUE}===============================================${NC}"
echo -e "You can now perform the following operations:"
echo -e "  - Start the daemon:       ${YELLOW}sudo systemctl start logguard${NC}"
echo -e "  - Check daemon status:    ${YELLOW}sudo systemctl status logguard${NC}"
echo -e "  - Stop the daemon:        ${YELLOW}sudo systemctl stop logguard${NC}"
echo -e "  - View daemon logs:       ${YELLOW}sudo journalctl -u logguard -f${NC}"
echo -e "  - Use LogGuard CLI:       ${YELLOW}logguard --help${NC}"
echo -e "  - Search logs via CLI:    ${YELLOW}logguard search --level ERROR${NC}"
echo -e "  - Launch Interactive TUI: ${YELLOW}logguard dashboard${NC}"
echo -e "  - Start Web Dashboard:    ${YELLOW}python3 ${INSTALL_DIR}/src/web/app.py${NC}"
echo -e "${BLUE}===============================================${NC}"
