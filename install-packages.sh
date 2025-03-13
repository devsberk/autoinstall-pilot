#!/bin/bash
# Instalação do Google Chrome
wget -O /tmp/google-chrome-stable_current_amd64.deb "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb"
dpkg -i /tmp/google-chrome-stable_current_amd64.deb
apt-get install -f -y
rm /tmp/google-chrome-stable_current_amd64.deb

# Instalação do AnyDesk
wget -O /tmp/AnyDeskClient.deb "https://ticorpfilestorage.blob.core.windows.net/varoa/Linux/Script%20Onboarding/AnyDeskClient.deb?si=Automate&sv=2022-11-02&sr=b&sig=fOYBnODf%2B%2FsAgK7M5KIZ845ot0frkdjUH%2FqjxB%2BdbMc%3D"
dpkg -i /tmp/AnyDeskClient.deb
apt-get install -f -y
rm /tmp/AnyDeskClient.deb

# Instalação do VSCode
wget -O /tmp/vscode.deb "https://code.visualstudio.com/sha/download?build=stable&os=linux-deb-x64"
dpkg -i /tmp/vscode.deb
apt-get install -f -y
rm /tmp/vscode.deb

# Instalação do Microsoft Defender
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft.gpg --yes >/dev/null 2>&1
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft.gpg] https://packages.microsoft.com/ubuntu/20.04/prod focal main" | tee /etc/apt/sources.list.d/microsoft.list >/dev/null 2>&1
apt update -y >/dev/null 2>&1
apt install -y mdatp >/dev/null 2>&1

# Reiniciar o sistema
reboot
