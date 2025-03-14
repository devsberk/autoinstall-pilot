#!/bin/bash

# Instalações do sistema

# Instalação do Google Chrome
wget -O /tmp/google-chrome-stable_current_amd64.deb "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb"
dpkg -i /tmp/google-chrome-stable_current_amd64.deb
apt-get install -f -y
rm /tmp/google-chrome-stable_current_amd64.deb

# Instalação do VSCode
wget -O /tmp/vscode.deb "https://code.visualstudio.com/sha/download?build=stable&os=linux-deb-x64"
dpkg -i /tmp/vscode.deb
apt-get install -f -y
rm /tmp/vscode.deb

# Instalação do Microsoft Defender
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft.gpg --yes
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft.gpg] https://packages.microsoft.com/ubuntu/20.04/prod focal main" | tee /etc/apt/sources.list.d/microsoft.list
apt update -y 
apt install -y mdatp 

# Instalação do AnyDesk
wget -O /tmp/AnyDeskClient.deb "https://ticorpfilestorage.blob.core.windows.net/varoa/Linux/Script%20Onboarding/AnyDeskClient.deb?si=Automate&sv=2022-11-02&sr=b&sig=fOYBnODf%2B%2FsAgK7M5KIZ845ot0frkdjUH%2FqjxB%2BdbMc%3D"
dpkg -i /tmp/AnyDeskClient.deb
apt-get install -f -y
rm /tmp/AnyDeskClient.deb

# Instalação do Cisco Secure Client e ISE Posture
BLOBURL="https://ticorpfilestorage.blob.core.windows.net/varoa/Linux/Script%20Onboarding/"
FILENAME_ZIP="Cisco%20Linux%205.1.2.42.zip"
SASTOKEN_ZIP="?si=Automate&sv=2022-11-02&sr=b&sig=rLUfZU7xqhHHyZEZclsUGZm4hHQrnYL0IoXXLRp%2Bgag%3D"
ZIP_URL="${BLOBURL}${FILENAME_ZIP}${SASTOKEN_ZIP}"
ZIP_FILE="/tmp/${FILENAME_ZIP}"
EXTRACT_DIR="/tmp/cisco-secure-client-linux64-5.1.2.42/"

curl -sL "$ZIP_URL" -o "$ZIP_FILE"
unzip -qq "$ZIP_FILE" -d "$EXTRACT_DIR"

COMPONENTS=("vpn" "posture" "iseposture")
for COMPONENT in "${COMPONENTS[@]}"; do
    COMPONENT_DIR="$EXTRACT_DIR/Cisco Linux 5.1.2.42/$COMPONENT"
    INSTALL_SCRIPT="$COMPONENT_DIR/${COMPONENT}_install.sh"
    [ -f "$INSTALL_SCRIPT" ] && chmod +x "$INSTALL_SCRIPT" && "$INSTALL_SCRIPT" || echo "Erro ao instalar $COMPONENT."
done

rm -rf "$ZIP_FILE" "$EXTRACT_DIR"

#################################### DISABLE IPV6 DEFINITIVO -- GLOBAL EFFECT ####################################

# 1. Desabilitar o IPv6 globalmente no sistema (usando /etc/sysctl.d/)
if ! grep -q "^net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*1$" /etc/sysctl.d/99-disable-ipv6.conf; then
    echo -e "net.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1\nnet.ipv6.conf.lo.disable_ipv6 = 1" | sudo tee /etc/sysctl.d/99-disable-ipv6.conf > /dev/null
    sudo sysctl --system > /dev/null
    echo -e "\nConfigurações de desabilitação do IPv6 aplicadas no sistema."
fi

# 2. Desabilitar o IPv6 no GRUB (para garantir que ele seja desabilitado no boot)
if ! grep -q "ipv6.disable=1" /etc/default/grub; then
    sudo sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=.*/& ipv6.disable=1/' /etc/default/grub
    sudo update-grub
fi

# 3. Desabilitar o IPv6 em todas as conexões existentes
echo "Desabilitando IPv6 em conexões de rede existentes..."
nmcli connection show | awk '/^\s*connection.id:/ {print $2}' | xargs -I {} -n 1 nmcli connection modify {} ipv6.method disabled

# 4. Configurar o NetworkManager para desabilitar o IPv6 em novas conexões
if ! grep -q "ipv6.method=disabled" /etc/NetworkManager/conf.d/99-disable-ipv6.conf; then
    echo -e "[connection]\nipv6.method=disabled" | sudo tee /etc/NetworkManager/conf.d/99-disable-ipv6.conf
fi

# Função para configurar certificados
_CERT() {
  tput bold; tput setaf 7; echo -e "\n[CERTIFICADOS]\n"; tput sgr0
    sleep 4

    # Variáveis
    CERTS_DIR="/usr/share/ca-certificates/uol"
    BLOB_BASE_URL="https://ticorpfilestorage.blob.core.windows.net/varoa/Linux/Script%20Onboarding/"
    TMP_DIR="/tmp/certs_tmp"
    
    declare -A SAS_TOKENS=(
        ["uolcorp"]="?si=Automate&sv=2022-11-02&sr=b&sig=FDiRdGRE9el8fFcFe5NuqLHU0IxUEs5sldqPBW%2BvpLU%3D"
        ["vpns"]="?si=Automate&sv=2022-11-02&sr=b&sig=EPwiZIjrRc6oJy%2Fcb1tlEpla3zMIqzvOjEAfHrM1iwY%3D"
        ["digicert"]="?si=Automate&sv=2022-11-02&sr=b&sig=dNS1mjhKjkcXj2UeTtFvYqNmnoHmgydlSpbyKwdP2vQ%3D"
        ["rapidssl"]="?si=Automate&sv=2022-11-02&sr=b&sig=6grOV2gie7ZVIO6Ra0YoUtYSXoha%2FzM1RSfvI2hfeH8%3D"
        ["caroot_2030"]="?si=Automate&sv=2022-11-02&sr=b&sig=r1tA5kGmvM3ZFbPRFmtUVzW6gBqPkdCmT%2B01GV2Mi%2Fo%3D"
        ["CARootUOL2044"]="?si=Automate&sv=2022-11-02&sr=b&sig=bIoCl5ShkHEK02BuAcaOLPDgUjSUzdBkgxKTOVt9nOI%3D"
        ["CARootPags"]="?si=Automate&sv=2022-11-02&sr=b&sig=nLVsyKpjgIlp9YpxiZdrtOh%2FTS9IA0jsNrRPG6QPlTY%3D"

    )
    
    declare -A FILE_NAMES=(
        ["uolcorp"]="uolcorp.crt"
        ["vpns"]="vpns.crt"
        ["digicert"]="DigiCertGlobalRootCA.crt"
        ["rapidssl"]="RapidSSLGlobalTLSRSA4096SHA2562022CA1.crt"
        ["caroot_2030"]="caroot_2030.crt"
        ["CARootUOL2044"]="CARootUOL2044.crt"
        ["CARootPags"]="CARootPags.cer"
    )
    
    # Criar diretórios necessários
    mkdir -p "${TMP_DIR}" "${CERTS_DIR}"
    
    # Trap para limpeza em caso de falha
    trap 'rm -rf ${TMP_DIR}' EXIT

    # Verificar e configurar certificados
    if [ -e "${CERTS_DIR}/caroot_2030.crt" ]; then
        echo -e "\033[32;1mCertificados de sistema já configurados.\033[0m"
        sleep 2
    else
        for cert in "${!FILE_NAMES[@]}"; do
            local FILE_NAME="${FILE_NAMES[$cert]}"
            local URL="${BLOB_BASE_URL}${FILE_NAME}${SAS_TOKENS[$cert]}"

            echo -e "\033[93;1mBaixando o certificado: ${FILE_NAME}\033[0m"
            sleep 1
            if ! curl -f -o "${TMP_DIR}/${FILE_NAME}" "${URL}" > /dev/null 2>&1; then
                echo -e "[ERROR] Falha ao baixar o certificado: ${FILE_NAME}"
                exit 1
            fi

            echo -e "\033[93;1mInstalando o certificado: ${FILE_NAME}\033[0m"
            sleep 1
            if ! sudo cp "${TMP_DIR}/${FILE_NAME}" "${CERTS_DIR}/" || ! sudo update-ca-certificates > /dev/null 2>&1; then
                echo -e "[ERROR] Falha ao instalar o certificado: ${FILE_NAME}"
                exit 1
            fi

            echo -e "\033[32;1m\nCertificado ${FILE_NAME} instalado com sucesso.\033[0m\n\n"
        done

        echo -e "\033[32;1m\nTodos os certificados foram baixados e instalados com sucesso.\033[0m\n"
    fi

    # Adicionando os certificados manualmente ao arquivo de configuração de certificados do sistema
    echo '/usr/local/share/ca-certificates/uolcorp.crt' | sudo tee -a /etc/ca-certificates.conf > /dev/null 2>&1
    echo '/usr/local/share/ca-certificates/vpns.crt' | sudo tee -a /etc/ca-certificates.conf > /dev/null 2>&1
    echo '/usr/local/share/ca-certificates/DigiCertGlobalRootCA.crt' | sudo tee -a /etc/ca-certificates.conf > /dev/null 2>&1
    echo '/usr/local/share/ca-certificates/RapidSSLGlobalTLSRSA4096SHA2562022CA1.crt' | sudo tee -a /etc/ca-certificates.conf > /dev/null 2>&1
    echo '/usr/local/share/ca-certificates/CARootPags.cer' | sudo tee -a /etc/ca-certificates.conf > /dev/null 2>&1
    echo '/usr/local/share/ca-certificates/CARootUOL2044.crt' | sudo tee -a /etc/ca-certificates.conf > /dev/null 2>&1

    sudo update-ca-certificates > /dev/null 2>&1;

    # Limpeza
    rm -rf "${TMP_DIR}"

    # Configuração do Blob Storage
    BLOBURL="https://ticorpfilestorage.blob.core.windows.net/varoa/Linux/Script%20Onboarding/"
    FILENAME_CERT="ZscalerRootCertificate-2048-SHA256.crt"
    FILENAME_JSON="policies.json"
    SASTOKEN_CERT="?si=Automate&sv=2022-11-02&sr=b&sig=S97ui0OUz52wXm6mMzXtXe6SGv%2Ffj3x3IBmM913QLtU%3D"
    SASTOKEN_JSON="?si=Automate&sv=2022-11-02&sr=b&sig=EVcFyiz4h2Ii%2BJiTjPWLXboXlj6DW%2BYVzKx%2FUlHvixA%3D"

    # Caminhos temporários para download
    CERTURL="${BLOBURL}${FILENAME_CERT}${SASTOKEN_CERT}"
    JSONURL="${BLOBURL}${FILENAME_JSON}${SASTOKEN_JSON}"
    FILEPATH_CERT="/tmp/${FILENAME_CERT}"
    FILEPATH_JSON="/tmp/${FILENAME_JSON}"

    # Função para download e importação de certificados
    gerenciar_certificado() {
    local certabspath="${FILEPATH_CERT}"
    local database=$1
    local caCertsPath
    local firefoxCersPath

    # Mapeamento de URLs para os arquivos
    declare -A urls=(
        [${FILEPATH_CERT}]="${CERTURL}"
    )

    # Definindo os caminhos específicos dependendo do destino
    if [ "$database" == "gnome-keyring" ]; then
        caCertsPath="/usr/share/ca-certificates/zscaler"
    elif [ "$database" == "browser-firefox" ]; then
        firefoxCersPath="/etc/firefox/policies/certificates"
        urls[${FILEPATH_JSON}]="${JSONURL}"
    fi

    # Baixar o certificado se não existir no caminho correto
    if [ "$database" == "gnome-keyring" ]; then
        if [ ! -f "${caCertsPath}/ZscalerRootCertificate-2048-SHA256.crt" ]; then
            curl -s -o "${FILEPATH_CERT}" "${CERTURL}" || { echo "[Erro] - Falha ao baixar o certificado!"; exit 1; }
        fi
    elif [ "$database" == "browser-firefox" ]; then
        if [ ! -f "${firefoxCersPath}/ZscalerRootCertificate-2048-SHA256.crt" ]; then
            curl -s -o "${FILEPATH_CERT}" "${CERTURL}" || { echo "[Erro] - Falha ao baixar o certificado!"; exit 1; }
        fi
    fi

    # Baixa o arquivo JSON somente se o destino for o Firefox
    if [ "$database" == "browser-firefox" ] && [ ! -f "$FILEPATH_JSON" ]; then
        curl -s -o "$FILEPATH_JSON" "${JSONURL}" || { echo "[Erro] - Falha ao baixar o policies.json!"; exit 1; }
    fi

    # Verifica e importa o certificado conforme o destino
    case ${database} in
    "gnome-keyring")
        if [ -e "${caCertsPath}/ZscalerRootCertificate-2048-SHA256.crt" ]; then
            echo -e "\033[32;1mCertificado já configurado no GNOME Keyring.\033[0m"
        else
            echo -e "Configurando no GNOME Keyring..."
            mkdir -p "${caCertsPath}"
            cp -f "${certabspath}" "${caCertsPath}/ZscalerRootCertificate-2048-SHA256.crt"
            chmod 644 "${caCertsPath}/ZscalerRootCertificate-2048-SHA256.crt"
            ln -sf "${caCertsPath}/ZscalerRootCertificate-2048-SHA256.crt" /etc/ssl/certs/
            echo 'zscaler/ZscalerRootCertificate-2048-SHA256.crt' | tee -a /etc/ca-certificates.conf > /dev/null
            update-ca-certificates >/dev/null 2>&1
            systemctl restart rsyslog
            logger -p local2.debug "[gnome-keyring] - Certificado importado!"
            echo -e "\033[92;1mCertificado configurado com sucesso no GNOME Keyring.\033[0m"
        fi
        ;;
    "browser-firefox")
        if [ -e "${firefoxCersPath}/ZscalerRootCertificate-2048-SHA256.crt" ]; then
            echo -e "\033[32;1mCertificado já configurado no Firefox.\033[0m"
        else
            echo -e "Configurando no Firefox..."
            mkdir -p "${firefoxCersPath}"
            cp -f "${certabspath}" "${firefoxCersPath}/ZscalerRootCertificate-2048-SHA256.crt"
            cp -f "${FILEPATH_JSON}" /etc/firefox/policies/policies.json
            systemctl restart rsyslog
            logger -p local2.debug "[browser-firefox] - Certificado importado!"
            echo -e "\033[92;1mCertificado e políticas configurados com sucesso no Firefox.\033[0m"
        fi
        ;;
    *)
        echo 'Argumento inesperado, saindo.'
        exit 1
        ;;
    esac
    }

    # Chamadas principais
    for db in "gnome-keyring" "browser-firefox"; do
        gerenciar_certificado "$db"
    done

    # Limpeza de arquivos temporários
    rm -f $FILEPATH_CERT $FILEPATH_JSON

}

# Reiniciar o sistema
reboot
