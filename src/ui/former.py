#!/bin/bash

# Renk tanımları
BLUE='\033[0;34m'
NC='\033[0m' # No Color

if [ -z "$1" ]; then
    echo -e "${BLUE}Kullanım: ./run_analysis.sh <log_dosyası_yolu>${NC}"
    exit 1
fi

echo -e "${BLUE}[INFO] Ortam kontrol ediliyor...${NC}"
# Python yüklü mü kontrolü
if ! command -v python3 &> /dev/null; then
    echo "Python3 bulunamadı, lütfen yükleyin."
    exit 1
fi

python3 src/main.py "$1"
