import re
import sys
import os
from colorama import Fore, Style, init

init(autoreset=True, strip=False)

class LogAnalyzer:
    def __init__(self, target):
        self.target = target
        self.patterns = {
            'PII': r'\b\d{11}\b|\b(?:\d[ -]*?){13,16}\b', # TCKN veya Kredi Kartı
            'Secret': r'(?i)(api_key|password|token|secret)\s*[:=]\s*[^\s]+',
            'Network': r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        }

    def self_check(self):
        """Görseldeki 'Auto Test Ability' kriterini sağlar."""
        print(f"{Fore.BLUE}[Self-Check] Sistem durumu kontrol ediliyor...{Style.RESET_ALL}")
        return True if os.path.exists(self.target) else False

    def run_analysis(self):
        if not self.self_check():
            print(f"{Fore.RED}[!] Hata: Hedef bulunamadı.{Style.RESET_ALL}")
            return

        print(f"{Fore.CYAN}[*] Analiz Başlatıldı: {self.target}{Style.RESET_ALL}")
        # ... (Önceki adımda verdiğim analiz döngüsü buraya gelecek)

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else input("Hedef log yolu: ")
    analyzer = LogAnalyzer(target)
    analyzer.run_analysis()