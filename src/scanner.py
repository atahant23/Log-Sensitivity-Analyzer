import os
import re
from src.validators.rules import SensitivityRules

class LogScanner:
    def __init__(self, target_path):
        self.target_path = target_path
        self.rules = SensitivityRules.get_patterns()

    def scan(self):
        leaks = []
        try:
            with open(self.target_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_no, line in enumerate(f, 1):
                    for ptype, pattern in self.rules.items():
                        matches = re.findall(pattern, line)
                        if matches:
                            leaks.append({'line': line_no, 'type': ptype, 'data': matches})
            return leaks
        except Exception as e:
            return f"Hata: {str(e)}"
