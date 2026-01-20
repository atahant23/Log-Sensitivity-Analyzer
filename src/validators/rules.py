import re

class SensitivityRules:
    @staticmethod
    def get_patterns():
        return {
            'TCKN (Kimlik No)': r'\b[1-9][0-9]{10}\b',
            'KREDI_KARTI': r'\b(?:\d[ -]*?){13,16}\b',
            'EMAIL_SIZINTISI': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'API_KEY/SECRET': r'(?i)(api_key|password|token|secret|access_key)\s*[:=]\s*[^\s]+',
            'IP_ADRESI': r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        }
