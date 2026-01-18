Log Sensitivity Analyzer - Detaylı Teknik Araştırma Raporu
Executive Summary
Log Sensitivity Analyzer, log verilerinde bulunan hassas bilgileri (PII - Personally Identifiable Information, PHI - Protected Health Information, finansal veriler vb.) otomatik olarak tespit eden, sınıflandıran ve maskeleme/redaksiyon yapan güvenlik araçları kategorisidir. Bu teknoloji, GDPR, HIPAA, PCI-DSS gibi düzenlemelere uyum sağlamak ve veri güvenliğini artırmak için kritik öneme sahiptir.

1. Temel Çalışma Prensipleri
1.1 Algılama Mekanizmaları
Log Sensitivity Analyzer araçları üç temel yöntemle hassas veri tespiti yapar:
a) Pattern Matching (Regex Tabanlı)

Önceden tanımlanmış regex desenleriyle SSN, kredi kartı numaraları, telefon numaraları gibi standart formatlı verileri tespit eder
Yüksek hız, düşük CPU kullanımı
Checksum doğrulaması yapabilir (Luhn algoritması vb.)

b) Named Entity Recognition (NER)

Doğal dil işleme (NLP) ve makine öğrenmesi modelleri kullanır
spaCy, Hugging Face Transformers gibi kütüphanelerle çalışır
İsim, lokasyon, organizasyon gibi yapılandırılmamış verileri tanır
Bağlam farkındalığı sağlar

c) Context-Aware Detection

Çevresel ipuçlarını (lemma context) kullanarak hassas veriyi doğrular
Örnek: "customer ID: 1234567890" ifadesindeki "customer ID" bağlamı
False positive oranını düşürür

1.2 İşlem Akışı
1. Log Collection → 2. Pre-Processing → 3. Detection → 4. Classification → 
5. Anonymization → 6. Storage/Forwarding → 7. Audit & Reporting
Aşama Detayları:

Log Collection: Çeşitli kaynaklardan (syslog, HTTP, file) log toplama
Pre-Processing: Log parsing, normalizasyon, zenginleştirme
Detection: PII/PHI/Secrets tespiti (NER + Regex + Context)
Classification: Hassasiyet seviyesi belirleme (Low/Medium/High/Critical)
Anonymization: Masking, hashing, redaction, synthetic replacement
Storage: Temizlenmiş logları güvenli şekilde saklama
Audit: Compliance raporları ve alert üretimi

1.3 Anonimleştirme Teknikleri
TeknikAçıklamaKullanım SenaryosuÖrnekMaskingKısmi/tam maskelemePCI-DSS uyumu4500-****-****-9012RedactionTamamen kaldırmaHIPAA compliance[REDACTED]HashingSHA-256/SHA-512Join operasyonlarıa3f5b...EncryptionAES-256 şifrelemeGeri çözülmesi gereken verilerenc:Ab3dF...Synthetic ReplacementFake data ile değiştirmeTest ortamlarıJohn Doe → Jane SmithTokenizationToken ile değiştirmeVeri analitiğiPERSON_TOKEN_001

2. Best Practices ve Endüstri Standartları
2.1 OWASP Top 10 Alignment
A09:2021 - Security Logging and Monitoring Failures

Hassas verinin log'lara yazılmasını önleme
Audit trail bütünlüğünü koruma
Real-time alerting mekanizmaları

2.2 Compliance Framework Gereksinimleri
GDPR (General Data Protection Regulation)

Article 32: Kişisel verilerin güvenliği
Article 5(1)(f): Veri güvenliği ve gizliliği
Best Practices:

Data minimization prensibi
Privacy by design
Pseudonymization zorunluluğu
Encryption at rest & in transit



HIPAA (Health Insurance Portability and Accountability Act)

§164.312(b): Audit Controls zorunluluğu
§164.312(d): Encryption zorunluluğu
Retention: Minimum 6 yıl log saklama
Best Practices:

ePHI (electronic Protected Health Information) tespiti ve maskeleme
Access control logging
Role-based access control (RBAC)
Immutable audit logs



PCI-DSS (Payment Card Industry Data Security Standard)

Requirement 10: Log management ve monitoring
Requirement 3: Cardholder data protection
Retention: Minimum 1 yıl aktif, 3 ay online
Best Practices:

Kredi kartı numaralarını asla plain-text loglamama
PAN (Primary Account Number) maskeleme
Tokenization kullanımı



SOX (Sarbanes-Oxley Act)

Section 404: Internal controls assessment
Retention: Minimum 7 yıl
Best Practices:

Financial data logging
Change tracking
Independent audit trail



2.3 NIST SP 800-92 Guidelines
Log Management Önerileri:

Log generation policies oluşturma
Log protection mekanizmaları
Log analysis ve retention procedures
Sensitive data handling guidelines

2.4 Industry Best Practices
Design Phase

"Shift Left" Security: Geliştirme aşamasında hassas veri loglama önleme
Structured Logging: JSON/Syslog formatlarında yapılandırılmış loglar
Field-level Sensitivity Tagging: Her field için hassasiyet seviyesi tanımlama

Implementation Phase

Layered Defense:

Application level: Loglama öncesi filtreleme
Pipeline level: Observability pipeline'da redaction
Storage level: Encryption at rest


Minimal Logging Principle: Sadece gerekli veriyi loglama
No Plain-Text Credentials: Asla password, token, API key loglamama
Context Preservation: Maskelenmiş veriyle bile debugging yapabilme

Operational Phase

Continuous Monitoring: Real-time sensitive data detection
Regular Audits: Quarterly compliance audits
Automated Testing: CI/CD pipeline'a entegre test
Training: Developer ve ops ekiplerine düzenli eğitim

Scaling Considerations

Horizontal scaling capability
Stateless architecture
Distributed processing (Kafka, Spark)
Rate limiting ve throttling

2.5 Common Anti-Patterns (Kaçınılması Gerekenler)
❌ String concatenation ile loglama: log.info("User: " + user.name)
❌ Exception stack trace'lerde PII: log.error("Error for " + email, exception)
❌ Debug modunda production çalıştırma: Aşırı detaylı loglama
❌ Generic catch blocks: Hassas veriyi exception'a ekleme
❌ Log forwarding without filtering: Redaksiyon yapmadan merkezi loglama
❌ Hardcoded regex patterns: Maintenance zorluğu

3. Benzer Açık Kaynak Projeler ve Rakipler
3.1 Lider Açık Kaynak Projeler
Microsoft Presidio ⭐ #1 Öneri

GitHub: https://github.com/microsoft/presidio
Dil: Python
Lisans: MIT
Stars: ~3,000+
Özellikler:

180+ PII entity type detection
NER + Regex + Context awareness
Image redaction (OCR ile)
Structured data support (CSV, DataFrame)
Multi-language support
REST API & Python SDK
PySpark integration
Customizable recognizers


Güçlü Yanlar:

Microsoft desteği, aktif geliştirme
Production-ready architecture
Comprehensive documentation
Enterprise-grade quality


Zayıf Yanlar:

Yüksek resource kullanımı (NER modelleri)
Learning curve


Deployment:

bash  pip install presidio-analyzer presidio-anonymizer
  python -m spacy download en_core_web_lg
Bearer (Formerly Curio)

GitHub: https://github.com/Bearer/bearer
Dil: Go
Lisans: Elastic License 2.0
Stars: ~1,800+
Özellikler:

SAST scanner (Static Application Security Testing)
Code-level PII detection
OWASP Top 10 coverage
59 built-in rules
CI/CD integration
Multi-language support (JS, Python, Ruby, Java, PHP, Go)



DataDog Sensitive Data Scanner (Open Core)

GitHub: https://github.com/DataDog/dd-sensitive-data-scanner
Lisans: Apache 2.0
Özellikler:

Real-time stream processing
Custom scanning rules
OOTB (Out-of-the-box) patterns
Low latency (<1ms overhead)
Production-tested at scale



LogAI (Salesforce)

GitHub: https://github.com/salesforce/logai
Dil: Python
Lisans: BSD-3-Clause
Stars: ~2,000+
Özellikler:

Log anomaly detection
Log clustering & summarization
OpenTelemetry data model
GUI toolkit included
ML/DL model integration



ReDiscovery

GitHub: https://github.com/redglue/ReDiscovery
Dil: Java
Lisans: Apache 2.0
Özellikler:

Database scanning
File system scanning
Apache OpenNLP based
Dictionary + Regex + NLP
GDPR focused



3.2 Ticari Çözümler (Comparison)
ÜrünGüçlü YanıFiyatlamaUse CaseDatadog Sensitive Data ScannerCloud-native, scale$0.10/GBEnterprise observabilitySplunk Data SecuritySIEM integrationEnterpriseLarge security teamsAWS ComprehendAWS ecosystemPay-per-APIAWS-centricAzure PurviewMicrosoft 365 integrationTieredAzure shopsGoogle DLP APIGCP nativePer-API-callGCP usersPII ToolsOn-prem, privacy-firstLicense-basedRegulated industriesNetwrix DSPMData discovery + classificationEnterpriseCompliance-heavy
3.3 Lightweight/Specialized Tools

pyWhat: Regex identification library (https://github.com/bee-san/pyWhat)
Trufflehog: Git secrets scanner
GitHound: GitHub secrets detection
Gitleaks: Git credential scanner
detect-secrets (Yelp): Pre-commit hook for secrets


4. Kritik Yapılandırma Dosyaları ve Parametreleri
4.1 Microsoft Presidio Configuration
presidio_analyzer_config.yaml
yaml# Analyzer Configuration
nlp_engine_name: "spacy"  # spacy, stanza, transformers
models:
  - lang_code: "en"
    model_name: "en_core_web_lg"  # lg: large, md: medium, sm: small

# Recognizer Registry
recognizers:
  - name: "CreditCardRecognizer"
    supported_language: "en"
    supported_entity: "CREDIT_CARD"
    enabled: true
    
  - name: "EmailRecognizer"
    supported_language: "en"
    supported_entity: "EMAIL_ADDRESS"
    enabled: true
    
  - name: "PhoneRecognizer"
    supported_language: "en"
    patterns:
      - name: "US_PHONE"
        regex: '\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'
        score: 0.5

# Confidence thresholds
threshold: 0.5  # 0.0-1.0, higher = fewer false positives
allow_list:
  - "example@example.com"  # Whitelist specific values
  
# Context enhancement
context_words:
  PERSON:
    - "name"
    - "patient"
    - "customer"
  PHONE_NUMBER:
    - "phone"
    - "tel"
    - "mobile"
presidio_anonymizer_config.yaml
yaml# Anonymization Operators
anonymizers:
  DEFAULT:
    type: "replace"
    new_value: "[REDACTED]"
    
  CREDIT_CARD:
    type: "mask"
    masking_char: "*"
    chars_to_mask: 12
    from_end: false
    
  EMAIL_ADDRESS:
    type: "hash"
    hash_type: "sha256"
    
  PERSON:
    type: "replace"
    new_value: "[PERSON]"
    
  PHONE_NUMBER:
    type: "mask"
    masking_char: "X"
    chars_to_mask: 7
    from_end: true

# Custom operators
custom_operators:
  - name: "synthetic_replacement"
    type: "custom"
    lambda: "lambda x: Faker().name()"
4.2 Vector (Observability Pipeline) Configuration
vector.toml
toml# Data Sources
[sources.application_logs]
type = "file"
include = ["/var/log/app/*.log"]
read_from = "beginning"

# Sensitive Data Detection & Redaction
[transforms.redact_pii]
type = "remap"
inputs = ["application_logs"]
source = '''
  # Email redaction
  email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
  .message = redact!(.message, filters: [email_pattern], redactor: "full")
  
  # Credit card redaction
  cc_pattern = r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'
  .message = redact!(.message, filters: [cc_pattern], redactor: "partial")
  
  # SSN redaction
  ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
  .message = redact!(.message, filters: [ssn_pattern], redactor: "hash")
  
  # Tag sensitive logs
  if contains(string!(.message), "[REDACTED]") {
    .tags.sensitive_data = true
  }
'''

# Routing
[sinks.sanitized_logs]
type = "elasticsearch"
inputs = ["redact_pii"]
endpoint = "http://elasticsearch:9200"
index = "logs-%Y.%m.%d"
4.3 OpenTelemetry Collector Configuration
otel-collector-config.yaml
yamlreceivers:
  otlp:
    protocols:
      grpc:
      http:

processors:
  # Sensitive data filtering
  attributes:
    actions:
      - key: password
        action: delete
      - key: api_key
        action: delete
      - key: authorization
        action: delete
        
  # Redaction processor
  redaction:
    allowed_keys:
      - "user_id"
      - "session_id"
    blocked_values:
      - "SECRET"
      - "PASSWORD"
      - "TOKEN"
      
  # Resource detection
  resourcedetection:
    detectors: [env, system]
    
  # Batch processing
  batch:
    timeout: 10s
    send_batch_size: 1024

exporters:
  otlp:
    endpoint: otel-collector:4317
  logging:
    loglevel: info

service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [attributes, redaction, resourcedetection, batch]
      exporters: [otlp, logging]
4.4 Log4j Configuration (Java)
log4j2.xml
xml<?xml version="1.0" encoding="UTF-8"?>
<Configuration status="WARN">
    <Appenders>
        <Console name="Console" target="SYSTEM_OUT">
            <PatternLayout pattern="%d{HH:mm:ss.SSS} [%t] %-5level %logger{36} - %msg%n"/>
        </Console>
        
        <!-- Rewrite appender for PII redaction -->
        <Rewrite name="Rewrite">
            <AppenderRef ref="Console"/>
            <SensitiveDataPolicy>
                <maskMode>REPLACE</maskMode>
                <mask>*</mask>
                <minScore>0.75</minScore>
                <entitiesToReplace>SSN,EMAIL,CREDIT_CARD</entitiesToReplace>
            </SensitiveDataPolicy>
        </Rewrite>
    </Appenders>
    
    <Loggers>
        <Root level="info">
            <AppenderRef ref="Rewrite"/>
        </Root>
    </Loggers>
</Configuration>
4.5 Kritik Parametreler Özeti
ParametreAçıklamaÖnerilen DeğerEtkisiconfidence_thresholdDetection confidence minimum0.5-0.8Yüksek = az FP, kaçan PIImasking_charMasking karakteri* veya XGörsel temsilchars_to_maskKaç karakter maskelenecek75% of totalBalance utility/securityhash_algorithmHash fonksiyonuSHA-256Geri dönüşsüzcontext_windowBağlam kelime sayısı5-10 wordsAccuracy artışıbatch_sizePipeline batch boyutu1000-5000Throughput/latencyallow_listWhitelist entriesDomain-specificFalse positive azaltmadeny_listBlacklist patternsKnown secretsExplicit blockinglog_levelPII scanner log seviyesiWARN/ERRORMetadata leakage önleme

5. Güvenlik Açısından Kritik Noktalar
5.1 Threat Model
T1: Sensitive Data Leakage via Logs

Risk: Production logs'a PII/PHI yazılması
Impact: Compliance violation, data breach
Mitigation:

Pre-production testing
Automated scanning in CI/CD
Real-time alerting



T2: Log Injection Attacks

Risk: Attacker manipüle edilmiş log enjeksiyonu
Impact: Log poisoning, SIEM evasion
Mitigation:

Input validation
Log encoding (OWASP ESAPI)
Immutable log storage



T3: Insufficient Redaction

Risk: Partial masking ile PII çıkarılabilir
Impact: Data re-identification
Mitigation:

Full redaction or tokenization
K-anonymity principles
Regular audits



T4: Scanner Bypass

Risk: Obfuscated PII scanner'dan kaçabilir
Impact: Undetected sensitive data
Mitigation:

Multi-layer detection
Anomaly-based detection
Regular model updates



T5: Log Tampering

Risk: Audit log'ları modify edilebilir
Impact: Compliance violation, forensics engelleme
Mitigation:

Immutable storage (WORM)
Cryptographic signing
Centralized logging



T6: Access Control Violations

Risk: Unauthorized log access
Impact: Sensitive data exposure
Mitigation:

RBAC implementation
Encryption at rest
Audit access logs



5.2 Secure Implementation Checklist
Development Phase

 Structured logging framework kullan (JSON, Syslog)
 Logging library'ye PII filter ekle
 Unit testler ile PII leakage kontrolü
 Code review'da log statements kontrol et
 Static analysis tools (Bearer, Semgrep) kullan
 Pre-commit hooks ile secret detection
 Developer training dokümante et

Deployment Phase

 Separate logging pipeline (dev/staging/prod)
 TLS 1.3 for log transmission
 Network segmentation (log collectors isolated)
 Least privilege access model
 Regular vulnerability scanning
 Incident response plan hazırla

Operational Phase

 24/7 monitoring ve alerting
 Quarterly compliance audits
 Regular expression pattern updates
 NER model retraining (quarterly)
 Penetration testing (annual)
 Disaster recovery testing

5.3 Common Vulnerabilities & Mitigations
VulnerabilityCWEDescriptionMitigationCleartext LoggingCWE-532Sensitive data plain-textPre-log redactionInformation ExposureCWE-200Log'da aşırı detayMinimal loggingImproper Access ControlCWE-284Log files unrestrictedRBAC + encryptionMissing EncryptionCWE-311Logs transported unencryptedTLS/mTLSInsufficient LoggingCWE-778Security events loglanmıyorComprehensive loggingLog InjectionCWE-117User input log'a geçiyorInput sanitization
5.4 Defense in Depth Strategy
Layer 1: Application Level
├─ Structured logging with sanitizers
├─ Field-level sensitivity tagging
└─ Developer training

Layer 2: Pipeline Level
├─ Real-time PII detection
├─ Automated redaction
└─ Anomaly detection

Layer 3: Storage Level
├─ Encryption at rest (AES-256)
├─ Immutable storage
└─ Access control (IAM/RBAC)

Layer 4: Network Level
├─ TLS 1.3 encryption
├─ Network segmentation
└─ Firewall rules

Layer 5: Monitoring & Response
├─ SIEM integration
├─ Alert on sensitive data detection
└─ Incident response procedures
5.5 Compliance-Specific Security Requirements
GDPR Compliance Security

Article 32 Requirements:

Pseudonymization mandatory
Encryption at rest & in transit
Regular testing (penetration tests)
Data breach notification (<72 hours)


Security Controls:

  - AES-256-GCM encryption
  - TLS 1.3 for transmission
  - Multi-factor authentication
  - Data loss prevention (DLP)
  - Right to erasure implementation
HIPAA Security Rule

§164.312 Technical Safeguards:

Access Control (Unique user IDs)
Audit Controls (immutable logs)
Integrity (checksums, digital signatures)
Transmission Security (end-to-end encryption)


BAA (Business Associate Agreement) gereksinimleri
Minimum Necessary Rule uyumu

PCI-DSS Security Controls

Requirement 10.2: Audit trail events
Requirement 10.3: Log entry elements
Requirement 10.5: Secure audit trails
Requirement 10.6: Log review (daily)

5.6 Incident Response Plan
PII Leakage Incident Response:

Detection (0-1 hour):

Automated alert via SIEM
Triage severity


Containment (1-4 hours):

Isolate affected systems
Stop log forwarding
Preserve evidence


Investigation (4-24 hours):

Scope determination
Root cause analysis
Impact assessment


Remediation (24-72 hours):

Patch vulnerability
Rotate credentials
Update detection rules


Recovery (72+ hours):

Restore normal operations
Enhanced monitoring
Lessons learned


Notification (Per regulation):

GDPR: 72 hours
HIPAA: 60 days
PCI-DSS: Immediately



5.7 Security Testing Methodology
Automated Testing
python# Example: pytest for PII detection
def test_credit_card_redaction():
    log_entry = "Payment with card 4532-1234-5678-9010"
    sanitized = redact_pii(log_entry)
    assert "4532" not in sanitized
    assert "CREDIT_CARD" in sanitized or "****" in sanitized

def test_email_redaction():
    log_entry = "Contact: john.doe@example.com"
    sanitized = redact_pii(log_entry)
    assert "@" not in sanitized or "[EMAIL]" in sanitized
Manual Security Review

Quarterly code review
Log sampling (random 1000 entries)
Regex pattern validation
False positive/negative analysis


6. Kaynaklar ve Referanslar
Teknik Dokümantasyon

Microsoft Presidio Documentation: https://microsoft.github.io/presidio/
OWASP Logging Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
NIST SP 800-92: Guide to Computer Security Log Management
OpenTelemetry Specification: https://opentelemetry.io/docs/specs/otel/

Compliance Frameworks

GDPR Official Text: https://gdpr-info.eu/
HIPAA Security Rule: https://www.hhs.gov/hipaa/for-professionals/security/
PCI-DSS v4.0: https://www.pcisecuritystandards.org/
NIST Cybersecurity Framework: https://www.nist.gov/cyberframework

Research Papers

"Presidio: Context Aware, Pluggable and Customizable Data Protection and De-identification SDK" - Microsoft Research
"A Survey on Personally Identifiable Information (PII) Detection" - IEEE Security & Privacy

Industry Resources

Datadog Sensitive Data Scanner Blog: https://www.datadoghq.com/product/sensitive-data-scanner/
AWS Comprehend PII Detection: https://aws.amazon.com/comprehend/
Bearer Security Blog: https://www.bearer.com/blog/

Open Source Projects

Microsoft Presidio GitHub: https://github.com/microsoft/presidio
Bearer GitHub: https://github.com/Bearer/bearer
Salesforce LogAI: https://github.com/salesforce/logai
DataDog SDS Core: https://github.com/DataDog/dd-sensitive-data-scanner

Additional Tools

pyWhat: https://github.com/bee-san/pyWhat
Trufflehog: https://github.com/trufflesecurity/trufflehog
Gitleaks: https://github.com/gitleaks/gitleaks


7. Sonuç ve Öneriler
7.1 Hızlı Başlangıç Önerileri
Küçük/Orta Ölçekli Projeler için:

Microsoft Presidio (Python SDK)
Vector (lightweight pipeline)
Managed cloud service (Datadog/Splunk)

Enterprise Ölçekli Projeler için:

Presidio + PySpark (big data)
OpenTelemetry Collector + custom processors
Multi-region deployment
Dedicated security team

Compliance-Heavy Ortamlar için:

Full audit trail (immutable logs)
Certified solutions (HIPAA-compliant vendors)
Regular third-party audits
On-premise deployment

7.2 ROI ve Business Impact

Risk Reduction: %80-95 PII leakage riski azaltma
Compliance Cost: GDPR fines (€20M+) önleme
Operational Efficiency: Automated vs manual review
Reputation Protection: Data breach'ten kaçınma

7.3 Gelecek Trendler

AI/ML Evolution: GPT-based PII detection
Zero Trust Logging: Assume breach mentality
Differential Privacy: Statistical guarantees
Homomorphic Encryption: Analyze encrypted logs
Federated Learning: Distributed PII detection
