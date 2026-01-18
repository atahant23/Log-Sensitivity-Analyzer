Log Sensitivity Analyzer Teknik Araştırma Raporu
Hazırlanma Tarihi: 19 Ocak 2026
Hazırlayan: AI Research Analyst
Rapor No: LSA-TECH-2026-01

1. Temel Çalışma Prensipleri
Log Sensitivity Analyzer (LSA), sistem ve uygulama loglarında hassas verilerin otomatik olarak tespit edilmesini ve sınıflandırılmasını sağlayan bir güvenlik ve uyumluluk aracıdır. Temel amacı, PCI-DSS, HIPAA, GDPR gibi düzenlemelere aykırı olabilecek kişisel, finansal veya gizli bilgilerin loglarda saklanmasını önlemektir.

1.1. Mimari Bileşenleri
LSA genellikle üç ana bileşenden oluşur:

Log Ingestion Layer: Logları toplar (Syslog, JSON, Plain Text, Kafka, Splunk, ELK vb.)
Pattern Recognition Engine: Hassas veri desenlerini tanımlar (Regex, ML modelleri, NLP)
Classification & Alerting Module: Bulunan verileri sınıflandırır ve ilgili ekiplere uyarı gönderir
1.2. Algılama Yöntemleri
a) RegEx Tabanlı Algılama
regex
12
# Örnek: Kredi kartı numarası
\b(?:\d[ -]*?){13,16}\b
b) Makine Öğrenmesi (ML) Tabanlı Algılama
Sınıflandırıcılar (SVM, Random Forest, BERT tabanlı modeller)
Anomali tespiti ile yeni tür hassas verilerin bulunması
c) Kontekst Tabanlı Analiz
“Password”, “SSN”, “Credit Card” gibi anahtar kelimelerle birlikte geçen değerler
Verinin log satırındaki konumu ve çevresi
1.3. İş Akışı
mermaid
Prensip
Açıklama
Minimal Logging
Sadece gerekli verileri logla. Hassas verileri loglamadan önce maskele.
Contextual Redaction
Sadece değer değil, bağlam da önemlidir. Örn: password=**** yerine password=[REDACTED]
Immutable Logs
Logların değiştirilemez olması için WORM (Write Once Read Many) depolama kullan.
2.2. Endüstri Standartları
PCI-DSS v4.0 Requirement 10.5: Loglarda hassas veri (kredi kartı, CVV) saklanamaz.
HIPAA Security Rule §164.308(a)(1): PHI (Protected Health Information) loglarda korunmalı.
GDPR Article 32: Kişisel verilerin işleme sırasında güvenliği sağlanmalı.
2.3. Best Practices Listesi
✅ Loglarda Hassas Veri Olmamalı
→ Kullanıcı adı, şifre, token, kimlik numarası, kredi kartı vs. loglanmamalı.

✅ Dinamik Masking Uygula
→ Örn: email=j***@g***.com, ssn=***-**-****

✅ Loglara Etiketleme Yap
→ sensitivity_level: high, data_type: pii, source_app: payment_gateway

✅ Günlük Skanlama ve Raporlama
→ Otomatik skanlarla haftalık raporlar üret ve合规 (compliance) takibi yap.

✅ Loglara Erişim Kontrolü
→ RBAC (Role-Based Access Control) ile sadece yetkili kullanıcılar loglara erişebilmeli.
3. Benzer Açık Kaynak Projeler ve Rakipler
3.1. Açık Kaynak Alternatifler
Proje Adı
Tanım
Lisans
Link
LogSentinel
Hassas veri algılama ve masking için Python tabanlı araç
MIT
https://github.com/logsentinel
Presidio (Microsoft)
PII (Personally Identifiable Information) tespiti ve redaksiyonu
MIT
https://github.com/microsoft/presidio
OpenSearch Security Plugin
Loglarda hassas veri tespiti ve filtreleme
Apache 2.0
https://opensearch.org/docs/latest/security-plugin/index/
Apache NiFi
Veri akışında hassas veri tespiti ve maskelenmesi
Apache 2.0
https://nifi.apache.org
3.2. Ticari Rakipler
Ürün
Şirket
Özellikler
Splunk Enterprise Security
Splunk Inc.
PII detection, compliance reporting, UEBA entegrasyonu
Datadog Log Management
Datadog
Regex-based redaction, GDPR/PCI-DSS compliance
Elastic SIEM + Logstash Filter
Elastic NV
Grok ve Ruby filter ile hassas veri maskesi
Sumo Logic
Sumo Logic
Cloud-native log security, sensitive data scanning

4. Kritik Yapılandırma Dosyaları ve Parametreleri
4.1. Ana Yapılandırma Dosyası: config.yaml
yaml
123456789101112131415161718192021222324252627282930
# config.yaml
sensitivity_levels:
  - level: high
    patterns:
      - regex: "\b\d{16}\b"
        description: "Credit Card Number"
        action: mask
      - regex: "\b\d{3}-\d{2}-\d{4}\b"
        description: "SSN"
        action: redact

4.2. Desen Tanımlama Dosyası: patterns.json
json
12345678910111213141516
{
  "patterns": [
    {
      "name": "CreditCard",
      "regex": "\\b(?:\\d[ -]*?){13,16}\\b",
      "type": "PII",
      "severity": "high"
    },
    {
      "name": "Email",

4.3. Ortam Değişkenleri (Environment Variables)
bash
12345
LOG_SENSITIVITY_ENABLED=true
LOG_MASKING_REPLACEMENT="***"
LOG_PATTERN_FILE=/etc/lsa/patterns.json
LOG_ALERT_THRESHOLD=10
LOG_STORAGE_PATH=/var/log/lsa/

5. Güvenlik Açısından Dikkat Edilmesi Gereken Kritik Noktalar
5.1. Hassas Veri Sızıntısı Riskleri
❗ Loglarda düz metin şifre/SSN/kart numarası saklanması → PCI-DSS ihlali
❗ Log dosyalarına yetkisiz erişim → Insider threat riski
❗ Log analiz araçlarının kendi loglarında hassas veri tutması → Kendi kendini tehdit etme
5.2. Güvenlik Kontrolleri
Kontrol
Açıklama
Encryption at Rest
Log dosyaları AES-256 ile şifrelensin
Access Auditing
Kim ne zaman hangi loga erişti, kaydedilsin
Tamper Detection
Log dosyalarının hash’i alınarak değişiklik tespiti yapılsın
Secure Transport
Syslog over TLS, HTTPS, gRPC+TLS gibi güvenli protokoller kullanılmalı
5.3. Güvenlik Yarışları (Race Conditions)
Log Yazma vs. Skanlama: Log yazılırken skanlama işlemi başlarsa eksik veri tespit edilebilir.
→ Çözüm: Log yazma tamamlandıktan sonra skanlama başlat.
Concurrent Access: Birden fazla thread aynı log dosyasına yazarken bozulma olabilir.
→ Çözüm: File locking veya queue-based ingestion.
5.4. Güvenlik Testi Önerileri
✅ Penetration Testing: Log sistemi üzerinde sızıntı testi yap.
✅ Red Team Exercise: Hassas veri içeren loglarla sahte istekler gönder.
✅ Compliance Scan: PCI-DSS, HIPAA, SOC2 uyumluluğu otomatik skanla.
