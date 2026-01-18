# Log Sensitivity Analyzer – Teknik Araştırma Raporu

> Tarih: 18 Ocak 2026

## 1) Temel Çalışma Prensipleri

**Amaç:** Uygulama ve altyapı loglarında yer alan kişisel veriler (PII/PHI), ödeme verileri (PCI) ve sır niteliğindeki bilgiler (anahtarlar, token’lar, parolalar) tespit edilip **maskelenir/anonimleştirilir**, böylece regülasyon ve güvenlik gereksinimleri karşılanır. citeturn1search73turn1search49

**Tespit yaklaşımları**
- **Kural/regex tabanlı tanımlayıcılar:** Kredi kartı, e‑posta, SSN gibi kalıpları bulur; yakınlık (proximity) anahtar kelimeleri ve checksum doğrulaması ile güçlendirilebilir. AWS CloudWatch Logs “managed data identifiers” ve “custom data identifiers” ile bu yöntemi sunar. citeturn1search43turn1search47
- **ML/NLP tabanlı tanıma:** İsim, adres, serbest metin PII gibi biçimsiz veriler için makine öğrenimi ve NER kullanır (ör. **Google Cloud DLP** ve **Microsoft Presidio**). citeturn1search25turn1search85
- **Entropi/anahtar sızıntısı tespiti:** Yüksek entropili dizeleri ve bilinen anahtar kalıplarını bulur (örn. **detect-secrets**, **TruffleHog**). citeturn1search110turn1search96

**Uygulama noktaları (pipeline aşamaları)**
- **Kaynakta/agent’te maskeleme:** Örn. Logback/Log4j2’de desen ile maskeleme; Fluent Bit/Collector filtreleri. citeturn1search90turn1search102
- **Toplayıcı/Collector üzerinde:** **OpenTelemetry Collector** `redaction`, `attributes`, `transform` işlemcileri ile log/trace/metric üzerinde maskeleme. citeturn1search104turn1search105
- **Arka uç/SIEM’de:** **Splunk** (props.conf / transforms.conf SEDCMD/regex), **Elastic** ingest pipeline `gsub` ile. citeturn1search13turn1search31
- **Bulut servisinde:** **AWS CloudWatch Logs Data Protection**, **Google Cloud Sensitive Data Protection (DLP)**. citeturn1search43turn1search25

**Anonimleştirme teknikleri**
- **Redaction/Masking:** Değerleri yıldızlama/placeholder’a çevirme; CloudWatch ve Datadog varsayılan maskeleme ve “unmask” yetkisi ile çalışır. citeturn1search43turn1search19
- **Hash/Tokenizasyon/Pseudonymization:** Tek yönlü iz sürme için hash; kısmi maskeleme; Datadog kural aksiyonları (redact/partial redact/hash/mask) destekler. citeturn1search20

---

## 2) En İyi Uygulamalar (Best Practices) ve Endüstri Standartları

- **Gerektiği kadar logla (Data minimization):** Amaç için gerekli asgari kişisel veri loglanmalı; GDPR/UK GDPR madde 5(1)(c) veri minimizasyonu. citeturn1search65
- **Güvenli loglama tasarımı:** OWASP Logging Cheat Sheet; hassas alanları asla loglama, yapılandırılmış log, saat damgası, kullanıcı/istek kimliği, fakat parola/anahtarları hariç tut. citeturn1search73
- **NIST SP 800‑92 rehberliği:** Merkezî toplama, saat senkronizasyonu, bütünlük/erişim kontrolü; olay yanıtını besleyen kayıt bileşenleri. citeturn1search49
- **ISO/IEC 27001:2022 A.8.15 (Logging):** Olayların tespit/incelemesi için logların oluşturulması, korunması, erişim yetkileri ve inceleme süreçleri. citeturn1search78turn1search80
- **PCI DSS:** Kart verisi ortamında günlüklerin toplanması/korunması ve periyodik inceleme; Req.10 ve “Effective Daily Log Monitoring” rehberi. citeturn1search50turn1search54
- **HIPAA:** ePHI içeren sistemlerde denetim kontrolleri; çoğu yorum 6 yıl saklama gereksinimine işaret eder (dokümantasyon için). citeturn1search67turn1search71
- **Varsayılan “deny‑list” değil “allow‑list” yaklaşımı:** Collector/agent seviyesinde hangi anahtarların geçeceğini beyaz listeleyin (OTel redaction/attributes). citeturn1search103turn1search104
- **Erişim kontrolü ve unmask izinleri:** Maske kaldırma (ör. `logs:Unmask` yetkisi – AWS) sadece yetkili rollere verilmeli; Datadog’da RBAC ve `data_scanner_unmask`. citeturn1search43turn1search23
- **Yaşam döngüsü ve saklama:** Regülasyon/iş ihtiyacına göre saklama süresi; eski logların yeniden işlenmesi mümkün değilse (örn. CloudWatch), geriye dönük maskeleme için re‑ingest planlayın. citeturn1search43

---

## 3) Benzer Açık Kaynak Projeler ve Rakipler

**Açık Kaynak**
- **Microsoft Presidio** – PII tespiti/anonimleştirme (NER + regex + sözlük), metin ve görseller; özelleştirilebilir tanıyıcılar. citeturn1search85
- **detect‑secrets (Yelp)** – Kod/tabanlı loglarda yüksek entropi, regex ve anahtar kelime tabanlı sır tespiti; pre‑commit ve CI entegrasyonu. citeturn1search108turn1search110
- **TruffleHog** – 800+ dedektör, doğrulama (secret canlı mı) ve çoklu kaynak taraması (git, dosya, S3, loglar). citeturn1search97turn1search96
- **OpenTelemetry Collector** – `redaction/attributes/transform` işlemcileriyle telemetri veri temizleme. citeturn1search104turn1search105
- **Elastic (Elasticsearch) Ingest Pipelines** – `gsub` ile PII maskeleme. citeturn1search31
- **Logback/Log4j2 maskleme eklentileri** – PatternLayout/Converter/RewritePolicy ile JSON/XML maskeleri. citeturn1search90turn1search116

**Ticari/Rakip Ürünler**
- **AWS CloudWatch Logs Data Protection** – Yönetilen ve özel tanımlayıcılar, maskeleme, `logs:Unmask` izni, bulgu metrikleri. citeturn1search43
- **Google Cloud Sensitive Data Protection (DLP)** – 100+ infoType, gerçek zamanlı redaksiyon/tokenizasyon entegrasyonları. citeturn1search25
- **Datadog Sensitive Data Scanner** – Kapsamlı tarama ve aksiyonlar (redact/partial/hash/mask) + RBAC. citeturn1search19turn1search20
- **Sentry (self‑host dahil)** – Sunucu tarafı veri scrubbing ve gelişmiş kurallar. citeturn1search41turn1search37
- **Splunk** – Index‑time sed/regex anonimleştirme; Edge/Heavy Forwarder ve field filter’lar. citeturn1search13turn1search16

> **Not:** GitHub’da *Log‑Sensitivity‑Analyzer* adlı örnek repo ve çatallar mevcuttur; kavram/prototip için referans niteliğindedir. citeturn1search2turn1search6

---

## 4) Kritik Yapılandırma Dosyaları ve Parametreler

**AWS CloudWatch Logs**
- *Policy JSON:* Data Protection Policy (audit + deidentify), managed/custom data identifiers, maskeleme ve bulguların hedefe yönlendirilmesi (CW Logs/S3/Firehose). Terraform `aws_cloudwatch_log_data_protection_policy_document` kaynağıyla üretilebilir. citeturn1search43turn1search44

**Google Cloud DLP**
- *DLP Deidentify API:* `projects.locations.content.deidentify` ile metin redaksiyonu; infoType listesi ve yer tutucu belirleme. citeturn1search25

**Datadog**
- *Scanning Groups & Rules:* Ürün bazlı kapsam (Logs/APM/RUM), aksiyonlar (redact/partial/hash/mask), yetkiler (`data_scanner_read/write/unmask`). citeturn1search20

**OpenTelemetry Collector**
- *processors.redaction/attributes/transform (YAML):* İzinli anahtarlar (allow‑list), `delete/update/hash` eylemleri; log/trace/metric boru hattına eklenir. citeturn1search103turn1search104

**Splunk**
- *props.conf / transforms.conf:* `SEDCMD` ve regex `TRANSFORMS` ile index‑time maskeleme; Splunk dokümantasyonu ve topluluk örnekleri. citeturn1search13turn1search14

**Elastic / OpenSearch**
- *Ingest Pipeline:* `gsub` işlemcisi ile regex değiştirme; OpenSearch’te benzer `gsub` işlemcisi. citeturn1search31turn1search34

**Uygulama Log Çerçeveleri**
- *Logback:* Özel `PatternLayout`/masking layout ile PII gizleme. citeturn1search90
- *Log4j2:* Regex/RewritePolicy/Converter tabanlı maskeleme. citeturn1search116

**Fluent Bit / Fluentd**
- *Filter zinciri:* Kayıtları çıkışa gitmeden önce dönüştürme/anonymize; Fluentd `fluent-plugin-anonymizer` ve Fluent Bit filtreleri. citeturn1search7turn1search10

---

## 5) Güvenlik Açısından Dikkat Edilecek Kritik Noktalar

1. **Yanlış negatif/pozitif riski:** Regex/ML mutlak değildir; Presidio ve GCP DLP de tam kapsama garantisi vermez—operasyonel kontrollerle destekleyin. citeturn1search85turn1search25
2. **Geriye dönük maskeleme:** CloudWatch’ta policy sonrası gelen loglar maskelenir; eski loglar otomatik maskelenmez. Arşivleri yeniden işleme stratejisi belirleyin. citeturn1search43
3. **Unmask yetkisi ve erişim kontrolü:** “Görünür hâle getirme” sadece yetkili rollerle sınırlı olmalı (AWS `logs:Unmask`, Datadog RBAC). citeturn1search43turn1search23
4. **Bütünlük ve gizlilik:** Logların aktarımı/atıl durumda şifreleme, imzalama ve dosya bütünlük izleme (PCI/NIST tavsiyeleri). citeturn1search50turn1search49
5. **Saklama ve silme politikaları:** GDPR/HIPAA/ISO gereksinimlerine uyumlu saklama; gereğinden fazla tutmayın (minimizasyon). citeturn1search65turn1search67
6. **Performans/latency etkisi:** Ağır regex/ML tespiti throughput’u etkileyebilir; collector/ingest düğümlerini ölçekleyin (Elastic ingest/OTel pratikleri). citeturn1search36turn1search104
7. **Geliştirici hijyeni:** Uygulama tarafında “kaçınma” ilkesi—parola/token asla loglanmasın; OWASP rehberini “shift‑left” kod gözden geçirme ve CI gizli anahtar tarayıcılarıyla (detect‑secrets/TruffleHog) tamamlayın. citeturn1search73turn1search96

---

## Hızlı Uygulama Örnekleri

**A) OpenTelemetry Collector ile maskeleme (YAML)**
```yaml
processors:
  redaction:
    allowed_keys: ["http.status_code","service.name","trace_id"]  # kalan anahtarlar kaldırılır
  attributes/sanitize:
    actions:
      - key: user.email
        action: delete
      - key: payment.card_number
        action: delete
      - key: client.ip
        action: hash
service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [redaction, attributes/sanitize]
      exporters: [debug]
```
Bu yapılandırma yalnızca izinli anahtarları geçirir; e‑posta ve kart numarasını siler, IP’yi hash’ler. citeturn1search103turn1search104

**B) Splunk index‑time maskeleme**
```ini
# props.conf
[sourcetype::secure_logs]
SEDCMD-maskpass = s/(password=)[^&\s]+/$1********/g

# transforms.conf (alternatif)
[mask_api]
REGEX = (?i)(apikey=)[^&\s]+
FORMAT = $1[REDACTED]
DEST_KEY = _raw
```
Index’e yazmadan önce parolayı ve API anahtarlarını maskeler. citeturn1search18turn1search13

**C) Elastic ingest pipeline ile `gsub`**
```json
PUT _ingest/pipeline/pii_mask
{
  "processors": [
    {"gsub": {"field": "message", "pattern": "(email=)[^,&\n]+", "replacement": "$1[REDACTED]"}},
    {"gsub": {"field": "message", "pattern": "(cc=)[0-9-]+", "replacement": "$1****"}}
  ]
}
```
İndeksleme sırasında e‑posta ve kart alanlarını maskeleyip depolar. citeturn1search31

**D) AWS CloudWatch Logs – Data Protection Policy (özet)**
- Yönetilen tanımlayıcıları seçin (ör. EmailAddress, CreditCardNumber), `deidentify.mask_config` ile maskeleme; `logs:Unmask` olanlar ham veriyi görebilir. citeturn1search43

**E) Datadog Sensitive Data Scanner – kural aksiyonları**
- Tarama grubu oluşturun, kural kütüphanesinden seçin veya regex yazın; “mask/hash/partial redact/redact” aksiyonları ve unmask izniyle yönetim. citeturn1search20

---

## Sonuç

"Log Sensitivity Analyzer" konsepti; tespit (regex/ML/entropi), işlem (mask/hash/tokenize) ve politika/erişim (RBAC/unmask) katmanlarının bir araya getirilmesiyle hayata geçirilir. Yukarıdaki standartlar ve pratikler; üretim ortamlarında **hukuki uyum** ve **operasyonel görünürlük** dengesini kurmanıza yardımcı olur. citeturn1search73turn1search49
