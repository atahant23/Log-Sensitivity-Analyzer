Log Sensitivity Analyzer Teknik Araştırma Raporu
1. Temel Çalışma Prensibi
Log Sensitivity Analyzer, günlük (log) dosyalarında bulunan hassas verilerin tespit edilmesi, analizi ve korunması için kullanılan bir araç/tekniktir. Temel çalışma prensipleri şunlardır:
1.1. Hassas Veri Tipleri Tespiti

Düzenli İfadeler (Regex) Kullanımı: Kredi kartı numaraları, TCKN, telefon numaraları, e-posta adresleri gibi yapılandırılmış verilerin tespiti.
Anahtar Kelime Tabanlı Tarama: "password", "secret", "token", "key" gibi hassas anahtar kelimelerin bulunması.
Model Tabanlı Tespit: Makine öğrenmesi modelleri kullanarak anormal veri desenlerinin tespiti.

1.2. Bağlamsal Analiz

Log kayıtlarının yapısını anlama.
Hassas verilerin hangi bağlamda kullanıldığını analiz etme.
Yanlış pozitifleri azaltmak için bağlamsal filtreleme.

1.3. Risk Puanlama

Tespit edilen hassas verilere risk skorları atama.
Veri sınıflandırması (hassas, gizli, genel kullanım).
Risk tabanlı önceliklendirme.

Kaynaklar:

NIST Special Publication 800-92: Guide to Computer Security Log Management
OWASP Logging Cheat Sheet
PCI DSS Requirement 10: Track and Monitor All Access to Network Resources

2. En İyi Uygulama Yöntemleri ve Endüstri Standartları
2.1. En İyi Uygulamalar
2.1.1. Log Yönetim Politikaları

Log Rotasyonu: Log dosyalarının düzenli olarak döndürülmesi ve arşivlenmesi.
Retention Politikaları: Yasal ve düzenleyici gerekliliklere uygun saklama süreleri.
Merkezi Log Toplama: Tüm logların merkezi bir sistemde toplanması (SIEM sistemleri).

2.1.2. Hassas Veri Maskeleme

Real-time Masking: Loglara yazılmadan önce hassas verilerin maskelenmesi.
Post-process Masking: Varolan loglardaki hassas verilerin sonradan maskelenmesi.
Kısmi Masking: Sadece hassas kısımların maskelenmesi (ör: kredi kartı son 4 hanesi gösterilmesi).

2.1.3. Erişim Kontrolleri

Role-Based Access Control (RBAC): Loglara erişimde rol tabanlı yetkilendirme.
Audit Logging: Log analiz sistemine erişimlerin kayıt altına alınması.
Minimum Privilege Prensibi: Sadece ihtiyaç duyulan loglara erişim izni verilmesi.

2.2. Endüstri Standartları
2.2.1. Yasal ve Düzenleyici Çerçeveler

GDPR: Kişisel verilerin işlenmesi ve korunması.
HIPAA: Sağlık verilerinin güvenliği.
PCI DSS: Ödeme kartı verilerinin güvenliği.
ISO 27001: Bilgi güvenliği yönetim sistemi.

2.2.2. Teknik Standartlar

CEE (Common Event Expression): Log formatı standardı.
SCAP (Security Content Automation Protocol): Güvenlik otomasyonu standardı.
RFC 5424: Syslog protokolü standardı.

Kaynaklar:

ISO/IEC 27035: Information Security Incident Management
NIST Cybersecurity Framework
CIS Controls v8

3. Benzer Açık Kaynak Projeler ve Rakipler
3.1. Açık Kaynak Çözümler
3.1.1. Logstash (Elastic Stack)

Açıklama: Veri toplama, dönüştürme ve gönderme pipeline'ı.
Hassas Veri Filtreleri: Grok filtreleri, mutate plugin'leri.
Özellikler: Regex tabanlı veri maskeleme, alan kaldırma.

3.1.2. Fluentd

Açıklama: Cloud-native veri toplayıcı.
Hassas Veri İşleme: Plugin tabanlı mimari.
Özellikler: Record Transformer plugin, regex desteği.

3.1.3. Graylog

Açıklama: Tam özellikli log yönetim platformu.
Hassas Veri Yönetimi: Content Pack'ler, extractor'lar.
Özellikler: Pipeline kuralları, regex desteği.

3.1.4. Apache NiFi

Açıklama: Veri akışı yönetim sistemi.
Hassas Veri İşleme: Processor'lar ve Controller Service'ler.
Özellikler: ReplaceText, MaskContent processor'ları.

3.2. Ticari Rakipler
3.2.1. Splunk Enterprise

Özellikler: Field masking, anonymization, data classification.
Fiyatlandırma: GB başına lisanslama.
Güçlü Yönler: Gelişmiş arama ve analitik özellikler.

3.2.2. Datadog Log Management

Özellikler: Sensitive Data Scanner, Pattern detection.
Fiyatlandırma: GB başına tüketim modeli.
Güçlü Yönler: Cloud-native, entegrasyon zenginliği.

3.2.3. Sumo Logic

Özellikler: Sensitive Data Protection, Compliance monitoring.
Fiyatlandırma: GB başına abonelik.
Güçlü Yönler: Machine Learning tabanlı anormallik tespiti.

Kaynaklar:

Elastic Stack Documentation
Fluentd Official Documentation
Splunk Security Essentials

4. Kritik Yapılandırma Dosyaları ve Parametreleri
4.1. Temel Yapılandırma Dosyaları
4.1.1. Düzenli İfade (Regex) Kütüphaneleri
patterns/
├── pii_patterns.conf      # Kişisel tanımlanabilir bilgi desenleri
├── pci_patterns.conf      # Ödeme kartı desenleri
├── healthcare_patterns.conf # Sağlık verisi desenleri
└── custom_patterns.conf   # Kurumsal özel desenler

4.1.2. Politika Yapılandırma Dosyaları
policies/
├── data_classification.yaml  # Veri sınıflandırma politikaları
├── masking_rules.yaml        # Maskeleme kuralları
├── retention_policies.yaml   # Saklama politikaları
└── alert_rules.yaml          # Uyarı kuralları

4.1.3. Sistem Yapılandırması
config/
├── analyzer_config.yaml     # Analizör ana konfigürasyonu
├── scanner_config.yaml      # Tarayıcı konfigürasyonu
├── storage_config.yaml      # Depolama konfigürasyonu
└── api_config.yaml          # API konfigürasyonu

4.2. Kritik Parametreler
4.2.1. Tarama Parametreleri
scanning:
  batch_size: 1000           # Toplu işlem boyutu
  max_threads: 8             # Maksimum thread sayısı
  timeout_seconds: 300       # Timeout süresi
  scan_depth: 10             # Dosya sistemi tarama derinliği

4.2.2. Desen Eşleştirme Parametreleri
pattern_matching:
  min_confidence: 0.85       # Minimum güven skoru
  max_false_positive: 0.05   # Maksimum yanlış pozitif oranı
  context_window: 50         # Bağlam penceresi boyutu
  enable_fuzzy_matching: true # Bulanık eşleştirme

4.2.3. Performans Parametreleri
performance:
  memory_limit_gb: 4         # Bellek limiti
  cpu_limit_percent: 80      # CPU limiti
  io_throttle: medium        # G/Ç kısıtlama seviyesi
  cache_size_mb: 512         # Önbellek boyutu

Kaynaklar:

GitHub: Various open-source log analyzer configurations
Elasticsearch: Index and search configuration best practices
Docker: Container resource limits documentation

5. Güvenlik Açısından Kritik Noktalar
5.1. Veri Gizliliği Riskleri
5.1.1. Log Sızıntıları

Hassas verilerin plain text olarak loglanması.
Debug loglarında üretim verilerinin bulunması.
Stack trace'lerde hassas bilgilerin açığa çıkması.

5.1.2. Yetkisiz Erişim

Log dosyalarına aşırı geniş erişim izinleri.
Log analiz arayüzlerinde yetersiz yetkilendirme.
API endpoint'lerinde authentication eksikliği.

5.2. Sistem Güvenliği Riskleri
5.2.1. Enjeksiyon Saldırıları

Log query'lerinde SQL/NoSQL enjeksiyonu.
Komut enjeksiyonu riskleri.
Log parser'larda buffer overflow.

5.2.2. Hizmet Dışı Bırakma (DoS)

Büyük log dosyalarının işlenmesi sırasında kaynak tüketimi.
Kötü niyetli büyük log dosyaları ile saldırı.
Regex tabanlı DoS (ReDoS) saldırıları.

5.3. Mitigasyon Stratejileri
5.3.1. Savunma Derinliği

Ağ Katmanı: Firewall kuralları, network segmentation.
Uygulama Katmanı: Input validation, output encoding.
Veri Katmanı: Encryption at rest, encryption in transit.

5.3.2. Güvenlik Kontrolleri
security_controls:
  authentication:
    enable_mfa: true
    session_timeout: 900
    max_login_attempts: 3
    
  authorization:
    role_based_access: true
    attribute_based_access: false
    audit_all_access: true
    
  encryption:
    data_at_rest: AES-256-GCM
    data_in_transit: TLS 1.3
    key_rotation_days: 90

5.3.3. İzleme ve Uyarı

Anormal log erişim pattern'lerinin tespiti.
Real-time security alert'ler.
Otomatik incident response tetikleyicileri.

5.4. Denetim ve Uyumluluk
5.4.1. Audit Trail

Tüm yapılandırma değişikliklerinin loglanması.
Kullanıcı eylemlerinin tam izlenebilirliği.
Değişiklik yönetimi süreçleri.

5.4.2. Compliance Reporting

Otomatik compliance raporları.
Regülasyonlara özel dashboard'lar.
Evidence collection otomasyonu.
