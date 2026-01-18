Log Sensitivity Analyzer Detaylı Teknik Araştırma Raporu
Log Sensitivity Analyzer, log dosyalarında hassas verilerin (PII, credentials, finansal bilgiler) otomatik tespiti ve sınıflandırılması için geliştirilmiş AI/ML tabanlı analiz teknolojisidir; anomaly detection ve pattern recognition ile güvenlik risklerini minimize eder. Bu detaylı rapor, temel prensiplerden security best practices'e kadar genişletilmiş analiz sunar, açık kaynak log management araçları ve spesifik konfigürasyon örnekleriyle desteklenmiştir.
​

Temel Çalışma Prensipleri
Log Sensitivity Analyzer'lar, log ingestion, parsing, normalization ve detection katmanlarından oluşur. İlk aşamada OpenTelemetry Collector veya Fluent Bit gibi ajanlar logları toplar, Logstash/Grok pattern'leri ile yapılandırır; ML modelleri (örneğin LSTM sequence anomaly detection) baseline'lerden sapmaları tespit eder. Hassas veri tespiti için regex (credit card: \b(?:\d[ -]*?){13,16}\b), entropy skorlama (yüksek entropi=potansiyel key) ve NER (Named Entity Recognition) modelleri kullanılır; false positive'leri azaltmak için context-aware scoring uygulanır.
​
​

Best Practices ve Endüstri Standartları
Structured JSON logging, log levels (ERROR/WARN production-only) ve retention (90 gün GDPR) standarttır; SigNoz/Graylog gibi araçlarda custom quick filters ve stream processing ile noise azaltılır. NIST 800-92 ve MITRE ATT&CK framework'üne uyum için UEBA (User Entity Behavior Analytics) entegrasyonu, backpressure handling (Kafka buffering) ve alerting (PagerDuty/Slack) zorunludur. Deployment pitfalls: storage 3-5x log volume planlama, RBAC ile access control.
​
​

Benzer Açık Kaynak Projeler ve Rakipler
Açık kaynak ekosistemde SigNoz (unified observability, columnar DB 2.5x hızlı query), Graylog (enterprise streams, Elasticsearch backend) ve ELK Stack (full-text search) liderdir; Loki label-based indexing ile storage'ı 10x azaltır. Ticari rakipler Splunk/Datadog olup, Wazuh security-focused anomaly detection sunar.
​
​

Araç	Collection	Analysis	Sensitivity Detection	Performans
SigNoz 
​	✅ OTLP/FluentD	✅ ML anomaly	✅ Log correlation	50% az resource
Graylog 
​	✅ Beats	✅ Streams	✅ Threat intel	30-60k logs/sn
Loki 
​	✅ Promtail	✅ LogQL	⚠️ Label-based	10x storage save
ELK 
​	✅ Logstash	✅ Kibana	✅ Grok patterns	Petabyte scale
Vector 
​	✅ Rust-native	✅ VRL transform	✅ Routing	Milyon events/sn
Kritik Yapılandırma Dosyaları ve Parametreleri
YAML/JSON konfigürasyonlar baskındır: SigNoz'da log-config.yaml (serviceName filter, retention_days:90), Graylog'ta graylog.conf (elasticsearch_hosts, stream_rules). Kritik params: threshold (anomaly_score>0.8 alert), buffer_size (10000 events), grok_patterns (%{IP:client_ip}), bloom_filters (query accel), culture_info (timestamp parse). Örnek ELK logstash.conf:
​
​

text
input { file { path => "/var/log/*.log" } }
filter { grok { match => { "message" => "%{COMBINEDAPACHELOG}" } } }
output { elasticsearch { hosts => ["localhost:9200"] } }
Nodinite'te RMS level ve Environment (PROD/TEST).
​

Güvenlik Kritik Noktaları
PII accidental exposure riski için filter plugins (PII scrubber), TLS encryption ve disk buffering zorunlu; JVM-based araçlarda (Logstash) memory leaks izlenmeli. Common pitfalls: default configs'ta auth yok, storage overflow data loss; çözümler RBAC, encryption-at-rest ve anomaly alerting. LOTL saldırılarına karşı sudo/SSH detailed logging, compliance için audit trails (syslog-ng signing)
