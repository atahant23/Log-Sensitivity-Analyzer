Log Sensitivity Analyzer — Teknik Araştırma Raporu
Not: “Log Sensitivity Analyzer” ifadesi literatürde/ürün ekosisteminde tek bir standart ürün adı olarak yaygın görünmüyor. Aramalar genelde “loglarda hassas veri tespiti / redaction (maskeleme) / sınıflandırma” problemini ve buna yönelik bileşenleri işaret ediyor. Bu rapor, endüstride “log sensitivity analysis” olarak anlaşılan konuyu (loglarda PII/secret/PCI/PHI tespiti, sınıflandırma ve redaksiyon) merkeze alır ve bunu yapan yaygın araç/standartlarla ilişkilendirir.
Paylaştığınız görsel sadece araştırma dosya isimlerini gösteriyor: research.genspark.chat_link.txt, research.genspark.prompt.md, research.genspark.result.md, research.genspark.sources.md (yani bir Markdown rapor şablonu/çıktı yapısı) Source

İçindekiler
Temel çalışma prensipleri
Best Practices & endüstri standartları
Açık kaynak benzerleri ve rakipler
Kritik yapılandırmalar ve parametreler
Güvenlik açısından kritik noktalar
Kaynaklar
1) Temel çalışma prensipleri
Bir “Log Sensitivity Analyzer” tipik olarak aşağıdaki işlevleri bir arada veya ayrı modüller halinde uygular:

1.1. Veri keşfi (Detection / Inspection)
Amaç: Log içeriğinde “hassas” sayılan veri tiplerini yakalamak:

Secrets: API key, token, private key, DB credential vb.
PII/PHI/PCI: e‑posta, telefon, IP, kimlik numarası, kart numarası, sağlık verisi vb.
Kurumsal gizli veri: müşteri no, sipariş no, erişim anahtarı gibi özel pattern’ler
Tespit yaklaşımları:

Regex / pattern tabanlı eşleştirme: En yaygın yaklaşım; hızlıdır ama false positive/false negative riski taşır. Örn. Grafana Alloy loki.secretfilter regex tabanlı çalışır ve Gitleaks kural dosyası yapısını kullanır Source.
Entropy (rastgelelik) tabanlı filtreleme: Özellikle “generic key” gibi geniş kurallarda yanlış pozitifleri azaltmak için kullanılır. loki.secretfilter içinde enable_entropy seçeneği vardır Source.
Allowlist / istisna listeleri: Bilinen güvenli değerleri veya sahte pozitifleri hariç tutar (örn. test dataları).
DLP sınıflandırıcıları / managed servisler: Bulut servisleriyle (örn. AWS Macie, CloudWatch Logs data protection) loglarda hassas veri tespiti yapılabilir Source Source.
1.2. Sınıflandırma (Sensitivity classification)
Tespit edilen bulguların “etiketlenmesi”:

Örn. Public / Internal / Confidential / Restricted veya PII/PCI/Secret gibi taksonomiler
Amaç: Depolama, erişim, maskeleme, uyarı ve retention kararlarının otomasyonu
OWASP, log event’lerinin tutarlı sınıflandırılması (type/severity/confidence) gerektiğini vurgular Source.

1.3. Redaction / masking / hashing (Sanitization)
Tespit edilen hassas verinin:

Tam maskeleme: ***REDACTED***
Kısmi maskeleme: ilk/son N karakteri gösterme
Hashing: korelasyon için (aynı token tekrarını yakalamak) ama geri döndürülemez
Silme / alan düşürme: structured log’larda belirli field’ları tamamen kaldırma
Örnek: OpenTelemetry .NET log redaction, custom processor ile attribute’larda redaction yapılmasını örnekler Source.

1.4. Pipeline yerleşimi (Nerede çalışır?)
“Log Sensitivity Analyzer” üç yerde konumlanabilir:

Uygulama içinde (SDK / logger middleware): En erken nokta; en az sızıntı. OTel .NET örneği bu yaklaşımı gösterir Source.
Agent/Collector üzerinde (log forwarder / OTel Collector / Fluent Bit / Alloy / Vector): Merkezi kontrol; farklı kaynaklar için tek politika.
Backend üzerinde (SIEM / log platformu ingest pipeline): En kolay devreye alınır ama “data already left the system” riski artar (özellikle SaaS).
2) Best Practices & endüstri standartları
2.1. Loglamada “veri minimizasyonu” (en kritik prensip)
OWASP “Data to exclude” bölümünde; session ID, access token, password, encryption keys, cardholder data vb. hassas unsurların loglara doğrudan yazılmaması, gerekirse maskelenmesi/hashed edilmesi gerektiğini söyler Source.

Pratik kural:
“Redaction sonradan yapılır” yaklaşımı yerine “en başta loglama yapma” tercih edilir.

2.2. Standartlaştırılmış log şeması ve alan bazlı kontrol
Structured logging (JSON/logfmt) kullanıp:
Hangi field’ların hassas olduğunu schema ile belirleyin (user.email, auth.token, payment.pan vb.)
Field bazlı redaction daha düşük hata oranı üretir (regex ile tüm satırda aramak yerine)
2.3. “Defense-in-depth”: Çok katmanlı redaction
Uygulama katmanında: obvious secrets/PII yazılmasın
Collector katmanında: ikinci bir güvenlik ağı
Backend katmanında: erişim kontrolü + index-time redaction + role-based view
2.4. Log güvenliği: bütünlük, erişim, saklama
OWASP; logların yetkisiz erişim/tahrifat/silme gibi risklere karşı korunmasını, erişimlerin ayrıca loglanmasını, güvenli aktarım (TLS) ve at-rest korumayı vurgular Source.

AWS CloudWatch Logs “data protection” dokümanı; TLS 1.2/1.3 kullanımı, encryption at rest, KMS ile anahtar yönetimi gibi pratikleri özetler Source.

2.5. Operasyonel best practice: Test & doğrulama
Redaction kuralları için unit test setleri (true positive / false positive / edge case)
Sahte pozitiflerin “allowlist” ile kontrollü yönetimi
Pipeline performans testi (yük altında regex maliyeti)
“Redaction coverage” metriği: kaç log satırı/alanı maskelendi? Hangi rule tetikliyor?
Grafana Alloy loki.secretfilter ayrıca metrikler sunar (kaç secret redacted, allowlisted vs.) Source.

3) Benzer açık kaynak projeler ve rakipler
3.1. Açık kaynak (doğrudan veya building block olarak)
Microsoft Presidio
Metin/structured data üzerinde PII tespiti ve anonimleştirme/redaction çerçevesi Source
Gitleaks
Repo/file/stdin üzerinde secret tespiti (regex kural setleri ile) Source
Alloy loki.secretfilter’ın kural modeli Gitleaks config yapısını baz alır Source.
TruffleHog
Secret discovery / classification / validation odaklı tarama Source
detect-secrets (Yelp)
Plugin+filter yapısı ile secret detection; false positive azaltma için filtre yaklaşımı Source
Vector VRL (pipeline transform)
Log pipeline’da transform fonksiyonlarıyla redaction yaklaşımına altyapı sağlar (VRL fonksiyon referansı) Source
3.2. Ticari / platform rakipleri (log üzerinde hassas veri tarama & redaction)
Datadog — Sensitive Data Scanner
“pattern matching” ile hassas veri tespit/etiketleme/redact/hashing (Datadog dokümanında konumlanıyor) Source
Elastic — Redact processor
Ingest pipeline’da Grok patterns ile metin gizleme (redact) Source
AWS — CloudWatch Logs data protection + Macie ile workflow
CloudWatch Logs tarafında masking + genel data protection yaklaşımı Source
Macie ile CloudWatch loglarını S3’e akıtıp tarama/izolasyon/alerting yapan referans mimari Source
4) Kritik yapılandırma dosyaları ve parametreleri
Bu bölüm, pratikte bir “Log Sensitivity Analyzer” kurarken en kritik knobs/parametreleri özetler.

4.1. Grafana Alloy: loki.secretfilter (örnek “log satırı redaction” bileşeni)
Bu bileşen log satırlarında secret redaction yapar; Gitleaks config yapısına dayalı custom config kabul eder Source.

Öne çıkan parametreler

gitleaks_config: özel gitleaks.toml yolu
types: hangi secret tiplerinin taranacağı (performans için kritik)
include_generic: generic rule’ları açar (false positive riski)
enable_entropy: entropy filtreleme (false positive azaltma)
allowlist: regex allowlist
partial_mask: ilk N karakteri göster
redact_with: redaction formatı (örn. <REDACTED-SECRET:$SECRET_NAME>)
Ayrıca bileşen “PII kapsam dışı olabilir” ve “false positive/over-redaction” uyarısı yapar; tek başına yeterli görülmemeli Source.

4.2. OpenTelemetry .NET: SDK seviyesinde redaction
OTel .NET örneğinde “custom processor” ile log attribute’ları üzerinde redaction yapılır; regex veya field-name tabanlı stratejiler önerilir Source.

Kritik knobs

Hangi attribute key’leri “sensitive field” sayılacak?
Regex seti (email, card, token, vs.)
Partial redaction vs full redaction kararı
Processor zincir sırası (redaction export’tan önce olmalı)
4.3. Elastic Ingest: redact processor
Elastic “redact processor”, Grok patterns ile input dokümandaki metni maskeler Source.

Kritik knobs (genel ingest mantığı)

Grok pattern kalitesi (false positive/negative)
Hangi field’larda uygulanacağı
Index-time redaction mı, query-time kontrol mü?
4.4. Bulut (AWS): CloudWatch Logs + Macie pattern’i
Macie ile CloudWatch loglarının S3’e aktarılıp taranması, hassas içerik çıkarsa izolasyon bucket’ına taşıma + SNS ile bildirim gibi bir referans workflow sunuluyor Source.

Kritik knobs

Log export/stream (Firehose/subscription filter)
KMS ile şifreleme
Tarama periyodu / olay tetikleme
“custom data identifier” (kuruma özel pattern’ler)
5) Güvenlik açısından dikkat edilmesi gereken kritik noktalar
5.1. En büyük risk: Hassas verinin logda “kalıcı” hale gelmesi
OWASP; token, parola, anahtar, kart verisi gibi öğelerin loglara yazılmamasını açıkça listeler Source.
Redaction yapıyor olsanız bile:

Redaction öncesi ham log bir yerde buffer’lanıyor mu?
Exporter/agent ham veriyi dışarı çıkarıyor mu?
5.2. Log injection / log forging
OWASP; CR/LF ve delimiter karakterleriyle log injection riskine dikkat çeker, event data’nın sanitize edilmesini önerir Source.

5.3. Erişim kontrolü ve “loglara erişimin loglanması”
Loglar hem operasyonel hem güvenlik verisi taşır; kim okudu/indirdi sorgusu denetlenmelidir Source.

5.4. Şifreleme (in transit / at rest) ve anahtar yönetimi
AWS CloudWatch Logs; at-rest encryption (varsayılan), KMS ile anahtar yönetimi ve TLS ile aktarımı vurgular Source.

5.5. Yanlış pozitif / aşırı redaction ile gözlemlenebilirlik kaybı
Özellikle “generic API key” gibi kurallar:

Aşırı redaction → debug ve incident response zorlaşır
Bu nedenle:
types ile kapsam daraltma (Alloy uyarısı: “tüm tipler resource-intensive”) Source
Entropy filtreleme (enable_entropy) Source
Allowlist
