Log Sensitivity Analyzer: Teknik Araştırma Raporu
1. Temel Çalışma Prensipleri
Log Sensitivity Analyzer sistemleri, yapılandırılmamış veya yarı yapılandırılmış log verileri içindeki riskli bilgileri tanımlamak için çok katmanlı bir analiz süreci kullanır:

Veri Yakalama ve Ayrıştırma (Ingestion & Parsing): Loglar (Syslog, JSON, XML vb.) sisteme akar. Analizör, log satırlarını anlamlı alanlara ayırır.

Örüntü Eşleştirme (Regex & Dictionaries): Kredi kartı numaraları, TC Kimlik numaraları, IP adresleri veya e-posta gibi belirli formatlara sahip verileri bulmak için düzenli ifadeler (Regex) kullanılır.

Doğal Dil İşleme (NLP) ve ML: Sabit formatı olmayan (örneğin; bir hata mesajı içindeki özel konuşmalar) hassas verileri tespit etmek için Named Entity Recognition (NER) gibi makine öğrenmesi modelleri kullanılır.

Sınıflandırma ve Puanlama: Tespit edilen veriler "Kritik", "Hassas" veya "Düşük Risk" olarak etiketlenir.

Maskeleme/Anonimleştirme (Redaction): Hassas veri kalıcı olarak silinir, yıldızlanır (****) veya geri döndürülemez şekilde hash'lenir.

2. En İyi Uygulama Yöntemleri (Best Practices) ve Endüstri Standartları
Log yönetimi sadece teknik bir süreç değil, aynı zamanda uyumluluk (compliance) gerekliliğidir.

Kaynağında Temizlik (Shift-Left): En iyi yöntem, verinin log sunucusuna gitmeden önce uygulama katmanında (Log library seviyesinde) temizlenmesidir.

En Az Yetki İlkesi (Principle of Least Privilege): Ham loglara sadece belirli sistem yöneticilerinin erişimi olmalı, analiz edilmiş ve temizlenmiş loglar genel kullanıma açılmalıdır.

Standartlara Uyumluluk:

GDPR/KVKK: Kişisel verilerin loglarda açıkça tutulmaması zorunluluğu.

PCI-DSS: Kredi kartı bilgilerinin (PAN) asla loglanmaması gerekliliği.

SOC2 & ISO 27001: Log bütünlüğü ve erişim denetimi standartları.

Düzenli Denetim: "False negative" (kaçırılan hassas veri) oranını düşürmek için analizör kuralları periyodik olarak güncellenmelidir.

3. Benzer Açık Kaynak Projeler ve Rakipler
Piyasada bu işi yapan hem bulut tabanlı devler hem de güçlü açık kaynak araçlar bulunmaktadır:

Açık Kaynak Araçlar:
Microsoft Presidio: Python tabanlı, NLP kullanan oldukça popüler bir veri temizleme ve anonimleştirme kütüphanesidir.

Go-Guardian: Log akışları üzerinde gerçek zamanlı hassas veri taraması yapan hafif bir araçtır.

Nightfall (OSS SDKs): Veri kaybı önleme (DLP) odaklı geliştirici araçları sunar.

Ticari Rakipler ve Kurumsal Çözümler:
Amazon Macie: AWS üzerindeki S3 logları ve veri setlerinde hassas verileri ML ile tespit eder.

Google Cloud DLP: Loglar dahil her türlü metin akışında 150'den fazla veri tipini tespit edip maskeleyebilir.

Datadog Sensitive Data Scanner: Loglar sisteme girdiği anda gerçek zamanlı tarama ve maskeleme yapar.

4. Kritik Yapılandırma Dosyaları ve Parametreleri
Bir analizörün etkinliği yapılandırma keskinliğine bağlıdır. Genelde şu parametreler kritiktir:

detection_rules.yaml: Hangi verinin hassas sayılacağını belirleyen Regex dizinleri.

threshold (Eşik Değeri): ML modellerinin bir veriyi "hassas" olarak etiketlemesi için gereken güven skoru (Örn: 0.85).

redaction_strategy: Verinin nasıl gizleneceği (Masking, Hashing, Tokenization veya Full Deletion).

exclusion_list (Beyaz Liste): Yanlış pozitifleri (False Positives) önlemek için tarama dışı bırakılacak güvenli alanlar veya anahtar kelimeler.

5. Güvenlik Açısından Dikkat Edilmesi Gereken Noktalar
Analizörün Kendisi Hedef Olabilir: Analizörün yapılandırma dosyalarına erişen bir saldırgan, hangi verilerin gizlendiğini öğrenerek filtreleri bypass edebilir.

Performans Kaygısı (Latency): Gerçek zamanlı analiz, log iletiminde gecikmeye neden olabilir. Bu durum, siber saldırı anında sistemin kör kalmasına yol açabilir.

Kalıntı Veri: Maskeleme sonrası logların yedeklerinde (backups) hala temizlenmemiş verilerin kalıp kalmadığı kontrol edilmelidir.

Şifreleme: Analizörden geçen loglar, depolama alanına (Data Lake/SIEM) gitmeden önce mutlaka "at-rest" (dururken) şifrelenmelidir.
