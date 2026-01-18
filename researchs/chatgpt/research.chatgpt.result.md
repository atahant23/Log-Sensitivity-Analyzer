Log Sensitivity Analyzer — Teknik Araştırma Raporu
-------------------------------------------------------

Not: “Log Sensitivity Analyzer” terimi literatürde tekil bir ürün olarak yer almasa da; kavramsal olarak log verilerindeki anormalliklerin, duyarlılıkların (sensitivity/anomaly) tespit edildiği analiz sistemleri veya bu tür sistemlerin komponentleri olarak ele alındı. Bu raporda bu teknolojinin genel çalışma prensiplerinden, endüstri uygulamalarına ve açık kaynak alternatiflerine kadar kapsamlı bir çerçeve sunuyorum.

1)  Temel Çalışma Prensipleri
_____________________________________  
 Log Analizi Nedir?

Log analizi, sistemler tarafından otomatik oluşturulan olay kayıtlarının (log) toplanması, işlenmesi, yorumlanması ve anlamlı bilgiye dönüştürülmesi sürecidir. Bu işlem hataları tespit etme, performansı izleme, güvenlik olaylarını ortaya çıkarma gibi amaçlarla yapılır.

 Duyarlılık / Sensitivity Analizi Kavramı

Burada “sensitivity” terimi anomali tespiti veya norm dışı davranış belirleme anlamını taşır: bir log girişinin normal davranıştan ne kadar sapmış olduğu. Özellikle güvenlik bağlamında bu sapmalar saldırı, kötüye kullanım veya hatalı konfigürasyon belirtisi olabilir.

Bu analiz genellikle statik eşiklere değil dinamik davranış modellerine göre yapılır ve makine öğrenimi algoritmalarıyla desteklenir.

 Çalışma Adımları

Aşağıdaki temel akış çoğu modern log duyarlılık/analiz sisteminde bulunur:

Log Toplama: Sunucular, uygulamalar, ağ cihazları vb. kaynaklardan logların toplanması.

Normalizasyon & Parse Etme: Farklı formatların ortak bir yapıya dönüştürülmesi.

Özellik Çıkarımı: Zaman damgası, seviye (error/info), IP adresi, kullanıcı vb. değerlerin çıkarılması.

Modelleme / Sensitivity Scoring: Anomali skorları üreten modeller (ör. Isolation Forest, sezgisel eşikler, içerik benzerliği) uygulanır.

Uyarı & Korelasyon: Anormal aktiviteler tespit edildiğinde uyarı üretme, olayları ilişkisel olarak bağlama.

2)  Best Practices & Endüstri Standartları
 ___________________________________________
 En İyi Uygulama Metodolojileri
 Centralize Log Collection

Veriler merkezi bir konumda toplanmalı (ör. SIEM). Bu, bağlam analizi ve ilişkisel korelasyona izin verir.

 Normalize Etme ve Zenginleştirme

Log formatları farklı olduğundan normalize etmek ve örneğin IP’ye ASN bilgisi gibi üst veri eklemek sistem duyarlılığını artırır.

 Anomali Tespiti Modelleri

Statik kurallar yerine anomaly detection teknikleri kullanmak daha duyarlı sonuç verir:

Makine öğrenimi / istatistiksel modeller

Zaman serisi analizi

İçerik tabanlı anomaliler (pattern/sequence)

 Sürekli Öğrenme & Geri Besleme

Modeller çevresel değişikliklere göre güncellenmeli — örneğin trafik tipleri değişince sıradan davranış kalıpları da değişir.

 Uyarı Gürültüsünü Azaltma (False Positives)

Yanıltıcı uyarıları engellemek için ayarlanabilir eşikler, bağlamsal filtreleme ve model geçerlilik kontrolleri kullanılmalı.

3)  Benzer Açık Kaynak Projeler / Rakipler
______________________________________________

Aşağıdaki araçlar, log verilerini toplayan/analyze eden projelerdir; duyarlılık analizi için temel alt yapı sağlar:

 Log Yönetimi / SIEM / Log Analiz Araçları
Araç	Tür	Özellik
Graylog	OSS log management	Merkezi log toplama + arama/filtreleme (özellikle SIEM use-case)
OSSEC	Host-based IDS	Log analizi + uyarı oluşturma motoru
Sagan	Log analiz	Snort tabanlı kural işleme & gerçek zamanlı analiz
Fluentd / Fluent Bit	Log toplama	Log forwarding / pipeline oluşturma
Octopussy	Log analiz	Syslog izleme + alarm sistemi
 Akademik / Research İlgili Projeler

LogAI: Log analizi için ML destekli kütüphane (özetleme, kümeleme, anomaliler).

LogPrécis: LLM-temelli kötü niyetli log analiz aracı.

LogBERT, LogGD gibi modeller: transformer / GNN tabanlı anomalilik tespiti araştırmaları.

Önemli: Bu araçların birçoğu doğrudan “sensitivity analyzer” ismiyle anılmasa da log duyarlılık (anomali/sensitivity) tespiti için kullanılabilir.

4)  Kritik Yapılandırma Dosyaları ve Parametreler
 ____________________________________________________
 SIEM / Log Analiz Platformları

Her platformun yapılandırması farklıdır ama ortak kritik parametreler:

Kaynak tanımları (hostnames, log pathler)

Parser kuralları (regex veya JSON / syslog parsing)

Anomali tespiti modelleri (threshold seviyeleri / model parametreleri)

Alarm eşikleri (critical/major/minor trigger seviyeleri)

Zaman senkronizasyonu (NTP, timestamp normalize)

Örnek:

Graylog pipeline kuralları (rule order, koşullar vb.)

OSSEC ossec.conf / custom rule set

Sagan signature/rule dosyaları

Bu parametreler, false positive/negative oranını doğrudan etkiler.

5)  Güvenlik Açısından Kritik Hususlar
____________________________________________
 Log Bütünlüğü

Loglar değiştirilmemeli; dijital imza / HMAC ile korunabilir. Bu, saldırganın izlerini silmesini zorlaştırır.

 Erişim Kontrolleri

Log depolarına yalnızca yetkili kullanıcı erişmeli; izinsiz erişim log analizini bozar.

 Zaman Senkronizasyonu

Log zaman damgaları doğru olmalı; analiz ve korelasyon için NTP gibi güvenilir kaynaklar kullanılmalı.

 Veri Koruma / Kişisel Veri

Loglarda PII (kişisel veri) varsa uygun maskeleme/anonymization yapılmalı (bazı araçlar bu desteği sağlar).

 Model Güvenilirliği

ML tabanlı anomali modelleri yanlış konfigüre edilirse false alarm üretir; modele düzenli validasyon yapılmalı.
