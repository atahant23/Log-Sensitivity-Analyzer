# 🛡️ Log Sensitivity Analyzer

<p align="left">
  <img src="https://img.shields.io/badge/Language-Python-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/Standard-KVKK%20%2F%20GDPR-lightgrey?style=flat-square" />
  <img src="https://img.shields.io/badge/Category-SecOps%20%7C%20Analyzer-red?style=flat-square" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" />
</p>

**Log Sensitivity Analyzer**, sistem kayıtlarındaki (log) hassas verileri ve sızıntı risklerini derinlemesine analiz eden, veri güvenliğini sağlamak ve regülasyon uyumluluğunu denetlemek için geliştirilmiş bir güvenlik analiz aracıdır.

---

## 📑 İçindekiler

* [Proje Hakkında](#-proje-hakkında)
* [Özellikler ve Analiz Yetenekleri](#-özellikler-ve-analiz-yetenekleri)
* [Teknik Metodoloji](#-teknik-metodoloji)
* [Kurulum](#-kurulum)
* [Kullanım](#-kullanım)
* [Yasal Uyarı](#-yasal-uyarı)

---

## 🎯 Proje Hakkında

Veri güvenliğinin en sessiz ama en tehlikeli sızıntı noktalarından biri olan "Log Dosyaları", genellikle saldırganların veya dikkatsiz yapılandırmaların kurbanı olur. 

Bu araç, log dosyaları içerisindeki PII (Kişisel Veri), kimlik bilgileri ve teknik sırları otomatik olarak tespit ederek veri ihlallerini henüz oluşmadan önlemeyi hedefler.

---

## 🚀 Özellikler ve Analiz Yetenekleri


Proje, aşağıdaki 4 ana disiplin üzerinde özelleşmiş testler uygular:

### 1. 🕵️‍♂️ Hassas Veri (PII/PHI) Analizi
* **Otomatik Tespit:** TCKN, E-posta ve telefon gibi kişisel verilerin loglara sızıp sızmadığını denetler.
* **Finansal Tarama:** Kredi kartı ve IBAN bilgilerini analiz eder.

### 2. 🔑 Kimlik Bilgisi ve Secret Sızıntısı
* **Credential Leak:** Loglardaki açık metin şifreleri ve veritabanı bağlantı dizilerini yakalar.
* **API Key Discovery:** AWS, Google Cloud ve GitHub gibi servislerin sızdırılmış anahtarlarını tespit eder.

### 3. 🎭 Akıllı Maskeleme (Redaction)
* **Veri Gizleme:** Tespit edilen verileri güvenli formatlarda yıldızlar veya hash'ler.

---

## 🛠️ Teknik Metodoloji

Bu araç, analizlerini gerçekleştirirken aşağıdaki standartları referans alır:

| Standart / Protokol | Açıklama |
| :--- | :--- |
| **KVKK & GDPR** | Kişisel verilerin korunması ve anonimleştirilmesi standartları. |
| **NIST SP 800-92** | Bilgisayar güvenlik log yönetimi rehberi. |
| **Regex & NLP** | Karmaşık veri setlerini ayrıştırmak için kullanılan hibrit motor. |

---

## 📥 Kurulum

Projeyi yerel makinenize klonlayın ve gerekli bağımlılıkları yükleyin.

```bash
# Repoyu klonlayın
git clone [https://github.com/EfeSidal/LogSensitivityAnalyzer.git](https://github.com/EfeSidal/LogSensitivityAnalyzer.git)

# Proje dizinine girin
cd LogSensitivityAnalyzer

# Gerekli kütüphaneleri yükleyin
pip install -r requirements.txt

```


⚠️ Yasal Uyarı
Dikkat: Bu yazılım yalnızca eğitim ve izinli güvenlik testleri amacıyla geliştirilmiştir. Sahibi olmadığınız sistemlerde kullanılması yasa dışıdır. Geliştirici, bu aracın kötü niyetli kullanımından doğacak sonuçlardan sorumlu tutulamaz.

<p align="center">Hazırlayan<b>Atahan Turna</b>

Öğrenci Numarası: 2420191030 </p>
