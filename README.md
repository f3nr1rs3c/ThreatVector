# ThreatVector - CVSS v3.1 Vector Calculator

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![GUI](https://img.shields.io/badge/GUI-Tkinter-red?style=flat-square)

Penetrasyon Testi ve zafiyet yönetimi süreçlerinde tespit edilen bulguların **CVSS v3.1 (Common Vulnerability Scoring System)** skorlarını ve vektör dizgilerini hızlıca hesaplamak için tasarlanmış, grafik arayüzlü (GUI) ve tamamen bağımsız çalışan bir Python aracıdır.

Özellikle siber güvenlik uzmanları ve Red Team üyeleri için tasarlanmış koyu renkli (Dark Mode / Red Team) modern bir temaya sahiptir.

## ✨ Özellikler

- **Tam CVSS 3.1 Uyumluluğu:** Standart "Base Score" algoritmalarını birebir ve hassas şekilde hesaplar.
- **Gerçek Zamanlı Hesaplama:** Metrikleri seçtiğiniz anda vektör, skor ve kritiklik seviyesi (Low, Medium, High, Critical) anında güncellenir.
- **Dinamik Renklendirme:** Ortaya çıkan skora göre severity (kritiklik) seviyesi otomatik olarak uygun renklerle vurgulanır.
- **Sıfır Bağımlılık (Zero-Dependency):** PyQt veya CustomTkinter gibi ekstra kütüphaneler kurmanıza gerek kalmadan, yalnızca Python'un yerleşik `tkinter` kütüphanesiyle çalışır. Her ortamda anında kullanıma hazırdır.
- **Tek Tıkla Kopyalama:** Raporlarınıza anında ekleyebilmeniz için hesaplanan vektör dizgisini tek tıkla panoya kopyalama özelliği.
- **Çift Dilli Arayüz:** Uluslararası terminolojiye hakimiyet için metrik terimlerinin İngilizce asılları ve Türkçe karşılıkları bir arada sunulmuştur.

## 🚀 Kurulum & Kullanım

Araç, dışarıdan hiçbir kütüphane bağımlılığı gerektirmez. Standart bir Python 3 ortamında doğrudan çalıştırılabilir.

1. Depoyu bilgisayarınıza indirin veya `ThreatVector.py` dosyasını kopyalayın.
2. Terminal veya Komut İstemcisi üzerinden dosyanın bulunduğu dizine gidin:
   ```bash
   cd "C:\Path\To\CVSS Vektör"
   ```
3. Aracı başlatın:
   ```bash
   python ThreatVector.py.py
   ```

## 🖥️ Arayüz

<img width="900" height="886" alt="image" src="https://github.com/user-attachments/assets/7d0b83cf-5fc4-4c8c-870e-827cd40803c5" />

Araç içerisinde sol tarafta sömürülebilirlik metrikleri (Attack Vector, Complexity vb.), sağ tarafta ise etki metrikleri (Confidentiality, Integrity vb.) yer almaktadır. En alt kısımda ise anlık skoru, vektör dizgisini ve kopyalama butonunu bulabilirsiniz.

## 📋 Metrikler (Metrics)

Hesaplayıcı aşağıdaki standart CVSS 3.1 metriklerini baz alır:
- **AV:** Attack Vector (Saldırı Vektörü)
- **AC:** Attack Complexity (Saldırı Karmaşıklığı)
- **PR:** Privileges Required (Gereken Ayrıcalıklar)
- **UI:** User Interaction (Kullanıcı Etkileşimi)
- **S:** Scope (Kapsam)
- **C:** Confidentiality (Gizlilik)
- **I:** Integrity (Bütünlük)
- **A:** Availability (Erişilebilirlik)

## 👤 Geliştirici

**Made by Sirius**

Bu araç, saha testleri ve ofansif güvenlik çalışmaları sırasında hızlı metrik hesaplamaları yapılabilmesi için oluşturulmuş pratik bir yardımcı araçtır.
