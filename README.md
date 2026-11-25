# Otomatik Zafiyet Tarayıcı (Kara Kutu / Black-Box Web Güvenlik Tarayıcısı)

Hedef web uygulamalarının kaynak koduna erişim gerektirmeden (tamamen **Kara Kutu / Black-Box** yaklaşımıyla) adres haritasını çıkaran, içine girdi (input) kabul eden sayfaları ve login ekranlarını tespit eden, bu noktalara HTTP istekleri gönderip yanıt metinlerini analiz eden modüler, Python tabanlı bir güvenlik denetim aracıdır.

> **Yasal Uyarı:** Bu araç yalnızca sahibi olduğunuz veya yazılı izin aldığınız sistemlerde (ve yerel laboratuvar ortamlarında) kullanılmalıdır. İzinsiz tarama yasa dışıdır (TCK 243-244).

---

## 🚀 Proje Durumu

- **Aktif Mimari:** %100 **Kara Kutu (Black-Box)** Web Keşif, Girdi İstek & Yanıt Analizi ve Web Kontrol Paneli mimarisi.
- **Takvim:** Proje 1 Ekim 2026'da başlamış olup haftalık Gantt iş takvimi için [docs/gantt_semasi.md](docs/gantt_semasi.md) dosyasına bakabilirsiniz.

| Modül / Özellik | Dosya | Durum |
|:---|:---|:---:|
| **Gelişmiş Web Crawler & Adres Haritası** (BFS, `robots.txt`/`sitemap.xml`, form/SPA/modern input süzgeci) | `scanner/crawler.py` | ✅ **Tamamlandı (Çalışıyor)** |
| **HTTP İstek, Request Auto-Login & Yanıt Metni Motoru** (GET/POST, CSRF token, HTTP 401 Basic/Digest, canlı sayfa analizi) | `scanner/input_requester.py` | ✅ **Tamamlandı (Çalışıyor)** |
| **Kara Kutu SQL Injection & Web Güvenlik Denetimi** (`CWE-89`, `CWE-209`, `CWE-598`, `CWE-352`) | `scanner/sqli_analyzer.py` | ✅ **Tamamlandı (Çalışıyor)** |
| **Görsel Web Arayüzü (Kontrol Paneli)** (`ThreadingHTTPServer`, adres haritası filtreleme, canlı `iframe` önizleme) | `web_app.py` / `web_arayuzu.bat` | ✅ **Tamamlandı (Çalışıyor)** |
| **İnteraktif Kara Kutu Ana Menü, CLI & Raporlama** (`logs/` zaman damgalı kayıt) | `main.py` / `tara.bat` | ✅ **Tamamlandı (Çalışıyor)** |

---

## 🛠️ Kurulum ve Çalıştırma

Projeyi yerel ortamınıza çekip hemen çalıştırmak için aşağıdaki adımları izleyebilirsiniz:

### 1. Repoyu Klonlayın
```bash
git clone https://github.com/mucoiks/ZaafiyetTarayici.git
cd ZaafiyetTarayici
```

### 2. Sanal Ortamı (venv) Kurun ve Paketleri Yükleyin
**Windows (Otomatik Kurulum):**
```cmd
tara.bat
```
veya **Manuel Kurulum (Windows / Linux / macOS):**
```bash
python -m venv venv
# Windows: venv\Scripts\activate
# Linux/macOS: source venv/bin/activate
pip install -r requirements.txt
```

---

## 💻 Kullanım Örnekleri

### Yöntem 1: Web Arayüzü (`web_arayuzu.bat` veya `python web_app.py --open`)
Tarayıcı üzerinden **1. Sitenin Adres Haritası & Input Alabilenler**, **2. Input Noktası Detayları**, **3. Gönderilen İstek Cevapları (Canlı Önizleme)** ve **4. Kara Kutu SQLi & Güvenlik Raporu** sekmelerini görsel olarak yönetebilirsiniz:
```cmd
web_arayuzu.bat
```
veya:
```bash
python web_app.py --open
```
*(Varsayılan adres: `http://127.0.0.1:5000`)*

### Yöntem 2: İnteraktif Kara Kutu Ana Menü (`tara.bat` veya `python main.py`)
Parametre vermeden doğrudan çalıştırdığınızda 5 seçenekli **Kara Kutu Ana Menü** açılır:
```cmd
tara.bat
```
**Ana Menü Seçenekleri:**
- `[1]` **Sitenin Adres Haritası & İçine Input Alabilenleri Listele (Crawler):** Sayfa haritası, form/input süzgeci, parametreler ve `robots.txt`/`sitemap.xml`.
- `[2]` **Keşfedilen Inputlara HTTP İsteği Gönder ve Yanıtları Kontrol Et:** Bulunan formlara ve parametreli URL'lere istek gönderip güncel sayfa/yanıt özetini listeler.
- `[3]` **Kara Kutu SQLi ve Web Güvenlik Denetimi:** Adres haritası ve HTTP yanıtları üzerinden `CWE-89`, `CWE-209`, `CWE-598` ve `CWE-352` denetimi yapar.
- `[4]` **Tam Kapsamlı Kara Kutu Tarama:** Adres Haritası + HTTP İstek Gönderimi + Kara Kutu SQLi Denetimi birlikte çalışır.
- `[5]` **Web Arayüzünü Başlat:** Kontrol panelini (`http://127.0.0.1:5000`) açar.

### Yöntem 3: Komut Satırı (CLI) Modları
```bash
# 1. Sadece Web Crawler (Adres haritası ve input alabilenler)
python main.py --mode crawler --target http://localhost:8080 --dvwa-login

# 2. Keşfedilen inputlara HTTP isteği gönderme
python main.py --mode requester --target http://localhost:8080 --dvwa-login

# 3. Kara Kutu SQLi ve Web Güvenlik Denetimi
python main.py --mode sqli --target http://localhost:8080 --dvwa-login

# 4. Tam Kapsamlı Kara Kutu Tarama (Harita + İstek + SQLi Denetimi)
python main.py --mode full --target http://localhost:8080 --dvwa-login
```

---

## ⚙️ Komut Satırı Parametreleri (`main.py`)

| Parametre | Varsayılan | Açıklama |
|---|---|---|
| `--mode` | `crawler` | Çalışma modu: `crawler`, `requester`, `sqli`, `sqli-passive`, `full`. |
| `--target` | *(Zorunlu)* | Taranacak izinli hedef web sitesi URL'si (Örn: `http://localhost:8080`). |
| `--max-pages` | `100` | Taranacak maksimum geçerli sayfa sayısı üst limiti. |
| `--max-depth` | `5` | BFS genişlik öncelikli arama derinlik sınırı. |
| `--dvwa-login` | `False` | DVWA test ortamına otomatik `admin:password` ile giriş yapıp oturumu kullanır. |
| `--cookie` | `None` | Giriş yapılmış oturum çerezi dizesi (`"name=val; name2=val2"`). |
| `--output` | `logs/[hedef]_[mod]_[zaman].txt` | Tarama bulgularının kaydedileceği dosya yolu. |

---

## 📁 Proje Yapısı

```text
├── main.py                     # Ana giriş noktası, SmartHTTPAuth, CLI ve İnteraktif Ana Menü
├── web_app.py                  # Web Kontrol Paneli (ThreadingHTTPServer + REST API)
├── requirements.txt            # Python bağımlılıkları
├── tara.bat / web_arayuzu.bat  # Windows hızlı başlatıcılar
├── docs/
│   └── gantt_semasi.md         # Haftalık proje planı ve Gantt şeması
├── dataset/
│   └── SQL_Dataset.csv         # İnceleme ve araştırma veri seti
└── scanner/
    ├── crawler.py              # Adres haritalama, SPA/React & form/input keşif motoru
    ├── input_requester.py      # GET/POST istek gönderimi, Auto-Login ve yanıt analizi
    └── sqli_analyzer.py        # Kara kutu SQL Injection ve web güvenlik denetçisi
```

---

## 👥 Ekip
- **Mücahit Haşim İPEK** (1230606809)
- **Necat AKYÜZ** (1220606005)
- **Ders Danışmanı:** Prof. Dr. Ercan BULUŞ
