# Otomatik Zafiyet Tarayıcı (Zaafiyet Tarayıcı)

Hedef web uygulamalarında yaygın güvenlik zafiyetlerini otomatik tespit eden, bulguları risk seviyesiyle raporlayan ve düzeltme önerisi sunan modüler, Python tabanlı bir güvenlik denetim aracıdır.

> **Yasal Uyarı:** Bu araç yalnızca sahibi olduğunuz veya yazılı izin aldığınız sistemlerde (ve yerel laboratuvar ortamlarında) kullanılmalıdır. İzinsiz tarama yasa dışıdır (TCK 243-244).

---

## 🚀 Proje Durumu
- **Aktif Faz:** **Faz 1 — Web Keşif Motoru (Crawler)** tamamlandı ve çalışır durumda.
- **Takvim:** Proje 1 Ekim 2026'da başlamış olup haftalık Gantt iş takvimi için [docs/gantt_semasi.md](docs/gantt_semasi.md) dosyasına bakabilirsiniz.

| Faz | Modül / Özellik | Durum |
|:---:|:---|:---:|
| **Faz 1.1** | **Gelişmiş Web Crawler (BFS, Derinlik Takibi, Form/Parametre Keşfi, robots.txt)** | ✅ **Tamamlandı (Çalışıyor)** |
| **Faz 1.2** | SQL Injection Tespit Modülü (CWE-89) | ⏳ Sırada (15 - 22 Ekim) |
| **Faz 1.3** | Cross-Site Scripting (XSS) Modülü (CWE-79) | ⏳ Planlandı (22 - 29 Ekim) |
| **Faz 1.4** | CLI Çıktısı, Loglama ve Faz 1 Doğrulama | ✅ **Tamamlandı** |
| **Faz 2** | Port Tarama ve HTTP Güvenlik Başlıkları Analizi | ⏳ Planlandı |
| **Faz 3** | CVE/NVD Eşleştirme ve Risk Skorlama | ⏳ Planlandı |
| **Faz 4** | Web Arayüzü (Opsiyonel / Flask) | ⏳ Planlandı |

---

## 🛠️ Kurulum ve Çalıştırma

Projeyi yerel ortamınıza çekip hemen çalıştırmak için aşağıdaki adımları izleyebilirsiniz:

### 1. Repoyu Klonlayın
```bash
git clone https://github.com/mucoiks/ZaafiyetTarayici.git
cd ZaafiyetTarayici
```

### 2. Sanal Ortamı (venv) Kurun ve Paketleri Yükleyin
**Windows:**
```cmd
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

**Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 💻 Kullanım Örnekleri

### Yöntem 1: Tek Tıkla Başlatıcı (Windows İçin `tara.bat`)
Windows kullanıcıları komut yazmadan doğrudan `tara.bat` dosyasını çalıştırabilir veya çift tıklayabilir:
```cmd
tara.bat
```

### Yöntem 2: Komut Satırı (CLI)

**Herhangi bir hedef web sitesini taramak:**
```bash
python main.py --target http://testphp.vulnweb.com --max-depth 2 --max-pages 30
```

**Yerel DVWA laboratuvarını otomatik oturum açarak taramak:**
```bash
python main.py --target http://localhost:8080 --dvwa-login --max-depth 3
```

**Harici oturum çerezi (Cookie) ile yetkili tarama yapmak:**
```bash
python main.py --target https://hedef-site.local --cookie "PHPSESSID=abc123xyz; security=low"
```

---

## ⚙️ Komut Satırı Parametreleri

| Parametre | Varsayılan | Açıklama |
|---|---|---|
| `--target` | *Zorunlu* | Taranacak hedef URL adresi. |
| `--max-depth` | `3` | BFS genişlik öncelikli arama derinlik sınırı (sonsuz döngüleri engeller). |
| `--max-pages` | `50` | Taranacak maksimum sayfa sayısı üst limiti. |
| `--dvwa-login` | `False` | DVWA test ortamına otomatik `admin:password` ile giriş yapıp çerezi kullanır. |
| `--cookie` | `None` | Giriş yapılmış oturum çerezi dizesi (`"name=val; name2=val2"`). |
| `--output` | `logs/[hedef]_[zaman].txt` | Tarama bulgularının kaydedileceği dosya yolu. |

---

## 🧪 Test Ortamı (DVWA)
1. Docker yüklüyse DVWA konteynerini başlatın:
   ```bash
   docker run --rm -p 8080:80 vulnerables/web-dvwa
   ```
2. Tarayıcıda `http://localhost:8080/setup.php` sayfasına gidip **"Create / Reset Database"** butonuna tıklayın.
3. Tarayıcıyı çalıştırın:
   ```bash
   python main.py --target http://localhost:8080 --dvwa-login
   ```

---

## 👥 Ekip
- **Mücahit Haşim İPEK** (1230606809)
- **Necat AKYÜZ** (1220606005)
- **Ders Danışmanı:** Prof. Dr. Ercan BULUŞ
