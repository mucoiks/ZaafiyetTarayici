# Otomatik Zafiyet Tarayıcı (Zaafiyet Tarayıcı)

Hedef web uygulamalarında yaygın güvenlik zafiyetlerini otomatik tespit eden, bulguları risk seviyesiyle raporlayan ve düzeltme önerisi sunan modüler, Python tabanlı bir güvenlik denetim aracıdır.

> **Yasal Uyarı:** Bu araç yalnızca sahibi olduğunuz veya yazılı izin aldığınız sistemlerde (ve yerel laboratuvar ortamlarında) kullanılmalıdır. İzinsiz tarama yasa dışıdır (TCK 243-244).

---

## 🚀 Proje Durumu
- **Aktif Faz:** **Faz 1.1 (Web Crawler)** ve **Faz 1.2 (Hibrit SQL Injection Denetim & SAST Modülü)** tamamlandı ve çalışır durumda.
- **Takvim:** Proje 1 Ekim 2026'da başlamış olup haftalık Gantt iş takvimi için [docs/gantt_semasi.md](docs/gantt_semasi.md) dosyasına bakabilirsiniz.

| Faz | Modül / Özellik | Durum |
|:---:|:---|:---:|
| **Faz 1.1** | **Gelişmiş Web Crawler (BFS, Derinlik Takibi, Form/Parametre Keşfi, robots.txt)** | ✅ **Tamamlandı (Çalışıyor)** |
| **Faz 1.2** | **Hibrit SQL Injection Denetim ve SAST Kaynak Kod Analiz Modülü (CWE-89 / CWE-209)** | ✅ **Tamamlandı (Çalışıyor)** |
| **Faz 1.3** | Cross-Site Scripting (XSS) Modülü (CWE-79) | ⏳ Sırada (22 - 29 Ekim) |
| **Faz 1.4** | İnteraktif Ana Menü, CLI Çıktısı ve Zaman Damgalı Loglama | ✅ **Tamamlandı** |
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

### Yöntem 1: İnteraktif Ana Menü (`tara.bat` veya `python main.py`)
Parametre vermeden doğrudan çalıştırdığınızda 4 modlu **Ana Menü** açılır:
```cmd
tara.bat
```
veya:
```bash
python main.py
```
**Ana Menü Seçenekleri:**
- `[1]` **Web Keşif Motoru (Sadece Crawler):** Sayfa, form, parametre ve `robots.txt` keşfi.
- `[2]` **Pasif SQLi ve Web Güvenlik Denetimi:** Crawler + Katman 1 (`CWE-89`, `CWE-209`, `CWE-598`, `CWE-352`).
- `[3]` **SAST Kaynak Kod Analizi:** `.php` ve `.py` dosyalarında `CWE-89` SQL Injection ve `Prepared Statement` tespiti.
- `[4]` **Tam Kapsamlı Hibrit Tarama:** Crawler + Pasif SQLi + SAST birlikte.

### Yöntem 2: Komut Satırı (CLI) Modları

```bash
# 1. Sadece Web Crawler modu
python main.py --mode crawler --target http://localhost:8080 --dvwa-login

# 2. Pasif SQLi ve Web Güvenlik Denetimi
python main.py --mode sqli-passive --target http://localhost:8080 --dvwa-login

# 3. SAST Kaynak Kod Analizi (Sunucu gerektirmez)
python main.py --mode sast --source-dir samples/dvwa_sqli_ornekleri

# 4. Tam Kapsamlı Hibrit Tarama (Web + SAST)
python main.py --mode hybrid --target http://localhost:8080 --dvwa-login --source-dir samples/dvwa_sqli_ornekleri
```

---

## ⚙️ Komut Satırı Parametreleri

| Parametre | Varsayılan | Açıklama |
|---|---|---|
| `--mode` | `hybrid` | Çalışma modu: `crawler`, `sqli-passive`, `sast`, `hybrid`. |
| `--target` | `None` | Taranacak hedef web sitesi URL'si (`http://localhost:8080`). |
| `--source-dir` | `None` | SAST (Statik Kaynak Kod Analizi) için `.php` / `.py` klasör veya dosya yolu. |
| `--max-depth` | `3` | BFS genişlik öncelikli arama derinlik sınırı (sonsuz döngüleri engeller). |
| `--max-pages` | `50` | Taranacak maksimum sayfa sayısı üst limiti. |
| `--dvwa-login` | `False` | DVWA test ortamına otomatik `admin:password` ile giriş yapıp çerezi kullanır. |
| `--cookie` | `None` | Giriş yapılmış oturum çerezi dizesi (`"name=val; name2=val2"`). |
| `--output` | `logs/[hedef]_[mod]_[zaman].txt` | Tarama bulgularının kaydedileceği dosya yolu. |

---

## 👥 Ekip
- **Mücahit Haşim İPEK** (1230606809)
- **Necat AKYÜZ** (1220606005)
- **Ders Danışmanı:** Prof. Dr. Ercan BULUŞ
