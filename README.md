# Otomatik Zafiyet Tarayıcı

Hedef web uygulamalarında yaygın güvenlik zafiyetlerini otomatik tespit eden, bulguları risk seviyesiyle raporlayan ve düzeltme önerisi sunan Python tabanlı bir araçtır.

> **Yasal uyarı:** Bu araç yalnızca sahibi olduğunuz veya yazılı izin aldığınız sistemlerde kullanılmalıdır. İzinsiz tarama yasa dışıdır. Geliştirme ve testler için DVWA ve OWASP Juice Shop gibi bilerek zafiyetli uygulamalar kullanın.

## Durum
Planlama aşaması. Kod henüz yazılmadı. Takvim için [docs/gantt_semasi.md](docs/gantt_semasi.md), sunum için [docs/on_sunum_taslagi.md](docs/on_sunum_taslagi.md) dosyalarına bakın.

## Özellikler (Hedef)
| Faz | Özellik | Durum |
|-----|---------|-------|
| 1 | Web crawler (link ve form keşfi) | Planlandı |
| 1 | SQL Injection tespiti | Planlandı |
| 1 | XSS tespiti | Planlandı |
| 2 | Port tarama | Planlandı |
| 2 | HTTP güvenlik başlığı analizi | Planlandı |
| 2 | Dizin listeleme tespiti | Planlandı |
| 2 | HTML rapor | Planlandı |
| 3 | CVE/NVD eşleştirme ve risk skorlama | Planlandı |
| 4 | Web arayüzü (opsiyonel) | Planlandı |

## Mimari
```
Hedef URL -> Crawler -> Tarama Modülleri -> Risk Skorlama -> Rapor
```

## Önerilen Dizin Yapısı
```
zafiyet-tarayici/
├── main.py
├── config.py
├── requirements.txt
├── scanner/
│   ├── crawler.py
│   ├── sqli_scanner.py
│   ├── xss_scanner.py
│   ├── port_scanner.py
│   ├── header_analyzer.py
│   ├── dir_scanner.py
│   └── cve_checker.py
├── reporter/
│   ├── console_report.py
│   ├── html_report.py
│   └── templates/
├── data/
├── web/            # Faz 4 (opsiyonel)
├── tests/
└── docs/
```

## Kurulum (Hedef)
```bash
git clone <repo-url>
cd zafiyet-tarayici
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt
```

Başlangıç bağımlılıkları: `requests`, `beautifulsoup4`, `jinja2`, `python-nmap`.

## Test Ortamı
1. Docker kurun.
2. DVWA'yı çalıştırın: `docker run --rm -p 8080:80 vulnerables/web-dvwa`
3. Aracı yalnızca `http://localhost:8080` üzerinde deneyin.

## Kullanım (Hedef Arayüz)
```bash
python main.py --target http://localhost:8080 --modules sqli,xss --output rapor.html
```
Henüz uygulanmadı; parametreler geliştirme sırasında değişebilir.

## Geliştirme Kuralları
- Her tarama modülü ortak bir arayüze uymalı (`scan(target) -> list[Finding]`).
- Her bulgu: tür, URL, parametre, risk seviyesi, kanıt ve **düzeltme önerisi** içermeli.
- İstekler `timeout` ile yapılmalı, hedefe aşırı yük bindirilmemeli (istek aralığı).
- Her modül için DVWA üzerinde test yapılmalı.

## Kaynaklar
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [NVD API](https://nvd.nist.gov/developers)
- [DVWA](https://github.com/digininja/DVWA)

## Ekip
- Mücahit Haşim İpek (1230606809)
- Necat Akyüz (numara eklenecek)
- Danışman: Ercan Buluş (unvan eklenecek)
