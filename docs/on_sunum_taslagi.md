# Ön Sunum Taslağı — Otomatik Zafiyet Tarayıcı

Önerilen süre: 5-7 dakika, 10 slayt.

---

## Slayt 1 — Başlık
- **Otomatik Zafiyet Tarayıcı**
- Yazılım Temelli Proje Geliştirme Dersi - Ön Sunum
- Ekip: Mücahit Haşim İPEK (1230606809), Necat Akyüz (1220606005)
- Ders Sorumlusu: Prof. Dr. Ercan BULUŞ
- Tarih: Ekim 2026

## Slayt 2 — Problem ve Motivasyon
- Web uygulamalarına yönelik saldırılar sürekli artıyor.
- Manuel güvenlik testi yavaş ve pahalı.
- Küçük işletmeler ve geliştiriciler için basit, otomatik bir araç ihtiyacı var.
- *Konuşma notu:* "Zafiyeti saldırgandan önce biz bulabilirsek güvenliği artırırız."

## Slayt 3 — Zafiyet Nedir?
- Yazılımdaki tasarım, kodlama veya yapılandırma hatasından doğan güvenlik açığı.
- Temel neden: **kullanıcı girdisine güvenmek**, hatalı yapılandırma.
- Referans: OWASP Top 10.

## Slayt 4 — Proje Amacı ve Kapsamı
- Hedef web uygulamasını otomatik tarayıp zafiyetleri tespit etmek.
- Bulguları risk seviyesiyle raporlamak ve **düzeltme önerisi** sunmak.
- Kapsam: SQL Injection, XSS, açık port, güvenlik başlıkları, dizin listeleme, CVE eşleştirme.

## Slayt 5 — Sistem Mimarisi
```
Hedef URL -> Crawler -> Tarama Modülleri -> Risk Skorlama -> Rapor
                         |- SQLi
                         |- XSS
                         |- Port / Başlık / Dizin
                         |- CVE kontrolü
```
- Modüler yapı: her zafiyet türü ayrı bir modül.

## Slayt 6 — Teknolojiler
| Alan | Araç |
|------|------|
| Dil | Python |
| HTTP / Parsing | requests, BeautifulSoup |
| Ağ | socket / python-nmap |
| CVE verisi | NVD API |
| Rapor | Jinja2 (HTML) |
| Arayüz (opsiyonel) | Flask |

## Slayt 7 — Geliştirme Planı (Gantt)
- Gantt şemasını göster ([gantt_semasi.md](gantt_semasi.md)).
- 4 faz: Web Tarama, Ağ ve Yapılandırma, CVE ve Risk, Arayüz.
- Hedef teslim: Ocak 2027 başı.
- "Yapabildiğimiz yere kadar" yaklaşımı: çekirdek hedef Faz 1 ve Faz 2, kalanı ek hedef.

## Slayt 8 — Etik ve Yasal Çerçeve
- Araç **yalnızca izinli sistemlerde** kullanılır.
- Test ortamı: kendi makinemizde DVWA ve OWASP Juice Shop.
- Gerçek dünya kullanımı: kapsamı belirlenmiş bug bounty programları (HackerOne, Bugcrowd).
- İzinsiz tarama suçtur; araçta kullanıcıdan hedef sahipliği onayı alınacak.

## Slayt 9 — Beklenen Çıktılar ve Riskler
- Çıktılar: çalışan CLI aracı, HTML rapor, dokümantasyon, test sonuçları.
- Riskler: zaman yetersizliği, yanlış pozitifler, API limitleri.
- Önlemler: aşamalı geliştirme, testlerde bilinen zafiyetli uygulamalarla doğrulama.

## Slayt 10 — Sonuç ve Sorular
- Özet: modüler, etik, aşamalı bir zafiyet tarayıcı.
- Hocadan geri bildirim istenecek konular: kapsam, arayüz gerekliliği, değerlendirme kriterleri.
- Teşekkürler / Sorular.

---

## Sunum İpuçları
- Slayt başına en fazla 5 madde, görsel ağırlıklı olsun.
- Slayt 7 için Gantt şemasını görsel olarak dışa aktar (mermaid.live üzerinden PNG).
- Mümkünse kısa bir demo ekran görüntüsü ekle (Faz 1 sonrası).
