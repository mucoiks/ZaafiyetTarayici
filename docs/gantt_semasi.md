# Gantt Şeması — Otomatik Zafiyet Tarayıcı

```mermaid
gantt
    title Otomatik Zafiyet Tarayıcı - Proje Takvimi (Ekim 2026 - Ocak 2027)
    dateFormat  YYYY-MM-DD
    axisFormat  %d %b

    section Planlama
    Konu araştırması ve zafiyet çalışması   :done,    p1, 2026-10-01, 10d
    Proje planı, Gantt, ön sunum            :active,  p2, 2026-10-01, 8d
    Geliştirme ortamı (Python, Git, DVWA)   :         p3, 2026-10-08, 5d

    section Faz 1 - Web Tarama
    Web crawler (link ve form keşfi)        :f1a, 2026-10-13, 10d
    SQL Injection tespit modülü             :f1b, after f1a, 10d
    XSS tespit modülü                       :f1c, after f1b, 7d
    CLI çıktısı ve Faz 1 testleri           :f1d, after f1c, 5d

    section Faz 2 - Ağ ve Yapılandırma
    Port tarama modülü                      :f2a, 2026-11-14, 10d
    HTTP güvenlik başlığı analizi           :f2b, after f2a, 5d
    Dizin tarama (directory listing)        :f2c, after f2b, 7d
    HTML rapor üretimi                      :f2d, after f2c, 7d

    section Faz 3 - CVE ve Risk
    CVE/NVD API entegrasyonu                :f3a, 2026-12-10, 10d
    Risk skorlama                           :f3b, after f3a, 5d
    Çoklu hedef desteği ve optimizasyon     :f3c, after f3b, 5d

    section Faz 4 - Arayüz ve Teslim
    Web arayüzü (opsiyonel, Flask)          :f4a, 2026-12-30, 4d
    Dokümantasyon ve final testleri         :f4b, 2026-12-27, 7d
    Final sunum hazırlığı                   :milestone, f4c, 2027-01-04, 1d
```

## Görev Tablosu

| Faz | Görev | Başlangıç | Süre | Çıktı |
|-----|-------|-----------|------|-------|
| Planlama | Konu araştırması | 1 Eki | 10 gün | Zafiyet rehberi |
| Planlama | Plan, Gantt, ön sunum | 1 Eki | 8 gün | Ön sunum |
| Planlama | Ortam kurulumu | 8 Eki | 5 gün | Python, Git, DVWA hazır |
| Faz 1 | Crawler | 13 Eki | 10 gün | URL/form listesi |
| Faz 1 | SQLi modülü | 23 Eki | 10 gün | SQLi tespiti |
| Faz 1 | XSS modülü | 2 Kas | 7 gün | XSS tespiti |
| Faz 1 | CLI + test | 9 Kas | 5 gün | Faz 1 teslimi |
| Faz 2 | Port tarama | 14 Kas | 10 gün | Açık port/servis listesi |
| Faz 2 | Başlık analizi | 24 Kas | 5 gün | Eksik başlık raporu |
| Faz 2 | Dizin tarama | 29 Kas | 7 gün | Dizin bulguları |
| Faz 2 | HTML rapor | 6 Ara | 7 gün | Faz 2 teslimi |
| Faz 3 | CVE entegrasyonu | 10 Ara | 10 gün | CVE eşleştirme |
| Faz 3 | Risk skorlama | 20 Ara | 5 gün | Düşük/Orta/Yüksek/Kritik |
| Faz 3 | Çoklu hedef | 25 Ara | 5 gün | Faz 3 teslimi |
| Faz 4 | Arayüz (opsiyonel) | 30 Ara | 4 gün | Flask arayüzü |
| Faz 4 | Dokümantasyon, test | 27 Ara | 7 gün | Final raporu |

> **Risk notu:** Zaman yetmezse Faz 4 (arayüz) ve Faz 3'teki çoklu hedef desteği çıkarılabilir. Çekirdek hedef Faz 1 ve Faz 2'dir.
