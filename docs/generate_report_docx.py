"""Namık Kemal Üniversitesi Çorlu Mühendislik Fakültesi tez yazım kurallarına uygun
olarak 'Zaafiyet Tarayıcı' Ön Proje Raporu docx dosyası üretici script.
"""
import os
import docx
from docx.shared import Inches, Pt, RGBColor, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn

def add_page_number(run):
    """Word altbilgisine sayfa numarası alanı ekler."""
    fldChar1 = parse_xml(r'<w:fldChar %s w:fldCharType="begin"/>' % nsdecls('w'))
    instrText = parse_xml(r'<w:instrText %s xml:space="preserve"> PAGE </w:instrText>' % nsdecls('w'))
    fldChar2 = parse_xml(r'<w:fldChar %s w:fldCharType="separate"/>' % nsdecls('w'))
    fldChar3 = parse_xml(r'<w:fldChar %s w:fldCharType="end"/>' % nsdecls('w'))
    run._r.append(fldChar1)
    run._r.append(instrText)
    run._r.append(fldChar2)
    run._r.append(fldChar3)

def create_report():
    doc = docx.Document()

    # Sayfa Boyutu: A4 (210 x 297 mm)
    section = doc.sections[0]
    section.page_width = Cm(21.0)
    section.page_height = Cm(29.7)

    # Kenar Boşlukları: Üst: 2.5 cm, Alt: 2.5 cm, Sol: 3.0 cm, Sağ: 2.0 cm
    section.top_margin = Cm(2.5)
    section.bottom_margin = Cm(2.5)
    section.left_margin = Cm(3.0)
    section.right_margin = Cm(2.0)

    # Varsayılan Yazı Tipi: Times New Roman, 12 pt, Siyah
    normal_style = doc.styles['Normal']
    normal_style.font.name = 'Times New Roman'
    normal_style.font.size = Pt(12)
    normal_style.font.color.rgb = RGBColor(0, 0, 0)
    normal_style.paragraph_format.line_spacing = 1.5
    normal_style.paragraph_format.space_after = Pt(6)

    # Altbilgi - Sayfa Numarası (Altta ve Ortada)
    footer = section.footer
    footer_p = footer.paragraphs[0]
    footer_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    footer_run = footer_p.add_run()
    footer_run.font.name = 'Times New Roman'
    footer_run.font.size = Pt(11)
    add_page_number(footer_run)

    def p(text="", bold=False, italic=False, align=WD_ALIGN_PARAGRAPH.LEFT, space_before=0, space_after=6, line_spacing=1.5):
        par = doc.add_paragraph()
        par.alignment = align
        par.paragraph_format.space_before = Pt(space_before)
        par.paragraph_format.space_after = Pt(space_after)
        par.paragraph_format.line_spacing = line_spacing
        if text:
            r = par.add_run(text)
            r.bold = bold
            r.italic = italic
            r.font.name = 'Times New Roman'
            r.font.size = Pt(12)
            r.font.color.rgb = RGBColor(0, 0, 0)
        return par

    def h1(title):
        """1. Derece Başlık: BÜYÜK HARF, 12-14 pt, Kalın"""
        par = doc.add_paragraph()
        par.alignment = WD_ALIGN_PARAGRAPH.LEFT
        par.paragraph_format.space_before = Pt(14)
        par.paragraph_format.space_after = Pt(6)
        par.paragraph_format.line_spacing = 1.5
        par.paragraph_format.keep_with_next = True
        r = par.add_run(title.upper())
        r.bold = True
        r.font.name = 'Times New Roman'
        r.font.size = Pt(12)
        r.font.color.rgb = RGBColor(0, 0, 0)
        return par

    def h2(title):
        """2. Derece Başlık: Her Kelimenin İlk Harfi Büyük, Kalın"""
        par = doc.add_paragraph()
        par.alignment = WD_ALIGN_PARAGRAPH.LEFT
        par.paragraph_format.space_before = Pt(10)
        par.paragraph_format.space_after = Pt(4)
        par.paragraph_format.line_spacing = 1.5
        par.paragraph_format.keep_with_next = True
        r = par.add_run(title)
        r.bold = True
        r.font.name = 'Times New Roman'
        r.font.size = Pt(12)
        r.font.color.rgb = RGBColor(0, 0, 0)
        return par

    def h3(title):
        """3. Derece Başlık: İlk kelime büyük diğerleri küçük, Kalın"""
        par = doc.add_paragraph()
        par.alignment = WD_ALIGN_PARAGRAPH.LEFT
        par.paragraph_format.space_before = Pt(8)
        par.paragraph_format.space_after = Pt(3)
        par.paragraph_format.line_spacing = 1.5
        par.paragraph_format.keep_with_next = True
        r = par.add_run(title)
        r.bold = True
        r.font.name = 'Times New Roman'
        r.font.size = Pt(12)
        r.font.color.rgb = RGBColor(0, 0, 0)
        return par

    # -------------------------------------------------------------
    # KAPAK SAYFASI
    # -------------------------------------------------------------
    p("T.C.", bold=True, align=WD_ALIGN_PARAGRAPH.CENTER, space_before=10, space_after=2)
    p("TEKİRDAĞ NAMIK KEMAL ÜNİVERSİTESİ", bold=True, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=2)
    p("ÇORLU MÜHENDİSLİK FAKÜLTESİ", bold=True, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=2)
    p("BİLGİSAYAR MÜHENDİSLİĞİ BÖLÜMÜ", bold=True, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=20)

    p("YAZILIM TEMELLİ PROJE GELİŞTİRME DERSİ", bold=True, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=4)
    p("LİSANS PROJESİ ÖN RAPORU", bold=True, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=50)

    p("ZAAFİYET TARAYICI", bold=True, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=6)
    p("(OTOMATİK WEB ZAFİYET TARAMA VE GÜVENLİK DENETİM ARACI)", italic=True, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=60)

    p("PROJEYİ HAZIRLAYANLAR:", bold=True, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=2)
    p("Mücahit Haşim İPEK (1230606809)", align=WD_ALIGN_PARAGRAPH.CENTER, space_after=2)
    p("Necat AKYÜZ (1220606005)", align=WD_ALIGN_PARAGRAPH.CENTER, space_after=40)

    p("DERS SORUMLUSU / DANIŞMAN:", bold=True, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=2)
    p("Prof. Dr. Ercan BULUŞ", align=WD_ALIGN_PARAGRAPH.CENTER, space_after=50)

    p("TEKİRDAĞ - 2026", bold=True, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=0)

    doc.add_page_break()

    # -------------------------------------------------------------
    # ÖZET
    # -------------------------------------------------------------
    h1("ÖZET")
    p("Web tabanlı yazılım sistemlerinin yaygınlaşması, beraberinde bu sistemleri hedef alan karmaşık siber saldırıların artmasını getirmiştir. Web uygulamalarındaki eksik girdi doğrulamaları, mantık hataları ve yanlış yapılandırmalar; kurumların kritik verilerinin sızmasına ve telafisi güç zararlara yol açmaktadır. Bu çalışmanın temel amacı; hedef web uygulamalarını otomatik olarak keşfeden, girdi noktalarını haritalandıran, SQL Enjeksiyonu ve Siteler Arası Betik Çalıştırma (XSS) gibi yaygın zafiyetleri denetleyen ve sonuçları giderim önerileriyle raporlayan modüler bir Otomatik Zafiyet Tarayıcısı geliştirmektir.")
    p("Proje mühendislik yaklaşımı gereği aşamalı (fazlı) geliştirme modeliyle planlanmıştır. Çalışma kapsamında keşif modülü için Genişlik Öncelikli Arama (BFS) algoritması ve kuyruk veri yapısı benimsenmiştir. Sistem, etik ve yasal kurallar (TCK 243-244) gereğince sadece izinli yerel laboratuvar ortamlarında (DVWA) doğrulanacaktır. Bu ön rapor, projenin kuramsal temellerini, sistem mimarisini, kullanılacak teknolojileri ve 13 haftalık çalışma takvimini kapsamaktadır.")
    p("Anahtar Kelimeler: Web Güvenliği, Zafiyet Tarayıcı, SQL Injection, XSS, Web Crawler, OWASP.", italic=True, space_before=10)

    doc.add_page_break()

    # -------------------------------------------------------------
    # ÖNSÖZ
    # -------------------------------------------------------------
    h1("ÖNSÖZ")
    p("Yazılım Temelli Proje Geliştirme dersi kapsamında hazırlanan bu proje, web uygulama güvenliğinin artırılması ve otomatik zafiyet tespiti süreçlerinin anlaşılmasını hedeflemektedir. Yazılım mühendisliği prensipleri doğrultusunda, modüler ve genişletilebilir bir mimaride tasarlanan çalışmamız; hem teorik güvenlik standartlarını hem de pratik uygulama adımlarını bir araya getirmektedir.")
    p("Çalışmamızın her aşamasında bizlere yol gösteren, değerli fikir ve önerileriyle ufkumuzu açan saygıdeğer danışman hocamız Prof. Dr. Ercan BULUŞ'a teşekkürlerimizi sunarız.")
    p("Mücahit Haşim İPEK\nNecat AKYÜZ\nEkim 2026", italic=True, align=WD_ALIGN_PARAGRAPH.RIGHT, space_before=20)

    doc.add_page_break()

    # -------------------------------------------------------------
    # İÇİNDEKİLER
    # -------------------------------------------------------------
    h1("İÇİNDEKİLER")
    toc_items = [
        ("ÖZET", "ii"),
        ("ÖNSÖZ", "iii"),
        ("SİMGELER VE KISALTMALAR DİZİNİ", "v"),
        ("ÇİZELGELER DİZİNİ", "vi"),
        ("ŞEKİLLER DİZİNİ", "vii"),
        ("1. GİRİŞ VE AMAÇ", "1"),
        ("2. KURAMSAL TEMELLER VE İLGİLİ ÇALIŞMALAR", "2"),
        ("    2.1. Web Uygulama Güvenliği ve Zafiyet Kavramı", "2"),
        ("    2.2. SQL Injection (CWE-89)", "2"),
        ("    2.3. Siteler Arası Betik Çalıştırma - XSS (CWE-79)", "3"),
        ("    2.4. Oturum Yönetimi ve Çerez Mekanizması", "3"),
        ("3. SİSTEM MİMARİSİ VE METODOLOJİ", "4"),
        ("    3.1. Genel Mimari ve İş Hattı", "4"),
        ("    3.2. Web Keşif Motoru (Crawler) ve BFS Algoritması", "5"),
        ("    3.3. Güvenlik Denetim Modülleri", "5"),
        ("4. KULLANILACAK TEKNOLOJİLER VE SEÇİM GEREKÇELERİ", "6"),
        ("    4.1. Programlama Dili: Python", "6"),
        ("    4.2. HTTP İletişim Kütüphanesi: Requests", "6"),
        ("    4.3. DOM Ayrıştırma: BeautifulSoup4", "6"),
        ("    4.4. Kuyruk Veri Yapısı: Collections.deque", "7"),
        ("5. ETİK VE YASAL ÇERÇEVE", "8"),
        ("6. PROJE PLANI VE İŞ PAKETLERİ (GANTT)", "9"),
        ("7. RİSK ANALİZİ VE YÖNETİMİ", "10"),
        ("8. SONUÇLAR VE ÖNERİLER", "11"),
        ("KAYNAKLAR", "12"),
        ("ÖZGEÇMİŞ", "13")
    ]
    for title, page in toc_items:
        p_toc = doc.add_paragraph()
        p_toc.paragraph_format.line_spacing = 1.15
        p_toc.paragraph_format.space_after = Pt(2)
        r_title = p_toc.add_run(title)
        r_title.font.name = 'Times New Roman'
        r_title.font.size = Pt(11)
        r_dots = p_toc.add_run(" " + "." * max(5, (75 - len(title) * 2)) + " ")
        r_dots.font.name = 'Times New Roman'
        r_dots.font.size = Pt(10)
        r_dots.font.color.rgb = RGBColor(120, 120, 120)
        r_page = p_toc.add_run(page)
        r_page.font.name = 'Times New Roman'
        r_page.font.size = Pt(11)

    doc.add_page_break()

    # -------------------------------------------------------------
    # SİMGELER VE KISALTMALAR DİZİNİ
    # -------------------------------------------------------------
    h1("SİMGELER VE KISALTMALAR DİZİNİ")
    abbrs = [
        ("API", "Application Programming Interface (Uygulama Programlama Arayüzü)"),
        ("BFS", "Breadth-First Search (Genişlik Öncelikli Arama)"),
        ("CLI", "Command Line Interface (Komut Satırı Arayüzü)"),
        ("CSP", "Content Security Policy (İçerik Güvenlik Politikası)"),
        ("CSRF", "Cross-Site Request Forgery (Siteler Arası İstek Sahteciliği)"),
        ("CVE", "Common Vulnerabilities and Exposures (Ortak Zafiyetler ve Maruziyetler)"),
        ("CVSS", "Common Vulnerability Scoring System (Ortak Zafiyet Puanlama Sistemi)"),
        ("CWE", "Common Weakness Enumeration (Ortak Zayıflık Numaralandırması)"),
        ("DOM", "Document Object Model (Belge Nesne Modeli)"),
        ("DoS", "Denial of Service (Hizmet Engelleme Saldırısı)"),
        ("DVWA", "Damn Vulnerable Web Application (Kasıtlı Savunmasız Web Uygulaması)"),
        ("FIFO", "First In First Out (İlk Giren İlk Çıkar)"),
        ("HTML", "HyperText Markup Language (Zengin Metin İşaretleme Dili)"),
        ("HTTP", "Hypertext Transfer Protocol (Köprü Metni Aktarım Protokolü)"),
        ("NVD", "National Vulnerability Database (Ulusal Zafiyet Veritabanı)"),
        ("OWASP", "Open Web Application Security Project (Açık Web Uygulaması Güvenlik Projesi)"),
        ("SQL", "Structured Query Language (Yapılandırılmış Sorgu Dili)"),
        ("SQLi", "SQL Injection (SQL Enjeksiyonu)"),
        ("TCK", "Türk Ceza Kanunu"),
        ("WAF", "Web Application Firewall (Web Uygulaması Güvenlik Duvarı)"),
        ("XSS", "Cross-Site Scripting (Siteler Arası Betik Çalıştırma)")
    ]
    for k, v in abbrs:
        p_abbr = doc.add_paragraph()
        p_abbr.paragraph_format.line_spacing = 1.15
        p_abbr.paragraph_format.space_after = Pt(2)
        r1 = p_abbr.add_run(f"{k:<10} : ")
        r1.bold = True
        r1.font.name = 'Times New Roman'
        r1.font.size = Pt(11)
        r2 = p_abbr.add_run(v)
        r2.font.name = 'Times New Roman'
        r2.font.size = Pt(11)

    doc.add_page_break()

    # -------------------------------------------------------------
    # ÇİZELGELER VE ŞEKİLLER DİZİNİ
    # -------------------------------------------------------------
    h1("ÇİZELGELER DİZİNİ")
    p("Çizelge 4.1. Kullanılacak Kütüphaneler ve Seçim Gerekçeleri ........................... 7")
    p("Çizelge 6.1. 13 Haftalık Proje İş Paketleri ve Zaman Çizelgesi ......................... 9")
    p("Çizelge 7.1. Proje Risk Matrisi ve Azaltma Stratejileri ................................ 10")

    p("", space_after=15)
    h1("ŞEKİLLER DİZİNİ")
    p("Şekil 3.1. Zaafiyet Tarayıcısı Sistem Mimarisi ve İşlem Akışı .......................... 4")
    p("Şekil 3.2. Genişlik Öncelikli Arama (BFS) Kuyruk Mimarisi .............................. 5")

    doc.add_page_break()

    # -------------------------------------------------------------
    # 1. BÖLÜM: GİRİŞ VE AMAÇ
    # -------------------------------------------------------------
    h1("1. GİRİŞ VE AMAÇ")
    p("İnternet teknolojilerinin ve bulut bilişimin hızla büyümesiyle birlikte işletmeler, kamu kurumları ve bireyler kritik iş süreçlerini web tabanlı yazılımlar üzerinden yürütmektedir. Bu durum, web uygulamalarını bilişim korsanlarının en birincil saldırı yüzeyi haline getirmiştir. Open Web Application Security Project (OWASP) verilerine göre, modern web uygulamalarının büyük bir bölümü en az bir kritik seviyeli güvenlik zafiyeti barındırmaktadır [1].")
    p("Söz konusu güvenlik açıklarının büyük bölümü, yazılım geliştirme aşamasında güvenli kodlama ilkelerinin göz ardı edilmesinden ve kullanıcıdan gelen verilerin sunucu tarafında yeterince doğrulanmamasından kaynaklanmaktadır. Bu açıkların kötü niyetli kişilerce suistimal edilmesi; veri tabanlarındaki gizli bilgilerin ifşasına, yetkisiz sistem erişimlerine ve telafisi güç mali kayıplara sebep olmaktadır.")
    p("Bu problemin giderilmesinde geleneksel yöntem manuel penetrasyon (sızma) testleridir. Ancak manuel testler; uzman iş gücü gerektirmesi, zaman alıcı olması ve her kod güncellemesinde tekrarlanmasının yüksek maliyet doğurması sebebiyle sürdürülebilir değildir. Bu bağlamda, hedef web sitelerini otomatik tarayarak yaygın zafiyetleri insan müdahalesine gerek kalmadan keşfeden yazılımlara büyük ihtiyaç duyulmaktadır.")
    p("Bu projenin temel amacı; harici bir hedef adresi girdi olarak alıp tüm saldırı yüzeyini (sayfalar, formlar, parametreler) haritalandıran, zararsız güvenlik testleri uygulayarak SQL Injection ve XSS gibi kritik zafiyetleri tespit eden ve tespit edilen açıkları geliştiriciye anlaşılır çözüm önerileriyle sunan modüler bir Otomatik Zafiyet Tarayıcı geliştirmektir.")

    # -------------------------------------------------------------
    # 2. BÖLÜM: KURAMSAL TEMELLER
    # -------------------------------------------------------------
    h1("2. KURAMSAL TEMELLER VE İLGİLİ ÇALIŞMALAR")
    
    h2("2.1. Web Uygulama Güvenliği ve Zafiyet Kavramı")
    p("Bir yazılım zafiyeti (vulnerability); sistemin tasarımında, kodlamasında veya yapılandırmasında meydana gelen, yetkisiz bir aktörün güvenlik politikalarını ihlal etmesine imkân tanıyan güvenlik açığıdır [2]. Web uygulamalarında güvenliğin sağlanabilmesi için Girdi Doğrulama (Input Validation), Çıktı Kodlama (Output Encoding) ve En Az Yetki Prensibi (Principle of Least Privilege) temel gerekliliklerdir.")

    h2("2.2. SQL Injection (CWE-89)")
    p("SQL Injection, kullanıcı girdilerinin filtre edilmeksizin dinamik veritabanı sorgularına dahil edilmesi sonucunda ortaya çıkan en tehlikeli zafiyet türlerinden biridir [3]. Saldırgan, girdi alanlarına SQL komut parçacıkları ekleyerek uygulamanın veri tabanı mantığını manipüle edebilir.")
    p("Projemiz kapsamında hata tabanlı (error-based) SQL denetimi hedeflenmektedir. Girdi alanlarına özel test karakterleri (tek tırnak vb.) enjekte edilerek sunucu yanıtında MySQL, PostgreSQL veya Microsoft SQL Server sözdizimi hata mesajlarının varlığı taranacaktır.")

    h2("2.3. Siteler Arası Betik Çalıştırma - XSS (CWE-79)")
    p("Cross-Site Scripting (XSS), saldırganın bir web sayfasına zararlı istemci taraflı betikler (çoğunlukla JavaScript) enjekte etmesiyle oluşur [4]. Kurban kullanıcı sayfayı ziyaret ettiğinde bu kodlar kullanıcının tarayıcısında çalıştırılarak oturum çerezlerinin çalınmasına (Session Hijacking) yol açar.")
    p("Çalışmamızda yansıtılan (Reflected) ve depolanan (Stored) XSS türleri üzerinde odaklanılacak; form parametrelerine gönderilen test karakter dizilerinin HTML çıktısında kaçış karakterleri (HTML entity encoding) uygulanmadan geri yansıyıp yansımadığı tespit edilecektir.")

    h2("2.4. Oturum Yönetimi ve Çerez Mekanizması")
    p("HTTP protokolü durumsuz (stateless) bir protokoldür; yani sunucu iki ayrı istek arasında bir bağlantı kuramaz. Bu sebeple kullanıcı oturumları 'Session Cookie' (oturum çerezi) aracılığıyla korunur. Zafiyet tarayıcımızın yalnızca herkese açık sayfaları değil, giriş gerektiren yetkili alanları da denetleyebilmesi için harici oturum çerezi kabul edebilecek şekilde tasarlanması gerekmektedir.")

    doc.add_page_break()

    # -------------------------------------------------------------
    # 3. BÖLÜM: SİSTEM MİMARİSİ VE METODOLOJİ
    # -------------------------------------------------------------
    h1("3. SİSTEM MİMARİSİ VE METODOLOJİ")
    
    h2("3.1. Genel Mimari ve İş Hattı")
    p("Zaafiyet Tarayıcısı, birbirine gevşek bağlı (loosely coupled) modüler bir boru hattı mimarisi üzerinde inşa edilecektir. Sistem genel akışı Şekil 3.1'de özetlenmiştir.")
    
    p("[Hedef URL / Çerez] ──► [Web Crawler (Keşif)] ──► [Form ve Parametre Listesi]", align=WD_ALIGN_PARAGRAPH.CENTER, italic=True)
    p("                                                              │", align=WD_ALIGN_PARAGRAPH.CENTER)
    p("                                                              ▼", align=WD_ALIGN_PARAGRAPH.CENTER)
    p("                                                  [Zafiyet Tarama Motoru]", align=WD_ALIGN_PARAGRAPH.CENTER, italic=True)
    p("                                                  ├─ SQLi Modülü", align=WD_ALIGN_PARAGRAPH.CENTER)
    p("                                                  ├─ XSS Modülü", align=WD_ALIGN_PARAGRAPH.CENTER)
    p("                                                  └─ Header Analizörü", align=WD_ALIGN_PARAGRAPH.CENTER)
    p("                                                              │", align=WD_ALIGN_PARAGRAPH.CENTER)
    p("                                                              ▼", align=WD_ALIGN_PARAGRAPH.CENTER)
    p("                                                  [Raporlama ve Risk Analizi]", align=WD_ALIGN_PARAGRAPH.CENTER, italic=True)
    p("Şekil 3.1. Zaafiyet Tarayıcısı Sistem Mimarisi ve İşlem Akışı", italic=True, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=12)

    h2("3.2. Web Keşif Motoru (Crawler) ve BFS Algoritması")
    p("Tarama sürecinin ilk adımı hedef sitenin tüm bağlantılarını ve form yapılarını ortaya çıkarmaktır. Bu işlemde Genişlik Öncelikli Arama (BFS) algoritması kullanılacaktır. BFS algoritması, ana sayfadan başlayarak önce aynı derinlikteki tüm linkleri ziyaret eder, ardından alt seviyelere geçer. Bu sayede sitenin kritik üst seviye sayfaları eksiksiz taranır.")
    p("Kuyruk yapısında bellek şişmesini ve gereksiz döngüleri engellemek için daha önce ziyaret edilen URL'ler bir 'visited' kümesinde tutulacaktır. Ayrıca oturumun düşmesini engellemek için 'logout', 'signout' gibi anahtar kelimeleri içeren bağlantılar otomatik olarak filtrelenecektir.")

    h2("3.3. Güvenlik Denetim Modülleri")
    p("Keşfedilen her form ve parametre nesnesi, zafiyet modüllerine girdi olarak beslenecektir:")
    p("1. SQLi Modülü: Form girdilerine zararsız özel karakterler gönderip sunucu yanıtındaki veritabanı hata desenlerini (regex patterns) analiz eder.")
    p("2. XSS Modülü: Parametrelere benzersiz etiketler enjekte edip dönen HTML yanıtında bu etiketlerin filtrelenip filtrelenmediğini denetler.")
    p("3. Header Analizörü: Sunucu yanıt başlıklarında Content-Security-Policy (CSP), Strict-Transport-Security (HSTS) ve X-Frame-Options başlıklarının eksikliğini denetler.")

    # -------------------------------------------------------------
    # 4. BÖLÜM: KULLANILACAK TEKNOLOJİLER
    # -------------------------------------------------------------
    h1("4. KULLANILACAK TEKNOLOJİLER VE SEÇİM GEREKÇELERİ")
    p("Projede yer alacak yazılım kütüphaneleri, mühendislik gereksinimleri ve performans kriterleri doğrultusunda titizlikle seçilmiştir. Seçilen kütüphaneler ve alternatiflerine göre avantajları Çizelge 4.1'de sunulmuştur.")

    # Tablo 4.1
    p("Çizelge 4.1. Kullanılacak Kütüphaneler ve Seçim Gerekçeleri", italic=True, align=WD_ALIGN_PARAGRAPH.LEFT, space_after=4)
    table = doc.add_table(rows=6, cols=3)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False

    headers = ["Alan / Bileşen", "Seçilen Teknoloji", "Seçim Gerekçesi ve Alternatif Farkı"]
    col_widths = [Cm(3.5), Cm(3.5), Cm(9.0)]
    for i, h in enumerate(headers):
        cell = table.cell(0, i)
        cell.width = col_widths[i]
        p_cell = cell.paragraphs[0]
        p_cell.paragraph_format.line_spacing = 1.15
        p_cell.paragraph_format.space_after = Pt(2)
        r = p_cell.add_run(h)
        r.bold = True
        r.font.name = 'Times New Roman'
        r.font.size = Pt(10)

    rows_data = [
        ("Programlama Dili", "Python 3.12+", "Siber güvenlik ekosistemindeki zengin kütüphane desteği, hızlı prototipleme ve taşınabilirlik."),
        ("HTTP İstemcisi", "Requests", "Dahili 'urllib'e göre oturum ve çerez yönetimini (Session) otomatik yapması, temiz API."),
        ("HTML Ayrıştırma", "BeautifulSoup4", "Bozuk HTML sayfalarını bile hatasız DOM ağacına çevirerek formları ayıklaması (Regex'e üstünlük)."),
        ("Kuyruk Mimarisi", "collections.deque", "Standart Python listelerinin O(N) ilk eleman çekme maliyetine karşın O(1) sabit zamanda çalışması."),
        ("Veri Modelleme", "@dataclass", "Klasik sözlük (dict) yapılarına göre nesne yönelimli, tip güvenli (type-safe) ve hataya kapalı olması.")
    ]
    for row_idx, data in enumerate(rows_data, start=1):
        for col_idx, text in enumerate(data):
            cell = table.cell(row_idx, col_idx)
            cell.width = col_widths[col_idx]
            p_cell = cell.paragraphs[0]
            p_cell.paragraph_format.line_spacing = 1.15
            p_cell.paragraph_format.space_after = Pt(2)
            r = p_cell.add_run(text)
            r.font.name = 'Times New Roman'
            r.font.size = Pt(10)

    p("", space_after=10)

    # -------------------------------------------------------------
    # 5. BÖLÜM: ETİK VE YASAL ÇERÇEVE
    # -------------------------------------------------------------
    h1("5. ETİK VE YASAL ÇERÇEVE")
    p("Siber güvenlik araştırmalarında ve yazılım geliştirme süreçlerinde etik kurallar ile yasal mevzuata tam uyum esastır. 5237 Sayılı Türk Ceza Kanunu'nun (TCK) 243. maddesi (Bilişim Sistemine Girme) ve 244. maddesi (Sistemi Engelleme, Bozma, Verileri Yok Etme veya Değiştirme) gereğince, hak sahibinin yazılı rızası olmaksızın bilişim sistemlerine otomatik araçlarla tarama yapmak suç kabul edilmektedir [5].")
    p("Bu projenin yürütülmesinde şu temel etik prensipler uygulanacaktır:")
    p("1. Yerel Test Ortamı İlkesi: Geliştirilen araç kesinlikle canlı kurumsal veya şahsi sistemler üzerinde kullanılmayacaktır. Tüm testler yerel makinede Docker konteyneri olarak çalışan DVWA (Damn Vulnerable Web Application) eğitim platformunda gerçekleştirilecektir.")
    p("2. Nezaket Gecikmesi (Politeness Delay): Hedef sunucuların istem dışı hizmet dışı kalmasını (Denial of Service) engellemek amacıyla istekler arasına 0.3 saniyelik bekleme süresi konulacaktır.")
    p("3. Kapsam Güvenliği (Scope Lock): Tarayıcının dış etki alanlarına (external domains) istek atmasını engelleyen sıkı ana makine (host) kontrolleri uygulanacaktır.")

    doc.add_page_break()

    # -------------------------------------------------------------
    # 6. BÖLÜM: PROJE PLANI VE İŞ PAKETLERİ
    # -------------------------------------------------------------
    h1("6. PROJE PLANI VE İŞ PAKETLERİ (GANTT)")
    p("Proje, 2026 Ekim başı ile 2027 Ocak başı arasındaki 13 haftalık akademik dönemi kapsayacak şekilde planlanmıştır. Çalışma paketleri ve teslim çıktıları Çizelge 6.1'de gösterilmiştir.")

    p("Çizelge 6.1. 13 Haftalık Proje İş Paketleri ve Zaman Çizelgesi", italic=True, align=WD_ALIGN_PARAGRAPH.LEFT, space_after=4)
    table_gantt = doc.add_table(rows=8, cols=4)
    table_gantt.alignment = WD_TABLE_ALIGNMENT.CENTER

    headers_g = ["Dönem / Hafta", "İş Paketi", "Açıklama", "Beklenen Çıktı"]
    col_widths_g = [Cm(2.5), Cm(4.0), Cm(5.5), Cm(4.0)]
    for i, h in enumerate(headers_g):
        cell = table_gantt.cell(0, i)
        cell.width = col_widths_g[i]
        p_c = cell.paragraphs[0]
        p_c.paragraph_format.line_spacing = 1.15
        p_c.paragraph_format.space_after = Pt(2)
        r = p_c.add_run(h)
        r.bold = True
        r.font.name = 'Times New Roman'
        r.font.size = Pt(10)

    gantt_data = [
        ("1. Hafta", "İP-1: Planlama ve Ön Rapor", "Gereksinim analizi, mimari tasarım ve literatür taraması.", "Ön Sunum ve Rapor"),
        ("2-3. Hafta", "İP-2: Web Crawler Geliştirme", "BFS algoritmalı link ve form keşif motoru.", "Keşif Modülü"),
        ("4. Hafta", "İP-3: SQL Injection Modülü", "Hata tabanlı SQL zafiyet tespit motoru.", "SQLi Tarayıcısı"),
        ("5. Hafta", "İP-4: XSS Tespit Modülü", "Reflected ve Stored XSS tespit yeteneği.", "XSS Tarayıcısı"),
        ("6-7. Hafta", "İP-5: Ağ ve Yapılandırma", "Port tarama ve HTTP güvenlik başlıkları analizi.", "Ağ Denetim Modülü"),
        ("8-9. Hafta", "İP-6: Raporlama ve CVE", "Jinja2 tabanlı HTML raporlama motoru ve CVE.", "Raporlama Motoru"),
        ("10-13. Hafta", "İP-7: Test ve Teslim", "Doğrulama testleri, dokümantasyon ve final sunumu.", "Final Teslimi")
    ]
    for row_idx, data in enumerate(gantt_data, start=1):
        for col_idx, text in enumerate(data):
            cell = table_gantt.cell(row_idx, col_idx)
            cell.width = col_widths_g[col_idx]
            p_c = cell.paragraphs[0]
            p_c.paragraph_format.line_spacing = 1.15
            p_c.paragraph_format.space_after = Pt(2)
            r = p_c.add_run(text)
            r.font.name = 'Times New Roman'
            r.font.size = Pt(10)

    p("", space_after=10)

    # -------------------------------------------------------------
    # 7. BÖLÜM: RİSK ANALİZİ
    # -------------------------------------------------------------
    h1("7. RİSK ANALİZİ VE YÖNETİMİ")
    p("Yazılım geliştirme sürecinde karşılaşılabilecek potansiyel teknik ve operasyonel riskler değerlendirilmiş ve önleyici tedbirler Çizelge 7.1'de tanımlanmıştır.")

    p("Çizelge 7.1. Proje Risk Matrisi ve Azaltma Stratejileri", italic=True, align=WD_ALIGN_PARAGRAPH.LEFT, space_after=4)
    table_risk = doc.add_table(rows=4, cols=3)
    table_risk.alignment = WD_TABLE_ALIGNMENT.CENTER

    headers_r = ["Belirlenen Risk", "Etki Seviyesi", "Azaltma / Çözüm Stratejisi"]
    col_widths_r = [Cm(4.5), Cm(3.0), Cm(8.5)]
    for i, h in enumerate(headers_r):
        cell = table_risk.cell(0, i)
        cell.width = col_widths_r[i]
        p_c = cell.paragraphs[0]
        p_c.paragraph_format.line_spacing = 1.15
        p_c.paragraph_format.space_after = Pt(2)
        r = p_c.add_run(h)
        r.bold = True
        r.font.name = 'Times New Roman'
        r.font.size = Pt(10)

    risk_data = [
        ("WAF / Bot Korumaları", "Orta", "İlk fazlarda yerel DVWA ortamına odaklanılacak; sahte negatifler elenecektir."),
        ("Zaman Kısıtı", "Yüksek", "Aşamalı mühendislik yaklaşımıyla Faz 1 ve 2 birincil teslim hedefi olarak korunacaktır."),
        ("Hatalı Pozitifler (False Positive)", "Orta", "Sadece HTTP durum koduna güvenilmeyip çoklu imza doğrulama desenleri kullanılacaktır.")
    ]
    for row_idx, data in enumerate(risk_data, start=1):
        for col_idx, text in enumerate(data):
            cell = table_risk.cell(row_idx, col_idx)
            cell.width = col_widths_r[col_idx]
            p_c = cell.paragraphs[0]
            p_c.paragraph_format.line_spacing = 1.15
            p_c.paragraph_format.space_after = Pt(2)
            r = p_c.add_run(text)
            r.font.name = 'Times New Roman'
            r.font.size = Pt(10)

    p("", space_after=10)

    # -------------------------------------------------------------
    # 8. BÖLÜM: SONUÇLAR VE ÖNERİLER
    # -------------------------------------------------------------
    h1("8. SONUÇLAR VE ÖNERİLER")
    p("Bu ön raporda, Namık Kemal Üniversitesi Yazılım Temelli Proje Geliştirme dersi kapsamında hayata geçirilecek 'Zaafiyet Tarayıcı' projesinin teorik temelleri, mimari tasarımı ve yol haritası sunulmuştur. Yapılan ön çalışmalar neticesinde gereksinimler netleştirilmiş, kullanılacak kütüphaneler ve algoritmalar akademik gerekçeleriyle belirlenmiştir.")
    p("Projenin sonraki adımlarında iş paketleri takvimine sadık kalınarak Faz 1 geliştirme sürecine başlanacak ve yerel test ortamında modüller tek tek doğrulanacaktır. Çalışmanın ilerleyen aşamalarında elde edilecek bulgular dönem sonu nihai bitirme raporunda detaylandırılacaktır.")

    doc.add_page_break()

    # -------------------------------------------------------------
    # KAYNAKLAR
    # -------------------------------------------------------------
    h1("KAYNAKLAR")
    refs = [
        "[1] OWASP Foundation, (2021), 'OWASP Top 10: 2021 The Ten Most Critical Web Application Security Risks', Açık Web Güvenliği Dokümantasyonu, https://owasp.org/Top10/.",
        "[2] NIST, (2023), 'National Vulnerability Database (NVD) Specifications and Common Vulnerability Scoring System (CVSS)', U.S. Department of Commerce.",
        "[3] MITRE Corporation, (2023), 'CWE-89: Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)', Common Weakness Enumeration, https://cwe.mitre.org/data/definitions/89.html.",
        "[4] PortSwigger, (2024), 'Cross-Site Scripting (XSS) Vulnerabilities and Defense Guide', PortSwigger Web Security Academy.",
        "[5] T.C. Adalet Bakanlığı, (2004), '5237 Sayılı Türk Ceza Kanunu: Bilişim Alanında Suçlar (Madde 243-244)', Resmi Gazete Sayı: 25611.",
        "[6] Berners-Lee, T., Fielding, R., Masinter, L., (2005), 'Uniform Resource Identifier (URI): Generic Syntax', RFC 3986, Internet Engineering Task Force (IETF)."
    ]
    for r in refs:
        p_ref = doc.add_paragraph()
        p_ref.paragraph_format.line_spacing = 1.15
        p_ref.paragraph_format.space_after = Pt(4)
        run_ref = p_ref.add_run(r)
        run_ref.font.name = 'Times New Roman'
        run_ref.font.size = Pt(11)

    doc.add_page_break()

    # -------------------------------------------------------------
    # ÖZGEÇMİŞ
    # -------------------------------------------------------------
    h1("ÖZGEÇMİŞ")
    h2("Mücahit Haşim İPEK")
    p("Tekirdağ Namık Kemal Üniversitesi Çorlu Mühendislik Fakültesi Bilgisayar Mühendisliği Bölümü lisans öğrencisidir (Öğrenci No: 1230606809). Yazılım geliştirme, web güvenliği ve nesne yönelimli programlama alanlarında çalışmalar yürütmektedir.")

    h2("Necat AKYÜZ")
    p("Tekirdağ Namık Kemal Üniversitesi Çorlu Mühendislik Fakültesi Bilgisayar Mühendisliği Bölümü lisans öğrencisidir (Öğrenci No: 1220606005). Ağ protokolleri, yazılım mühendisliği ve web teknolojileri konularında çalışmalar gerçekleştirmektedir.")

    # Kaydet
    output_path = r"c:\Users\admin\Desktop\Yazılım Temelli Proje Geliştirme\docs\on_proje_raporu.docx"
    doc.save(output_path)
    print(f"[+] Rapor başarıyla oluşturuldu: {output_path}")

if __name__ == "__main__":
    create_report()
