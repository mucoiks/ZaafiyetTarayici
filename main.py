"""Otomatik Zafiyet Tarayıcı — Ana Giriş Noktası ve İnteraktif Menü Sistemi.

Hem interaktif konsol menüsüyle (parametresiz çalıştırıldığında) hem de
komut satırı argümanlarıyla (CLI) çalışır:

İnteraktif Menü:
    python main.py

Komut Satırı (CLI) Örnekleri:
    python main.py --mode crawler --target http://localhost:8080 --dvwa-login
    python main.py --mode sqli-passive --target http://localhost:8080 --dvwa-login
    python main.py --mode sast --source-dir samples/dvwa_sqli_ornekleri
    python main.py --mode hybrid --target http://localhost:8080 --dvwa-login --source-dir samples/dvwa_sqli_ornekleri
"""
import argparse
import os
import re
import sys
from datetime import datetime
from urllib.parse import urlparse

import requests

from scanner.crawler import Crawler, CrawlResult
from scanner.sqli_analyzer import HybridSQLiAnalyzer


def dvwa_login(base_url, user="admin", password="password"):
    """DVWA'ya giriş yapıp oturum açılmış bir requests.Session döndürür.

    DVWA girişte CSRF token ister; önce token alınır, sonra form gönderilir.
    """
    session = requests.Session()
    page = session.get(f"{base_url}/login.php", timeout=5)
    match = re.search(r"name=['\"]user_token['\"] value=['\"]([^'\"]+)", page.text)
    data = {"username": user, "password": password, "Login": "Login"}
    if match:
        data["user_token"] = match.group(1)
    session.post(f"{base_url}/login.php", data=data, timeout=5)
    session.cookies.set("security", "low")
    return session


def build_session(base_url, use_dvwa_login=False, cookie_str=None):
    """Seçilen oturum yöntemine göre requests.Session nesnesi hazırlar."""
    if use_dvwa_login:
        return dvwa_login(base_url)
    if cookie_str:
        session = requests.Session()
        for item in cookie_str.split(";"):
            if "=" in item:
                k, v = item.strip().split("=", 1)
                session.cookies.set(k, v)
        return session
    return None


def normalize_url(target_url):
    """Hedef URL'yi standart http/https formatına getirir."""
    base = target_url.strip().rstrip("/")
    if not base.startswith(("http://", "https://")):
        base = "http://" + base
    return base


def print_crawl_summary(result):
    """Crawler sonuçlarını terminale düzenli biçimde yazdırır."""
    summary_text = (
        f"\n[+] {len(result.pages)} sayfa, {len(result.forms)} form, "
        f"{len(result.param_urls)} parametreli URL bulundu"
    )
    if result.disallowed_paths:
        summary_text += f", {len(result.disallowed_paths)} robots.txt kuralı tespit edildi"
    print(summary_text + "\n")

    if result.disallowed_paths:
        print("[*] robots.txt Gizli/Yasaklı Yollar:")
        for path in result.disallowed_paths:
            print(f"  [Disallow] {path}")
        print()

    print("[*] Keşfedilen Sayfalar:")
    for page in result.pages:
        print(f"  [{page.status_code}] (Derinlik: {page.depth}) {page.url}")

    print("\n[*] Keşfedilen Formlar ve Test Edilebilir Alanlar:")
    for form in result.forms:
        inj = ", ".join(i.name for i in form.injectable_inputs)
        others = ", ".join(i.name for i in form.inputs if not i.is_injectable)
        print(f"  [{form.method.upper()}] {form.action}")
        print(f"      Test Edilebilir Alanlar: [{inj if inj else 'Yok'}]")
        if others:
            print(f"      Sabit/Buton Alanları   : [{others}]")

    if result.param_urls:
        print("\n[*] Parametreli URL'ler (Zafiyet Denetim Adayları):")
        for p_url in result.param_urls:
            p_names = ", ".join(p_url.params.keys())
            print(f"  GET {p_url.full_url}  -> Parametreler: [{p_names}]")


def print_sqli_audit_summary(audit_report, show_passive=True, show_sast=True):
    """SQLi denetim sonuçlarını (Pasif ve/veya SAST) terminale yazdırır."""
    print("\n" + "=" * 65)
    print("SQL INJECTION (CWE-89) VE GÜVENLİK DENETİM SONUÇLARI")
    print("=" * 65)

    if show_passive:
        if audit_report.passive_findings:
            print(
                f"\n[*] Pasif Web Saldırı Yüzeyi ve Hata İfşası Bulguları "
                f"({len(audit_report.passive_findings)} adet):"
            )
            for idx, f_item in enumerate(audit_report.passive_findings, start=1):
                print(f"  {idx}. [{f_item.severity}] {f_item.cwe}")
                print(f"     Konum     : {f_item.location}")
                print(f"     Parametre : {f_item.parameter}")
                print(f"     Kanıt     : {f_item.evidence}")
                print(f"     Çözüm     : {f_item.remediation}")
        else:
            print("\n[*] Pasif Web Denetimi: Herhangi bir riskli parametre veya hata sızıntısı bulunmadı.")

    if show_sast:
        print(
            f"\n[*] SAST Kaynak Kod Analizi "
            f"(Taranan Dosya: {audit_report.scanned_files}, "
            f"Zafiyet: {len(audit_report.sast_findings)}, "
            f"Güvenli Sorgu: {len(audit_report.safe_usages)}):"
        )
        for idx, s_item in enumerate(audit_report.sast_findings, start=1):
            print(f"  [!] ZAFİYET #{idx}: [{s_item.severity}] {s_item.cwe}")
            print(f"      Dosya/Satır : {s_item.location}")
            print(f"      Değişken    : {s_item.parameter}")
            print(f"      Kod Satırı  : {s_item.evidence}")
            print(f"      Çözüm       : {s_item.remediation}")

        for idx, safe_item in enumerate(audit_report.safe_usages, start=1):
            print(f"  [+] GÜVENLİ KOD #{idx}: {safe_item.mechanism}")
            print(f"      Dosya/Satır : {safe_item.location}")
            print(f"      Kod Satırı  : {safe_item.evidence}")


def save_report_to_log(
    mode_label,
    base_url="",
    max_pages=50,
    max_depth=3,
    crawl_result=None,
    audit_report=None,
    source_dir="",
    output_path=None
):
    """Seçilen modülün çıktılarını zaman damgalı olarak logs/ klasörüne kaydeder."""
    logs_dir = "logs"
    os.makedirs(logs_dir, exist_ok=True)

    if output_path:
        log_path = output_path
    else:
        if base_url:
            host = urlparse(base_url).netloc.replace(":", "_").replace("/", "_")
        else:
            host = "sast_kaynak_kod"
        if not host:
            host = "site"
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_path = os.path.join(logs_dir, f"{host}_{mode_label}_{timestamp}.txt")

    with open(log_path, "w", encoding="utf-8") as f:
        f.write("=" * 65 + "\n")
        f.write(f"ZAAFİYET TARAYICI RAPORU ({mode_label.upper()})\n")
        if base_url:
            f.write(f"Hedef URL  : {base_url}\n")
            f.write(f"Ayarlar    : Max Pages={max_pages}, Max Depth={max_depth}\n")
        if source_dir and audit_report:
            f.write(f"Kaynak Kod : {source_dir} ({audit_report.scanned_files} dosya tarandı)\n")
        f.write(f"Tarih      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 65 + "\n\n")

        f.write("ÖZET:\n")
        if crawl_result is not None:
            f.write(f"- Keşfedilen Sayfalar          : {len(crawl_result.pages)}\n")
            f.write(f"- Keşfedilen Formlar           : {len(crawl_result.forms)}\n")
            f.write(f"- Parametreli URL'ler          : {len(crawl_result.param_urls)}\n")
            f.write(f"- robots.txt Kuralları         : {len(crawl_result.disallowed_paths)}\n")
        if audit_report is not None:
            if crawl_result is not None:
                f.write(f"- Pasif Web Denetim Bulguları  : {len(audit_report.passive_findings)}\n")
            if source_dir:
                f.write(f"- SAST Kaynak Kod Zafiyetleri  : {len(audit_report.sast_findings)}\n")
                f.write(f"- Doğrulanan Güvenli Sorgular  : {len(audit_report.safe_usages)}\n")
        f.write("\n")

        if crawl_result is not None:
            if crawl_result.disallowed_paths:
                f.write("-" * 50 + "\n")
                f.write("ROBOTS.TXT BULGULARI:\n")
                f.write("-" * 50 + "\n")
                for path in crawl_result.disallowed_paths:
                    f.write(f"Disallow: {path}\n")
                f.write("\n")

            f.write("-" * 50 + "\n")
            f.write("SAYFALAR VE DURUM KODLARI:\n")
            f.write("-" * 50 + "\n")
            for page in crawl_result.pages:
                f.write(f"[{page.status_code}] (Derinlik: {page.depth}) {page.url}\n")
            f.write("\n")

            f.write("-" * 50 + "\n")
            f.write("FORMLAR VE GİRDİ ALANI DETAYLARI:\n")
            f.write("-" * 50 + "\n")
            for form in crawl_result.forms:
                inj = ", ".join(i.name for i in form.injectable_inputs)
                f.write(f"[{form.method.upper()}] {form.action} (Kaynak: {form.page_url})\n")
                f.write(f"  Test Edilebilir: [{inj if inj else 'Yok'}]\n")
                for inp in form.inputs:
                    f.write(
                        f"    - {inp.name} (Tür: {inp.type}, Değer: '{inp.value}', "
                        f"Test Edilebilir: {inp.is_injectable})\n"
                    )
                f.write("\n")

            f.write("-" * 50 + "\n")
            f.write("PARAMETRELİ URL'LER:\n")
            f.write("-" * 50 + "\n")
            for p_url in crawl_result.param_urls:
                f.write(f"URL: {p_url.url}\n")
                f.write(f"  Tam Adres: {p_url.full_url}\n")
                f.write("  Parametreler:\n")
                for k, v in p_url.params.items():
                    f.write(f"    - {k} = {v}\n")
                f.write("\n")

        if audit_report is not None:
            if audit_report.passive_findings:
                f.write("-" * 50 + "\n")
                f.write("PASİF WEB DENETİM BULGULARI (CWE-89 / CWE-209 / CWE-352):\n")
                f.write("-" * 50 + "\n")
                for idx, item in enumerate(audit_report.passive_findings, start=1):
                    f.write(f"{idx}. [{item.severity}] {item.cwe}\n")
                    f.write(f"   Konum     : {item.location}\n")
                    f.write(f"   Parametre : {item.parameter}\n")
                    f.write(f"   Kanıt     : {item.evidence}\n")
                    f.write(f"   Çözüm     : {item.remediation}\n\n")

            if source_dir:
                f.write("-" * 50 + "\n")
                f.write("SAST KAYNAK KOD ANALİZİ BULGULARI (CWE-89):\n")
                f.write("-" * 50 + "\n")
                for idx, item in enumerate(audit_report.sast_findings, start=1):
                    f.write(f"ZAFİYET #{idx}: [{item.severity}] {item.cwe}\n")
                    f.write(f"   Dosya/Satır : {item.location}\n")
                    f.write(f"   Değişken    : {item.parameter}\n")
                    f.write(f"   Kod Satırı  : {item.evidence}\n")
                    f.write(f"   Çözüm       : {item.remediation}\n\n")

                for idx, s_item in enumerate(audit_report.safe_usages, start=1):
                    f.write(f"GÜVENLİ KOD #{idx}: {s_item.mechanism}\n")
                    f.write(f"   Dosya/Satır : {s_item.location}\n")
                    f.write(f"   Kod Satırı  : {s_item.evidence}\n\n")

    print(f"\n[+] Rapor başarıyla '{log_path}' dosyasına kaydedildi.")
    return log_path


def execute_workflow(
    mode,
    target_url=None,
    max_pages=50,
    max_depth=3,
    use_dvwa_login=False,
    cookie_str=None,
    source_dir=None,
    output_path=None
):
    """Seçilen çalışma moduna ('crawler', 'sqli-passive', 'sast', 'hybrid') göre işlemleri yürütür."""
    crawl_result = None
    base = ""

    # Web taraması gerektiren modlar: crawler, sqli-passive, hybrid
    if mode in ("crawler", "sqli-passive", "hybrid") and target_url:
        base = normalize_url(target_url)
        try:
            session = build_session(base, use_dvwa_login=use_dvwa_login, cookie_str=cookie_str)
        except requests.RequestException:
            print(f"\n[!] HATA: Hedefe bağlanılamadı ({base}).")
            print("    Lütfen hedef web sunucusunun (veya Docker/DVWA'nın) çalıştığından emin olun.")
            if mode != "hybrid" or not source_dir:
                return
            base = ""

        if base:
            print(f"\n[*] Web Crawler başlatılıyor: {base} (Max Derinlik: {max_depth}, Max Sayfa: {max_pages})...")
            crawl_result = Crawler(
                base,
                session=session,
                max_pages=max_pages,
                max_depth=max_depth
            ).crawl()
            print_crawl_summary(crawl_result)

    # Sadece Crawler Modu
    if mode == "crawler":
        if crawl_result is not None:
            save_report_to_log(
                mode_label="crawler",
                base_url=base,
                max_pages=max_pages,
                max_depth=max_depth,
                crawl_result=crawl_result,
                output_path=output_path
            )
        return

    # SQLi Denetim Modları: sqli-passive, sast, hybrid
    analyzer = HybridSQLiAnalyzer()
    if mode == "sqli-passive":
        audit_report = analyzer.run_hybrid_audit(crawl_result=crawl_result, source_path=None)
        print_sqli_audit_summary(audit_report, show_passive=True, show_sast=False)
        save_report_to_log(
            mode_label="sqli_pasif",
            base_url=base,
            max_pages=max_pages,
            max_depth=max_depth,
            crawl_result=crawl_result,
            audit_report=audit_report,
            output_path=output_path
        )
    elif mode == "sast":
        if not source_dir or not os.path.exists(source_dir):
            print(f"\n[!] HATA: Kaynak kod yolu bulunamadı: '{source_dir}'")
            return
        audit_report = analyzer.run_hybrid_audit(crawl_result=None, source_path=source_dir)
        print_sqli_audit_summary(audit_report, show_passive=False, show_sast=True)
        save_report_to_log(
            mode_label="sast",
            audit_report=audit_report,
            source_dir=source_dir,
            output_path=output_path
        )
    elif mode == "hybrid":
        audit_report = analyzer.run_hybrid_audit(crawl_result=crawl_result, source_path=source_dir)
        print_sqli_audit_summary(
            audit_report,
            show_passive=(crawl_result is not None),
            show_sast=bool(source_dir)
        )
        save_report_to_log(
            mode_label="hibrit",
            base_url=base,
            max_pages=max_pages,
            max_depth=max_depth,
            crawl_result=crawl_result,
            audit_report=audit_report,
            source_dir=source_dir or "",
            output_path=output_path
        )


def prompt_web_target_settings():
    """Kullanıcıdan interaktif olarak hedef URL ve oturum ayarlarını alır."""
    target_url = input("\nTaranacak site adresi (Varsayılan: http://localhost:8080): ").strip()
    if not target_url:
        target_url = "http://localhost:8080"

    print("\nOturum / Giriş Türü:")
    print("  [1] Standart Tarama (Oturum / Giriş yok)")
    print("  [2] DVWA Test Ortamı (Otomatik admin/password girişi)")
    print("  [3] Özel Cookie (Çerez) ile Tarama")
    auth_choice = input("Seçiminiz (1, 2 veya 3 - Varsayılan: 2): ").strip() or "2"

    use_dvwa = (auth_choice == "2")
    cookie_val = None
    if auth_choice == "3":
        cookie_val = input("Cookie değeri (Örn: PHPSESSID=xyz; security=low): ").strip()

    depth_str = input("Maksimum tarama derinliği (Varsayılan: 3): ").strip()
    max_depth = int(depth_str) if depth_str.isdigit() else 3

    pages_str = input("Maksimum sayfa sınırı (Varsayılan: 50): ").strip()
    max_pages = int(pages_str) if pages_str.isdigit() else 50

    return target_url, max_pages, max_depth, use_dvwa, cookie_val


def prompt_source_dir():
    """Kullanıcıdan SAST için kaynak kod dizinini alır."""
    default_dir = os.path.join("samples", "dvwa_sqli_ornekleri")
    src = input(f"\nSAST için kaynak kod klasörü/dosyası (Varsayılan: {default_dir}): ").strip()
    return src if src else default_dir


def interactive_main_menu():
    """Kullanıcıya tüm modülleri bağımsız seçebileceği interaktif Ana Menü sunar."""
    while True:
        print("\n" + "=" * 65)
        print("          OTOMATİK ZAFİYET TARAYICI — ANA MENÜ")
        print("   Tekirdağ Namık Kemal Üniversitesi - Bilgisayar Mühendisliği")
        print("=" * 65)
        print("  [1] Web Keşif Motoru (Sadece Crawler - Sayfa, Form, Parametre, robots.txt)")
        print("  [2] Pasif SQLi ve Web Güvenlik Denetimi (Crawler + CWE-89 / CWE-209)")
        print("  [3] SAST Kaynak Kod Analizi (PHP / Python Dosyalarında CWE-89 SQLi Tespiti)")
        print("  [4] Tam Kapsamlı Hibrit Tarama (Crawler + Pasif SQLi + SAST Birlikte)")
        print("  [0] Çıkış")
        print("-" * 65)

        choice = input("Yapmak istediğiniz işlemi seçin (0-4): ").strip()

        if choice in ("0", "q", "Q", "cikis", "çıkış"):
            print("\n[*] Programdan çıkılıyor. İyi çalışmalar!")
            break

        elif choice == "1":
            print("\n--- [MODÜL 1] SADECE WEB KEŞİF MOTORU (CRAWLER) ---")
            target_url, max_pages, max_depth, use_dvwa, cookie_val = prompt_web_target_settings()
            execute_workflow(
                mode="crawler",
                target_url=target_url,
                max_pages=max_pages,
                max_depth=max_depth,
                use_dvwa_login=use_dvwa,
                cookie_str=cookie_val
            )

        elif choice == "2":
            print("\n--- [MODÜL 2] PASİF SQLi VE WEB GÜVENLİK DENETİMİ ---")
            target_url, max_pages, max_depth, use_dvwa, cookie_val = prompt_web_target_settings()
            execute_workflow(
                mode="sqli-passive",
                target_url=target_url,
                max_pages=max_pages,
                max_depth=max_depth,
                use_dvwa_login=use_dvwa,
                cookie_str=cookie_val
            )

        elif choice == "3":
            print("\n--- [MODÜL 3] SAST STATİK KAYNAK KOD ANALİZİ (CWE-89) ---")
            src_dir = prompt_source_dir()
            execute_workflow(mode="sast", source_dir=src_dir)

        elif choice == "4":
            print("\n--- [MODÜL 4] TAM KAPSAMLI HİBRİT TARAMA (WEB + SAST) ---")
            target_url, max_pages, max_depth, use_dvwa, cookie_val = prompt_web_target_settings()
            src_dir = prompt_source_dir()
            execute_workflow(
                mode="hybrid",
                target_url=target_url,
                max_pages=max_pages,
                max_depth=max_depth,
                use_dvwa_login=use_dvwa,
                cookie_str=cookie_val,
                source_dir=src_dir
            )

        else:
            print("\n[!] Geçersiz seçim! Lütfen 0 ile 4 arasında bir değer girin.")
            continue

        again = input("\nAna menüye dönmek ister misiniz? (E/h - Varsayılan: E): ").strip().lower()
        if again in ("h", "hayir", "hayır", "n", "no"):
            print("\n[*] Programdan çıkılıyor. İyi çalışmalar!")
            break


def main():
    # Eğer hiçbir komut satırı argümanı verilmemişse doğrudan İnteraktif Ana Menüyü başlat
    if len(sys.argv) == 1:
        interactive_main_menu()
        return

    parser = argparse.ArgumentParser(
        description="Otomatik Zafiyet Tarayıcı (Modüler CLI ve Ana Menü Sistemi)"
    )
    parser.add_argument(
        "--mode",
        choices=["crawler", "sqli-passive", "sast", "hybrid"],
        help="Çalışma modu: 'crawler' (Sadece Keşif), 'sqli-passive' (Pasif SQLi), 'sast' (Kaynak Kod), 'hybrid' (Tümü)"
    )
    parser.add_argument("--target", help="Hedef URL (yalnızca izinli sistemler)")
    parser.add_argument("--max-pages", type=int, default=50, help="Maksimum taranacak sayfa sayısı")
    parser.add_argument("--max-depth", type=int, default=3, help="Maksimum tarama derinliği (varsayılan: 3)")
    parser.add_argument("--dvwa-login", action="store_true", help="DVWA test ortamına otomatik giriş yap")
    parser.add_argument("--cookie", help="Giriş yapılmış oturum çerezi (Örn: 'session_id=xyz; role=user')")
    parser.add_argument(
        "--source-dir",
        help="SAST (Statik Kaynak Kod Analizi) için taranacak kaynak kod klasörü veya dosyası (.php, .py)"
    )
    parser.add_argument("--output", help="Özel log dosyası yolu")
    args = parser.parse_args()

    # --mode belirtilmemişse verilen argümanlara göre modu otomatik belirle
    mode = args.mode
    if not mode:
        if args.target and args.source_dir:
            mode = "hybrid"
        elif args.source_dir and not args.target:
            mode = "sast"
        else:
            mode = "crawler"

    if mode in ("crawler", "sqli-passive") and not args.target:
        parser.error(f"--mode {mode} için --target <URL> belirtmelisiniz.")
    if mode == "sast" and not args.source_dir:
        parser.error("--mode sast için --source-dir <KLASÖR> belirtmelisiniz.")

    execute_workflow(
        mode=mode,
        target_url=args.target,
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        use_dvwa_login=args.dvwa_login,
        cookie_str=args.cookie,
        source_dir=args.source_dir,
        output_path=args.output
    )


if __name__ == "__main__":
    main()
