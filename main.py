"""Otomatik Zafiyet Tarayıcı — Ana Giriş Noktası ve İnteraktif Menü Sistemi.

Hem interaktif konsol menüsüyle (parametresiz çalıştırıldığında) hem de
komut satırı argümanlarıyla (CLI) çalışır:

İnteraktif Menü:
    python main.py

Komut Satırı (CLI) Örnekleri:
    python main.py --mode crawler --target http://localhost:8080 --dvwa-login
    python main.py --mode requester --target http://localhost:8080 --dvwa-login
    python main.py --mode sqli --target http://localhost:8080 --dvwa-login
    python main.py --mode full --target http://localhost:8080 --dvwa-login
"""
import argparse
import os
import re
import sys
from datetime import datetime
from urllib.parse import urlparse

import requests
from requests.auth import AuthBase, HTTPBasicAuth, HTTPDigestAuth

from scanner.crawler import Crawler, CrawlResult
from scanner.sqli_analyzer import HybridSQLiAnalyzer


class SmartHTTPAuth(AuthBase):
    """Sunucunun WWW-Authenticate başlığına göre hem Basic hem Digest Auth destekleyen akıllı kimlik doğrulayıcı."""

    def __init__(self, username, password, allowed_host=None):
        self.username = username
        self.password = password
        self.allowed_host = (allowed_host or "").lower().split(":")[0]
        self._basic = HTTPBasicAuth(username, password)
        self._digest = HTTPDigestAuth(username, password)

    def _handle_401(self, r, **kwargs):
        if r.status_code == 401:
            www_auth = (r.headers.get("WWW-Authenticate") or r.headers.get("www-authenticate") or "").lower()
            if "digest" in www_auth:
                return self._digest.handle_401(r, **kwargs)
        return r

    def __call__(self, r):
        if self.allowed_host:
            req_host = urlparse(r.url).netloc.lower().split(":")[0]
            clean_req = req_host[4:] if req_host.startswith("www.") else req_host
            clean_allow = self.allowed_host[4:] if self.allowed_host.startswith("www.") else self.allowed_host
            if clean_req and clean_req != clean_allow and not clean_req.endswith("." + clean_allow):
                return r
        self._digest.init_per_thread_state()
        self._digest._thread_local.pos = None
        self._digest._thread_local.num_401_calls = 1
        if self._digest._thread_local.last_nonce:
            return self._digest(r)
        r = self._basic(r)
        r.register_hook("response", self._handle_401)
        r.register_hook("response", self._digest.handle_redirect)
        return r


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


def build_session(base_url, use_dvwa_login=False, cookie_str=None, http_user=None, http_pass=None, auto_login=False):
    """Seçilen oturum yöntemine göre requests.Session nesnesi hazırlar."""
    if use_dvwa_login:
        return dvwa_login(base_url)
    session = requests.Session()
    if cookie_str:
        for item in cookie_str.split(";"):
            if "=" in item:
                k, v = item.strip().split("=", 1)
                session.cookies.set(k, v)
    if http_user is not None and http_user != "":
        allowed_host = urlparse(base_url).netloc if base_url else None
        session.auth = SmartHTTPAuth(http_user, http_pass or "", allowed_host=allowed_host)
        session._zt_credentials = (http_user, http_pass or "")
        if auto_login:
            from scanner.input_requester import InputRequester
            login_log = InputRequester(session=session).perform_auto_login(base_url, http_user, http_pass or "")
            session._auto_login_log = login_log
    return session


def normalize_url(target_url):
    """Hedef URL'yi standart http/https formatına getirir."""
    base = target_url.strip().rstrip("/")
    if not base.startswith(("http://", "https://")):
        base = "http://" + base
    return base


def print_crawl_summary(result):
    """Crawler sonuçlarını (1. Adres Haritası, 2. İçine Input Alabilen Adresler) terminale yazdırır."""
    input_pages = [p for p in result.pages if getattr(p, "has_inputs", False)]
    summary_text = (
        f"\n[+] Sitenin Adres Haritası: {len(result.pages)} adres keşfedildi | "
        f"İçine Input Alabilen Adres Sayısı: {len(input_pages)} "
        f"({len(result.forms)} Form/Input Grubu, {len(result.param_urls)} Parametreli URL)"
    )
    if result.disallowed_paths:
        summary_text += f" | {len(result.disallowed_paths)} robots.txt kuralı"
    print(summary_text + "\n")

    print("=" * 65)
    print("1. SİTENİN TAM ADRES HARİTASI (SITE MAP)")
    print("=" * 65)
    for idx, page in enumerate(result.pages, start=1):
        inp_badge = (
            f" --> [INPUT ALABİLİYOR: {page.input_count} girdi]"
            if getattr(page, "has_inputs", False)
            else " [Statik / Input Yok]"
        )
        title_str = f" ({page.title})" if getattr(page, "title", "") else ""
        print(f"  {idx:2d}. [{page.status_code}] (Derinlik: {page.depth}) {page.url}{title_str}{inp_badge}")

    print("\n" + "=" * 65)
    print(f"2. HARİTADAN SEÇİLEN İÇİNE INPUT ALABİLEN ADRESLER ({len(input_pages)} ADRES)")
    print("=" * 65)
    if not input_pages and not result.forms and not result.param_urls:
        print("  [!] Bu sitede içine input alabilen herhangi bir sayfa veya form bulunamadı.")
    else:
        for idx, page in enumerate(input_pages, start=1):
            login_tag = " [LOGIN EKRANI]" if getattr(page, "is_login_page", False) else ""
            print(f"  {idx}. {page.url}{login_tag}")
            for detail in getattr(page, "input_details", []):
                print(f"      -> Kabul Edilen Inputlar: {detail}")

    if result.forms:
        print("\n[*] Form ve Sayfa İçi Input Noktası Detayları:")
        for form in result.forms:
            inj = ", ".join(f"{i.name} ({i.type})" for i in form.injectable_inputs)
            others = ", ".join(i.name for i in form.inputs if not i.is_injectable)
            login_tag = f" [LOGIN: {form.form_type}]" if getattr(form, "is_login_form", False) else f" [{getattr(form, 'form_type', 'Form')}]"
            print(f"  [{form.method.upper()}]{login_tag} Hedef: {form.action} (Sayfa: {form.page_url})")
            print(f"      İçine Veri Girilebilen Inputlar: [{inj if inj else 'Yok'}]")
            if others:
                print(f"      Sabit/Buton Alanları           : [{others}]")

    if result.param_urls:
        print("\n[*] URL Üzerinden GET Input Alan Adresler:")
        for p_url in result.param_urls:
            p_names = ", ".join(p_url.params.keys())
            print(f"  GET {p_url.full_url}  -> Parametreler: [{p_names}]")


def print_sqli_audit_summary(audit_report):
    """Kara kutu SQLi ve güvenlik denetim sonuçlarını terminale yazdırır."""
    print("\n" + "=" * 65)
    print("KARA KUTU (BLACK-BOX) SQL INJECTION VE GÜVENLİK DENETİM SONUÇLARI")
    print("=" * 65)

    if audit_report and audit_report.passive_findings:
        print(
            f"\n[*] Tespit Edilen Kara Kutu Güvenlik Bulguları "
            f"({len(audit_report.passive_findings)} adet):"
        )
        for idx, f_item in enumerate(audit_report.passive_findings, start=1):
            print(f"  {idx}. [{f_item.severity}] {f_item.cwe} ({f_item.category})")
            print(f"     Konum     : {f_item.location}")
            print(f"     Parametre : {f_item.parameter}")
            print(f"     Kanıt     : {f_item.evidence}")
            print(f"     Çözüm     : {f_item.remediation}")
    else:
        print("\n[*] Kara Kutu Denetimi: Herhangi bir riskli parametre veya hata sızıntısı bulunmadı.")


def save_report_to_log(
    mode_label,
    base_url="",
    max_pages=50,
    max_depth=3,
    crawl_result=None,
    audit_report=None,
    req_report=None,
    output_path=None
):
    """Seçilen modülün çıktılarını zaman damgalı olarak logs/ klasörüne kaydeder."""
    logs_dir = "logs"
    os.makedirs(logs_dir, exist_ok=True)

    if output_path:
        log_path = output_path
    else:
        host = urlparse(base_url).netloc.replace(":", "_").replace("/", "_") if base_url else "site"
        if not host:
            host = "site"
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_path = os.path.join(logs_dir, f"{host}_{mode_label}_{timestamp}.txt")

    with open(log_path, "w", encoding="utf-8") as f:
        f.write("=" * 65 + "\n")
        f.write(f"ZAAFİYET TARAYICI KARA KUTU RAPORU ({mode_label.upper()})\n")
        if base_url:
            f.write(f"Hedef URL  : {base_url}\n")
            f.write(f"Ayarlar    : Max Pages={max_pages}, Max Depth={max_depth}\n")
        f.write(f"Tarih      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 65 + "\n\n")

        f.write("ÖZET:\n")
        if crawl_result is not None:
            input_pages = [p for p in crawl_result.pages if getattr(p, "has_inputs", False)]
            f.write(f"- Sitenin Adres Haritası       : {len(crawl_result.pages)} adres\n")
            f.write(f"- İçine Input Alabilen Adres   : {len(input_pages)} adres\n")
            f.write(f"- Keşfedilen Form / Input Grubu: {len(crawl_result.forms)}\n")
            f.write(f"- Parametreli URL'ler          : {len(crawl_result.param_urls)}\n")
            f.write(f"- robots.txt Kuralları         : {len(crawl_result.disallowed_paths)}\n")
        if req_report is not None:
            f.write(f"- Gönderilen HTTP İstek Sayısı : {len(req_report.logs)} istek\n")
        if audit_report is not None:
            f.write(f"- Kara Kutu Güvenlik Bulguları : {len(audit_report.passive_findings)}\n")
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
            f.write("1. SİTENİN TAM ADRES HARİTASI (SITE MAP):\n")
            f.write("-" * 50 + "\n")
            for page in crawl_result.pages:
                inp_tag = (
                    f" [INPUT ALIYOR: {page.input_count} girdi]"
                    if getattr(page, "has_inputs", False)
                    else " [Statik / Input Yok]"
                )
                title_part = f" ({page.title})" if getattr(page, "title", "") else ""
                f.write(f"[{page.status_code}] (Derinlik: {page.depth}) {page.url}{title_part}{inp_tag}\n")
            f.write("\n")

            input_pages = [p for p in crawl_result.pages if getattr(p, "has_inputs", False)]
            f.write("-" * 50 + "\n")
            f.write(f"2. HARİTADAN SEÇİLEN İÇİNE INPUT ALABİLEN ADRESLER ({len(input_pages)} ADRES):\n")
            f.write("-" * 50 + "\n")
            for idx, page in enumerate(input_pages, start=1):
                login_tag = " [LOGIN EKRANI]" if getattr(page, "is_login_page", False) else ""
                f.write(f"{idx}. {page.url}{login_tag}\n")
                for det in getattr(page, "input_details", []):
                    f.write(f"   -> {det}\n")
            f.write("\n")

            f.write("-" * 50 + "\n")
            f.write("3. FORMLAR VE GİRDİ ALANI DETAYLARI:\n")
            f.write("-" * 50 + "\n")
            for form in crawl_result.forms:
                inj = ", ".join(i.name for i in form.injectable_inputs)
                f_type_str = getattr(form, "form_type", "Standart Form")
                login_prefix = "[LOGIN EKRANI] " if getattr(form, "is_login_form", False) else ""
                f.write(f"{login_prefix}[{form.method.upper()}] ({f_type_str}) {form.action} (Kaynak: {form.page_url})\n")
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

        if req_report is not None and getattr(req_report, "logs", None):
            f.write("-" * 50 + "\n")
            f.write("4. GÖNDERİLEN HTTP İSTEKLERİ VE YANIT METNİ (RESPONSE TEXT) ÖZETİ:\n")
            f.write("-" * 50 + "\n")
            for idx, r_log in enumerate(req_report.logs, start=1):
                params_str = ", ".join(f"{k}={v}" for k, v in (r_log.sent_params or {}).items())
                if r_log.error_message:
                    f.write(f"{idx}. [{r_log.source_type}] [{r_log.method}] {r_log.target_url} -> HATA: {r_log.error_message}\n\n")
                    continue
                f.write(
                    f"{idx}. [{r_log.source_type}] [{r_log.method}] {r_log.target_url} "
                    f"-> HTTP {r_log.status_code} ({r_log.elapsed_ms} ms, {r_log.response_length} B)\n"
                )
                f.write(f"   Gönderilen Inputlar : {{{params_str}}}\n")
                if r_log.final_url and r_log.final_url != r_log.target_url:
                    f.write(f"   Güncel Sayfa (URL)  : {r_log.final_url}\n")
                if r_log.reflected_inputs:
                    f.write(f"   Yanıtta Yansıyanlar : {', '.join(r_log.reflected_inputs)}\n")
                if r_log.db_errors:
                    f.write(f"   Veritabanı Hataları : {', '.join(r_log.db_errors)}\n")
                if r_log.response_text_summary:
                    preview = " | ".join(r_log.response_text_summary.splitlines()[:4])[:250]
                    f.write(f"   Yanıt Metni Özeti   : {preview}\n")
                f.write("\n")

        if audit_report is not None and audit_report.passive_findings:
            f.write("-" * 50 + "\n")
            f.write("KARA KUTU WEB VE SQL INJECTION DENETİM BULGULARI:\n")
            f.write("-" * 50 + "\n")
            for idx, item in enumerate(audit_report.passive_findings, start=1):
                f.write(f"{idx}. [{item.severity}] {item.cwe} ({item.category})\n")
                f.write(f"   Konum     : {item.location}\n")
                f.write(f"   Parametre : {item.parameter}\n")
                f.write(f"   Kanıt     : {item.evidence}\n")
                f.write(f"   Çözüm     : {item.remediation}\n\n")

    print(f"\n[+] Rapor başarıyla '{log_path}' dosyasına kaydedildi.")
    return log_path


def execute_workflow(
    mode,
    target_url=None,
    max_pages=50,
    max_depth=3,
    use_dvwa_login=False,
    cookie_str=None,
    custom_test_val=None,
    output_path=None
):
    """Seçilen Kara Kutu (Black-Box) çalışma moduna göre işlemleri yürütür."""
    if not target_url:
        print("\n[!] HATA: Lütfen taranacak bir hedef URL belirtin.")
        return

    base = normalize_url(target_url)
    try:
        session = build_session(base, use_dvwa_login=use_dvwa_login, cookie_str=cookie_str)
    except requests.RequestException:
        print(f"\n[!] HATA: Hedefe bağlanılamadı ({base}).")
        print("    Lütfen hedef web sunucusunun çalıştığından emin olun.")
        return

    print(f"\n[*] Web Crawler başlatılıyor: {base} (Max Derinlik: {max_depth}, Max Sayfa: {max_pages})...")
    crawl_result = Crawler(
        base,
        session=session,
        max_pages=max_pages,
        max_depth=max_depth
    ).crawl()
    print_crawl_summary(crawl_result)

    # 1. Sadece Crawler Modu (Adres Haritası ve Input Alabilenlerin Listelenmesi)
    if mode == "crawler":
        save_report_to_log(
            mode_label="crawler",
            base_url=base,
            max_pages=max_pages,
            max_depth=max_depth,
            crawl_result=crawl_result,
            output_path=output_path
        )
        return

    req_report = None
    if mode in ("requester", "full"):
        from scanner.input_requester import InputRequester, print_input_request_summary
        requester = InputRequester(session=session, custom_test_value=custom_test_val)
        req_report = requester.send_all_from_crawl(crawl_result)
        print_input_request_summary(req_report)
        if mode == "requester":
            save_report_to_log(
                mode_label="input_istek",
                base_url=base,
                max_pages=max_pages,
                max_depth=max_depth,
                crawl_result=crawl_result,
                req_report=req_report,
                output_path=output_path
            )
            return

    # Kara Kutu SQLi ve Web Güvenlik Denetimi ('sqli', 'sqli-passive', 'full')
    analyzer = HybridSQLiAnalyzer()
    audit_report = analyzer.run_hybrid_audit(crawl_result=crawl_result, req_report=req_report)
    print_sqli_audit_summary(audit_report)
    save_report_to_log(
        mode_label="kara_kutu_sqli" if mode != "full" else "tam_kara_kutu",
        base_url=base,
        max_pages=max_pages,
        max_depth=max_depth,
        crawl_result=crawl_result,
        audit_report=audit_report,
        req_report=req_report,
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
    auth_choice = input("Seçiminiz (1, 2 veya 3 - Varsayılan: 1): ").strip() or "1"

    use_dvwa = (auth_choice == "2")
    cookie_val = None
    if auth_choice == "3":
        cookie_val = input("Cookie değeri (Örn: PHPSESSID=xyz; security=low): ").strip()

    depth_str = input("Maksimum tarama derinliği (Varsayılan: 5): ").strip()
    max_depth = int(depth_str) if depth_str.isdigit() else 5

    pages_str = input("Maksimum sayfa sınırı (Varsayılan: 100): ").strip()
    max_pages = int(pages_str) if pages_str.isdigit() else 100

    return target_url, max_pages, max_depth, use_dvwa, cookie_val


def interactive_main_menu():
    """Kullanıcıya Kara Kutu (Black-Box) modüllerini seçebileceği interaktif Ana Menü sunar."""
    while True:
        print("\n" + "=" * 65)
        print("      OTOMATİK ZAFİYET TARAYICI — KARA KUTU (BLACK-BOX) MENÜ")
        print("   Tekirdağ Namık Kemal Üniversitesi - Bilgisayar Mühendisliği")
        print("=" * 65)
        print("  [1] Sitenin Adres Haritası & İçine Input Alabilenleri Listele (Crawler)")
        print("  [2] Keşfedilen Inputlara HTTP İsteği Gönder ve Yanıtları Kontrol Et")
        print("  [3] Kara Kutu SQLi ve Web Güvenlik Denetimi (CWE-89 / CWE-209 / CWE-352)")
        print("  [4] Tam Kapsamlı Kara Kutu Tarama (Harita + İstek Gönderimi + SQLi Denetimi)")
        print("  [5] Web Arayüzünü Başlat (Tarayıcı Kontrol Paneli - http://127.0.0.1:5000)")
        print("  [0] Çıkış")
        print("-" * 65)

        choice = input("Yapmak istediğiniz işlemi seçin (0-5): ").strip()

        if choice in ("0", "q", "Q", "cikis", "çıkış"):
            print("\n[*] Programdan çıkılıyor. İyi çalışmalar!")
            break

        elif choice == "1":
            print("\n--- [MODÜL 1] SİTENİN ADRES HARİTASI VE INPUT ALABİLENLER (CRAWLER) ---")
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
            print("\n--- [MODÜL 2] KEŞFEDİLEN INPUTLARA HTTP İSTEĞİ GÖNDERME ---")
            target_url, max_pages, max_depth, use_dvwa, cookie_val = prompt_web_target_settings()
            custom_val = input("Tüm inputlara gönderilecek özel test değeri (Varsayılan için boş bırakın): ").strip() or None
            execute_workflow(
                mode="requester",
                target_url=target_url,
                max_pages=max_pages,
                max_depth=max_depth,
                use_dvwa_login=use_dvwa,
                cookie_str=cookie_val,
                custom_test_val=custom_val
            )

        elif choice == "3":
            print("\n--- [MODÜL 3] KARA KUTU SQLi VE WEB GÜVENLİK DENETİMİ ---")
            target_url, max_pages, max_depth, use_dvwa, cookie_val = prompt_web_target_settings()
            execute_workflow(
                mode="sqli",
                target_url=target_url,
                max_pages=max_pages,
                max_depth=max_depth,
                use_dvwa_login=use_dvwa,
                cookie_str=cookie_val
            )

        elif choice == "4":
            print("\n--- [MODÜL 4] TAM KAPSAMLI KARA KUTU TARAMA (HARİTA + İSTEK + SQLi) ---")
            target_url, max_pages, max_depth, use_dvwa, cookie_val = prompt_web_target_settings()
            custom_val = input("Tüm inputlara gönderilecek özel test değeri (Varsayılan için boş bırakın): ").strip() or None
            execute_workflow(
                mode="full",
                target_url=target_url,
                max_pages=max_pages,
                max_depth=max_depth,
                use_dvwa_login=use_dvwa,
                cookie_str=cookie_val,
                custom_test_val=custom_val
            )

        elif choice == "5":
            print("\n--- [MODÜL 5] WEB ARAYÜZÜ BAŞLATILIYOR ---")
            from web_app import run_web_server
            run_web_server(host="127.0.0.1", port=5000, open_browser=True)
            break

        else:
            print("\n[!] Geçersiz seçim! Lütfen 0 ile 5 arasında bir değer girin.")
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
        description="Otomatik Zafiyet Tarayıcı (Kara Kutu Web Keşif, İstek ve SQLi Denetim Sistemi)"
    )
    parser.add_argument(
        "--mode",
        choices=["crawler", "requester", "sqli", "sqli-passive", "full"],
        default="crawler",
        help="Çalışma modu: 'crawler' (Harita & Input Keşfi), 'requester' (İstek Gönder), 'sqli' (Kara Kutu SQLi), 'full' (Tam Tarama)"
    )
    parser.add_argument("--target", required=True, help="Hedef URL (yalnızca izinli sistemler)")
    parser.add_argument("--max-pages", type=int, default=100, help="Maksimum taranacak sayfa sayısı")
    parser.add_argument("--max-depth", type=int, default=5, help="Maksimum tarama derinliği (varsayılan: 5)")
    parser.add_argument("--dvwa-login", action="store_true", help="DVWA test ortamına otomatik giriş yap")
    parser.add_argument("--cookie", help="Giriş yapılmış oturum çerezi (Örn: 'session_id=xyz; role=user')")
    parser.add_argument("--output", help="Özel log dosyası yolu")
    args = parser.parse_args()

    execute_workflow(
        mode=args.mode,
        target_url=args.target,
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        use_dvwa_login=args.dvwa_login,
        cookie_str=args.cookie,
        output_path=args.output
    )


if __name__ == "__main__":
    main()
