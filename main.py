"""Komut satırı giriş noktası (şimdilik sadece crawler).

Kullanım:
    python main.py --target http://localhost:8080
    python main.py --target http://localhost:8080 --dvwa-login
"""
import argparse
import os
import re
from urllib.parse import urlparse

import requests

from datetime import datetime
from scanner.crawler import Crawler


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


def main():
    parser = argparse.ArgumentParser(description="Otomatik Zafiyet Tarayıcı (crawler aşaması)")
    parser.add_argument("--target", required=True, help="Hedef URL (yalnızca izinli sistemler)")
    parser.add_argument("--max-pages", type=int, default=50, help="Maksimum taranacak sayfa sayısı")
    parser.add_argument("--max-depth", type=int, default=3, help="Maksimum tarama derinliği (varsayılan: 3)")
    parser.add_argument("--dvwa-login", action="store_true", help="DVWA test ortamına otomatik giriş yap")
    parser.add_argument("--cookie", help="Giriş yapılmış oturum çerezi (Örn: 'session_id=xyz; role=user')")
    parser.add_argument("--output", help="Özel log dosyası yolu (varsayılan: logs/[site]_[tarih].txt)")
    args = parser.parse_args()

    base = args.target.strip().rstrip("/")
    if not base.startswith(("http://", "https://")):
        base = "http://" + base
    try:
        if args.dvwa_login:
            session = dvwa_login(base)
        elif args.cookie:
            session = requests.Session()
            # "name=value; name2=value2" formatındaki çerezleri ayrıştır
            for item in args.cookie.split(";"):
                if "=" in item:
                    k, v = item.strip().split("=", 1)
                    session.cookies.set(k, v)
        else:
            session = None
    except requests.RequestException as exc:
        print(f"\n[!] HATA: Hedefe bağlanılamadı ({base}).")
        print("    Lütfen hedef web sunucusunun (veya Docker/DVWA'nın) çalıştığından emin olun.")
        return

    result = Crawler(
        base,
        session=session,
        max_pages=args.max_pages,
        max_depth=args.max_depth
    ).crawl()

    summary_text = (
        f"\n[+] {len(result.pages)} sayfa, {len(result.forms)} form, "
        f"{len(result.param_urls)} parametreli URL bulundu"
    )
    if result.disallowed_paths:
        summary_text += f", {len(result.disallowed_paths)} robots.txt kuralı tespit edildi"
    print(summary_text + "\n")

    # Terminale yazdır
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
        print("\n[*] Parametreli URL'ler (Zafiyet Test Adayları):")
        for p_url in result.param_urls:
            p_names = ", ".join(p_url.params.keys())
            print(f"  GET {p_url.full_url}  -> Parametreler: [{p_names}]")

    # logs klasörünü oluştur ve dinamik dosya adı belirle
    logs_dir = "logs"
    os.makedirs(logs_dir, exist_ok=True)

    if args.output:
        log_path = args.output
    else:
        host = urlparse(base).netloc.replace(":", "_").replace("/", "_")
        if not host:
            host = "site"
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_path = os.path.join(logs_dir, f"{host}_{timestamp}.txt")

    with open(log_path, "w", encoding="utf-8") as f:
        f.write("=" * 65 + "\n")
        f.write(f"GELİŞMİŞ WEB CRAWLER KEŞİF RAPORU: {base}\n")
        f.write(f"Tarih: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Ayarlar: Max Pages={args.max_pages}, Max Depth={args.max_depth}\n")
        f.write("=" * 65 + "\n\n")

        f.write("ÖZET:\n")
        f.write(f"- Keşfedilen Sayfalar: {len(result.pages)}\n")
        f.write(f"- Keşfedilen Formlar: {len(result.forms)}\n")
        f.write(f"- Parametreli URL'ler: {len(result.param_urls)}\n")
        f.write(f"- robots.txt Kuralları: {len(result.disallowed_paths)}\n\n")

        if result.disallowed_paths:
            f.write("-" * 50 + "\n")
            f.write("ROBOTS.TXT BULGULARI:\n")
            f.write("-" * 50 + "\n")
            for path in result.disallowed_paths:
                f.write(f"Disallow: {path}\n")
            f.write("\n")

        f.write("-" * 50 + "\n")
        f.write("SAYFALAR VE DURUM KODLARI:\n")
        f.write("-" * 50 + "\n")
        for page in result.pages:
            f.write(f"[{page.status_code}] (Derinlik: {page.depth}) {page.url}\n")

        f.write("\n" + "-" * 50 + "\n")
        f.write("FORMLAR VE GİRDİ ALANI DETAYLARI:\n")
        f.write("-" * 50 + "\n")
        for form in result.forms:
            inj = ", ".join(i.name for i in form.injectable_inputs)
            f.write(f"[{form.method.upper()}] {form.action} (Kaynak: {form.page_url})\n")
            f.write(f"  Test Edilebilir: [{inj if inj else 'Yok'}]\n")
            for inp in form.inputs:
                f.write(f"    - {inp.name} (Tür: {inp.type}, Değer: '{inp.value}', Test Edilebilir: {inp.is_injectable})\n")
            f.write("\n")

        f.write("-" * 50 + "\n")
        f.write("PARAMETRELİ URL'LER (SQLi & XSS Test Noktaları):\n")
        f.write("-" * 50 + "\n")
        for p_url in result.param_urls:
            f.write(f"URL: {p_url.url}\n")
            f.write(f"  Tam Adres: {p_url.full_url}\n")
            f.write(f"  Parametreler:\n")
            for k, v in p_url.params.items():
                f.write(f"    - {k} = {v}\n")
            f.write("\n")

    print(f"\n[+] Tarama sonuçları başarıyla '{log_path}' dosyasına kaydedildi.")


if __name__ == "__main__":
    main()
