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
    parser.add_argument("--max-pages", type=int, default=50)
    parser.add_argument("--dvwa-login", action="store_true", help="DVWA test ortamına otomatik giriş yap")
    parser.add_argument("--cookie", help="Giriş yapılmış oturum çerezi (Örn: 'session_id=xyz; role=user')")
    parser.add_argument("--output", help="Özel log dosyası yolu (varsayılan: logs/[site]_[tarih].txt)")
    args = parser.parse_args()

    base = args.target.strip().rstrip("/")
    if not base.startswith(("http://", "https://")):
        base = "http://" + base
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

    result = Crawler(base, session=session, max_pages=args.max_pages).crawl()

    summary_text = (
        f"\n[+] {len(result.pages)} sayfa, {len(result.forms)} form, "
        f"{len(result.param_urls)} parametreli URL bulundu\n"
    )
    print(summary_text)

    # Terminale yazdır
    for page in result.pages:
        print(f"  sayfa: {page}")
    for form in result.forms:
        names = ", ".join(i["name"] for i in form.inputs)
        print(f"  form : {form.method.upper()} {form.action}  [{names}]")

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
        f.write("=" * 60 + "\n")
        f.write(f"TARAMA RAPORU: {base}\n")
        f.write(f"Tarih: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")

        f.write(f"ÖZET:\n")
        f.write(f"- Keşfedilen Sayfalar: {len(result.pages)}\n")
        f.write(f"- Keşfedilen Formlar: {len(result.forms)}\n")
        f.write(f"- Parametreli URL'ler: {len(result.param_urls)}\n\n")

        f.write("-" * 40 + "\n")
        f.write("SAYFALAR:\n")
        f.write("-" * 40 + "\n")
        for page in result.pages:
            f.write(f"{page}\n")

        f.write("\n" + "-" * 40 + "\n")
        f.write("FORMLAR VE GİRDİ ALANLARI:\n")
        f.write("-" * 40 + "\n")
        for form in result.forms:
            names = ", ".join(i["name"] for i in form.inputs)
            f.write(f"[{form.method.upper()}] {form.action}\n")
            f.write(f"  Girdiler: {names if names else '(Input yok)'}\n")

        f.write("\n" + "-" * 40 + "\n")
        f.write("PARAMETRELİ URL'LER (Zafiyet Adayları):\n")
        f.write("-" * 40 + "\n")
        for p_url in result.param_urls:
            f.write(f"{p_url}\n")

    print(f"\n[+] Tarama sonuçları başarıyla '{log_path}' dosyasına kaydedildi.")


if __name__ == "__main__":
    main()
