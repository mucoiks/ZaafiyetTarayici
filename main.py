"""Komut satırı giriş noktası (şimdilik sadece crawler).

Kullanım:
    python main.py --target http://localhost:8080
    python main.py --target http://localhost:8080 --dvwa-login
"""
import argparse
import re

import requests

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
    parser.add_argument("--dvwa-login", action="store_true", help="DVWA test ortamına giriş yap")
    args = parser.parse_args()

    base = args.target.rstrip("/")
    session = dvwa_login(base) if args.dvwa_login else None

    result = Crawler(base, session=session, max_pages=args.max_pages).crawl()

    print(f"\n[+] {len(result.pages)} sayfa, {len(result.forms)} form, "
          f"{len(result.param_urls)} parametreli URL bulundu\n")
    for page in result.pages:
        print(f"  sayfa: {page}")
    for form in result.forms:
        names = ", ".join(i["name"] for i in form.inputs)
        print(f"  form : {form.method.upper()} {form.action}  [{names}]")


if __name__ == "__main__":
    main()
