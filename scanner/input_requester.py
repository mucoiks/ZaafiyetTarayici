"""Keşfedilen Form ve URL Girdilerine HTTP İsteği Gönderme Modülü (Input Requester).

Crawler (`scanner/crawler.py`) tarafından tespit edilen:
1. HTML Formlarına (`FormInfo` -> GET / POST / Multipart File)
2. Parametreli URL'lere (`ParamURL` -> GET Query Parametreleri)

otomatik olarak uygun tipte test verileri (veya kullanıcı tanımlı girdi değerleri)
yerleştirip HTTP istekleri gönderir ve sunucu yanıtlarını (durum kodu, yanıt süresi,
boyut, yansıyan girdiler ve veritabanı hata izleri) kayıt altına alır.

Doğrudan Çalıştırma Örneği:
    python -m scanner.input_requester --target http://localhost:8080 --dvwa-login
"""
import argparse
import os
import sys
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
from bs4 import BeautifulSoup

# Doğrudan bu dosya çalıştırıldığında üst dizini import yoluna ekle
if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scanner.crawler import (
    Crawler,
    CrawlResult,
    FormInfo,
    InputField,
    ParamURL,
    PASSIVE_DB_ERROR_PATTERNS,
    LOGIN_USER_FIELD_HINTS,
    LOGIN_PASS_FIELD_HINTS,
    detect_db_errors_in_text,
)

# CSRF ve oturum doğrulama alanları (orijinal değerleri korunmalıdır)
CSRF_FIELD_NAMES = {
    "user_token", "csrf_token", "csrf", "_token", "_csrf",
    "authenticity_token", "csrfmiddlewaretoken", "__requestverificationtoken"
}

# Girdi türüne göre varsayılan test değerleri
DEFAULT_VALUES_BY_TYPE = {
    "text": "test_input",
    "search": "test_search",
    "password": "TestPassword123!",
    "email": "test@example.com",
    "url": "http://example.com",
    "tel": "5551234567",
    "number": "1",
    "range": "1",
    "date": "2026-01-01",
    "datetime-local": "2026-01-01T12:00",
    "month": "2026-01",
    "week": "2026-W01",
    "time": "12:00",
    "color": "#000000",
    "textarea": "test_message_content",
}


@dataclass
class InputRequestLog:
    """Tek bir form veya parametreli URL isteğinin sonuç ve güncel sayfa yanıt kaydı."""
    source_type: str                 # "FORM" veya "PARAM_URL"
    page_url: str                    # Formun veya linkin bulunduğu kaynak sayfa
    target_url: str                  # İsteğin gönderildiği hedef adres (action / url)
    method: str                      # "GET", "POST" veya "HTTP-AUTH"
    sent_params: dict = field(default_factory=dict)
    status_code: int = 0
    elapsed_ms: float = 0.0
    response_length: int = 0
    final_url: str = ""              # İstek sonrası sayfanın yenilendiği / yönlendirildiği güncel URL
    redirect_chain: list = field(default_factory=list)
    page_title: str = ""             # Yenilenen sayfanın <title> başlığı
    response_text_summary: str = ""  # Yenilenen sayfadaki görünür metin / mesaj özeti
    response_html: str = ""          # Yenilenen sayfanın HTML kaynak kodu
    response_headers: dict = field(default_factory=dict)
    session_cookies: dict = field(default_factory=dict)
    unlocked_forms: list = field(default_factory=list)  # Giriş başarılı olduğunda yeni sayfada çıkan formlar/inputlar
    reflected_inputs: list = field(default_factory=list)
    db_errors: list = field(default_factory=list)
    error_message: str = ""


@dataclass
class InputRequestReport:
    """Tüm girdi isteklerinin toplu raporu."""
    logs: list = field(default_factory=list)  # list of InputRequestLog

    @property
    def successful_requests(self):
        return [item for item in self.logs if item.status_code > 0 and not item.error_message]

    @property
    def failed_requests(self):
        return [item for item in self.logs if item.error_message]


class InputRequester:
    """Crawler çıktısındaki tüm girdi noktalarına HTTP isteği gönderen motor."""

    def __init__(self, session=None, timeout=5, delay=0.2, custom_test_value=None):
        self.session = session or requests.Session()
        if "User-Agent" not in self.session.headers:
            self.session.headers.update({"User-Agent": Crawler.DEFAULT_USER_AGENT})
        self.timeout = timeout
        self.delay = delay
        self.custom_test_value = custom_test_value

    def _select_value_for_input(self, inp):
        """Girdi alanının türüne ve mevcut değerine göre gönderilecek veriyi belirler."""
        # Sabit alanlar (submit, button, reset) veya CSRF token alanları kendi değerini korur
        if not inp.is_injectable or inp.name.lower() in CSRF_FIELD_NAMES:
            if inp.value:
                return inp.value
            if inp.type == "submit":
                return "Submit"
            return ""

        # Kullanıcı özel bir test değeri belirttiyse onu kullan
        if self.custom_test_value is not None:
            return self.custom_test_value

        # Hidden, select, radio, checkbox alanlarında mevcut geçerli değer varsa koru, yoksa varsayılan ata
        if inp.type in ("hidden", "select", "radio", "checkbox") and inp.value:
            return inp.value

        return DEFAULT_VALUES_BY_TYPE.get(inp.type, inp.value or "1")

    def _detect_db_errors(self, html_text):
        """Yanıt gövdesinde veritabanı hata mesajı olup olmadığını kontrol eder."""
        return detect_db_errors_in_text(html_text)

    def _populate_response_details(self, log_entry: InputRequestLog, resp, injectable_names, sent_map):
        """HTTP yanıtından güncel sayfa URL'ini, başlığını, görünür metnini ve HTML'ini çıkarır."""
        log_entry.status_code = resp.status_code
        log_entry.response_length = len(resp.text)
        log_entry.final_url = resp.url or log_entry.target_url
        log_entry.redirect_chain = [f"{r.status_code} -> {r.url}" for r in getattr(resp, "history", [])]
        log_entry.response_headers = dict(resp.headers)
        log_entry.session_cookies = self.session.cookies.get_dict()
        if "Authorization" in self.session.headers:
            log_entry.session_cookies["Authorization"] = self.session.headers["Authorization"]
        log_entry.db_errors = self._detect_db_errors(resp.text)
        log_entry.response_html = resp.text[:40000]

        try:
            soup = BeautifulSoup(resp.text, "html.parser")
            if soup.title and soup.title.string:
                log_entry.page_title = soup.title.string.strip()
            for tag in soup(["script", "style", "noscript"]):
                tag.decompose()
            lines = [line.strip() for line in soup.get_text("\n").splitlines() if line.strip()]
            log_entry.response_text_summary = "\n".join(lines)[:4000]
        except Exception:
            log_entry.response_text_summary = resp.text[:2000]

        for name in injectable_names:
            sent_val = str(sent_map.get(name, ""))
            if sent_val and len(sent_val) >= 2 and sent_val in resp.text:
                log_entry.reflected_inputs.append(name)

    def send_form_request(self, form: FormInfo) -> InputRequestLog:
        """Tek bir FormInfo nesnesindeki girdileri doldurup HTTP isteği (GET/POST) gönderir."""
        method = (form.method or "get").upper()
        data = {}
        files = {}
        injectable_names = []

        for inp in form.inputs:
            if inp.type == "file":
                val = self.custom_test_value or "test_dosya_icerigi"
                files[inp.name] = ("test.txt", val.encode("utf-8"), "text/plain")
                data[inp.name] = "test.txt"
                injectable_names.append(inp.name)
            else:
                val = self._select_value_for_input(inp)
                data[inp.name] = val
                if inp.is_injectable and inp.name.lower() not in CSRF_FIELD_NAMES:
                    injectable_names.append(inp.name)

        log_entry = InputRequestLog(
            source_type="FORM",
            page_url=form.page_url,
            target_url=form.action,
            method=method,
            sent_params=dict(data)
        )

        start_time = time.perf_counter()
        try:
            if method == "HTTP-AUTH":
                u_val = str(data.get("username", ""))
                p_val = str(data.get("password", ""))
                saved_creds = getattr(self.session, "_zt_credentials", None)
                if saved_creds and saved_creds[0] and u_val in ("", "test_input", "admin"):
                    u_val, p_val = str(saved_creds[0]), str(saved_creds[1])
                    log_entry.sent_params["username"] = u_val
                    log_entry.sent_params["password"] = p_val
                resp = self.session.get(form.action, auth=HTTPBasicAuth(u_val, p_val), timeout=self.timeout)
                if resp.status_code == 401:
                    www_auth = (resp.headers.get("WWW-Authenticate") or resp.headers.get("www-authenticate") or "").lower()
                    if "digest" in www_auth:
                        resp = self.session.get(form.action, auth=HTTPDigestAuth(u_val, p_val), timeout=self.timeout)
                # Eğer HTTP 401 kapısı doğru şifreyle açıldıysa (200 OK), içerideki React/HTML sayfasının inputlarını da çıkar
                if resp.status_code == 200:
                    self.session._zt_credentials = (u_val, p_val)
                    helper_crawler = Crawler(form.action, session=self.session)
                    html_body = resp.text
                    soup_inner = BeautifulSoup(html_body, "html.parser")
                    inner_forms = helper_crawler._extract_forms(soup_inner, resp.url or form.action)
                    js_cache = {}
                    js_f, _ = helper_crawler._extract_js_and_spa_inputs(
                        soup_inner, resp.url or form.action, html_body, fetched_js_cache=js_cache
                    )
                    if not inner_forms:
                        rendered = helper_crawler._render_dom_with_headless_browser(
                            resp.url or form.action, orig_html=html_body, fetched_js_cache=js_cache
                        )
                        if rendered:
                            soup_dom = BeautifulSoup(rendered, "html.parser")
                            inner_forms = helper_crawler._extract_forms(soup_dom, resp.url or form.action)
                    if not inner_forms:
                        inner_forms.extend(js_f)
                    log_entry.unlocked_forms = inner_forms
            elif method == "POST":
                if files:
                    post_data = {k: v for k, v in data.items() if k not in files}
                    resp = self.session.post(form.action, data=post_data, files=files, timeout=self.timeout)
                else:
                    resp = self.session.post(form.action, data=data, timeout=self.timeout)
            else:
                resp = self.session.get(form.action, params=data, timeout=self.timeout)

            log_entry.elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            self._populate_response_details(log_entry, resp, injectable_names, data)

        except requests.RequestException as exc:
            log_entry.elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            log_entry.error_message = str(exc)

        return log_entry

    def send_param_url_request(self, param_url: ParamURL) -> InputRequestLog:
        """Tek bir ParamURL nesnesindeki GET parametrelerine istek gönderir."""
        params = {}
        injectable_names = []

        for k, v in param_url.params.items():
            if k.lower() in ("submit", "login", "btn", "button") or k.lower() in CSRF_FIELD_NAMES:
                params[k] = v
            else:
                params[k] = self.custom_test_value if self.custom_test_value is not None else (v or "1")
                injectable_names.append(k)

        log_entry = InputRequestLog(
            source_type="PARAM_URL",
            page_url=param_url.full_url,
            target_url=param_url.url,
            method="GET",
            sent_params=dict(params)
        )

        start_time = time.perf_counter()
        try:
            resp = self.session.get(param_url.url, params=params, timeout=self.timeout)
            log_entry.elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            self._populate_response_details(log_entry, resp, injectable_names, params)

        except requests.RequestException as exc:
            log_entry.elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            log_entry.error_message = str(exc)

        return log_entry

    def perform_auto_login(self, target_url: str, username: str, password: str) -> InputRequestLog:
        """Hedef sayfadaki Login formunu (HTML Form, CSRF Token, React/SPA API veya HTTP 401) otomatik bulup
        verilen kullanıcı adı / öğrenci no ve şifre ile HTTP Request üzerinden oturum açar.
        """
        start_time = time.perf_counter()
        self.session._zt_credentials = (username, password)
        log_entry = InputRequestLog(
            source_type="AUTO_LOGIN",
            page_url=target_url,
            target_url=target_url,
            method="POST",
            sent_params={}
        )

        try:
            # 1. Hedef sayfaya ilk GET isteğini at (HTTP 401 Basic / Digest varsa otomatik doğrula)
            resp = self.session.get(target_url, auth=HTTPBasicAuth(username, password), timeout=self.timeout)
            if resp.status_code == 401:
                www_auth = (resp.headers.get("WWW-Authenticate") or resp.headers.get("www-authenticate") or "").lower()
                if "digest" in www_auth:
                    resp = self.session.get(target_url, auth=HTTPDigestAuth(username, password), timeout=self.timeout)

            current_url = resp.url or target_url
            html_body = resp.text

            # 2. Sayfadaki formları ve inputları (HTML + Headless Tarayıcı DOM + React/SPA JS paketleri) keşfet
            helper_crawler = Crawler(current_url, session=self.session, timeout=self.timeout)
            soup = BeautifulSoup(html_body, "html.parser")
            forms = helper_crawler._extract_forms(soup, current_url)

            # Eğer standart HTML içinde login formu yoksa JS/SPA paket analizi ve Headless DOM çalıştır
            has_login = any(getattr(f, "is_login_form", False) for f in forms)
            if not has_login:
                js_cache = {}
                js_forms, _ = helper_crawler._extract_js_and_spa_inputs(
                    soup, current_url, html_body, fetched_js_cache=js_cache
                )
                rendered_html = helper_crawler._render_dom_with_headless_browser(
                    current_url, orig_html=html_body, fetched_js_cache=js_cache
                )
                if rendered_html:
                    soup_dom = BeautifulSoup(rendered_html, "html.parser")
                    dom_forms = helper_crawler._extract_forms(soup_dom, current_url)
                    for df in dom_forms:
                        if df not in forms:
                            forms.append(df)
                for jf in js_forms:
                    if jf not in forms:
                        forms.append(jf)

            # Eğer ana sayfada hala login formu yoksa ancak sayfada /login, /login.php, /giris linki varsa orayı kontrol et
            has_login = any(getattr(f, "is_login_form", False) for f in forms)
            if not has_login and not forms:
                for a_tag in soup.find_all("a", href=True):
                    href_low = a_tag["href"].lower()
                    if any(k in href_low for k in ("login", "giris", "signin", "auth")):
                        login_page_url = requests.compat.urljoin(current_url, a_tag["href"])
                        resp_l = self.session.get(login_page_url, timeout=self.timeout)
                        current_url = resp_l.url or login_page_url
                        html_body = resp_l.text
                        soup_l = BeautifulSoup(html_body, "html.parser")
                        forms = helper_crawler._extract_forms(soup_l, current_url)
                        if not forms:
                            js_f, _ = helper_crawler._extract_js_and_spa_inputs(soup_l, current_url, html_body)
                            forms.extend(js_f)
                        if forms:
                            break

            # Sadece HTTP 401 korumalı bir klasör/sayfa ise ve içeride başka login formu yoksa doğrudan ilk yanıtı döndür
            login_candidates = [f for f in forms if getattr(f, "is_login_form", False)]
            target_form = login_candidates[0] if login_candidates else (forms[0] if forms else None)

            if target_form is None:
                # Form bulunamadıysa ancak HTTP 200 döndüyse veya SPA JSON API uç noktası ise
                log_entry.method = "HTTP-AUTH" if resp.request.headers.get("Authorization") else "GET"
                log_entry.sent_params = {"username": username, "password": password}
                log_entry.elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
                self._populate_response_details(log_entry, resp, ["username"], log_entry.sent_params)
                return log_entry

            # 3. Seçilen Login Formundaki inputlara username/öğrenci no, password ve CSRF token değerlerini yerleştir
            payload = {}
            user_matched = False
            pass_matched = False
            injectable_names = []

            for inp in target_form.inputs:
                name_low = inp.name.lower()
                # CSRF token veya gizli oturum alanlarını olduğu gibi koru
                if name_low in CSRF_FIELD_NAMES or (inp.type == "hidden" and inp.value):
                    payload[inp.name] = inp.value
                    continue
                if not inp.is_injectable:
                    if inp.value:
                        payload[inp.name] = inp.value
                    elif inp.type == "submit":
                        payload[inp.name] = "Login"
                    continue

                is_pass_field = (
                    inp.type == "password"
                    or any(h in name_low for h in LOGIN_PASS_FIELD_HINTS)
                )
                is_user_field = (
                    not is_pass_field
                    and any(h in name_low for h in LOGIN_USER_FIELD_HINTS)
                )

                if is_pass_field:
                    payload[inp.name] = password
                    if "(" in inp.name and inp.name.endswith(")"):
                        clean_k = inp.name.rsplit("(", 1)[-1].rstrip(")").strip()
                        if clean_k and clean_k not in payload:
                            payload[clean_k] = password
                    elif " " in inp.name and "password" not in payload:
                        payload["password"] = password
                    pass_matched = True
                elif is_user_field:
                    payload[inp.name] = username
                    if "(" in inp.name and inp.name.endswith(")"):
                        clean_k = inp.name.rsplit("(", 1)[-1].rstrip(")").strip()
                        if clean_k and clean_k not in payload:
                            payload[clean_k] = username
                    elif " " in inp.name and "username" not in payload:
                        payload["username"] = username
                    user_matched = True
                    injectable_names.append(inp.name)
                else:
                    # Henüz kullanıcı adı alanı eşleşmediyse ilk metin/sayı/email alanına kullanıcı adını ata
                    if not user_matched and inp.type in ("text", "email", "number", "tel", "search"):
                        payload[inp.name] = username
                        user_matched = True
                        injectable_names.append(inp.name)
                    elif not pass_matched:
                        payload[inp.name] = password
                        pass_matched = True
                    else:
                        payload[inp.name] = inp.value or username

            if not user_matched:
                payload["username"] = username
                injectable_names.append("username")
            if not pass_matched:
                payload["password"] = password

            # 4. Login isteğini gönder (HTML Form URL-Encoded veya React/SPA JSON API)
            action_url = target_form.action or current_url
            if action_url == current_url:
                for alt_f in login_candidates:
                    if alt_f.action and alt_f.action != current_url:
                        action_url = alt_f.action
                        break
            method = (target_form.method or "post").upper()
            f_type_str = getattr(target_form, "form_type", "")
            if method == "GET" and getattr(target_form, "is_login_form", False) and ("SPA" in f_type_str or "Formsuz" in f_type_str):
                method = "POST"

            log_entry.page_url = target_form.page_url or current_url
            log_entry.target_url = action_url
            log_entry.method = method
            log_entry.sent_params = dict(payload)

            parsed_curr = urlparse(current_url)
            origin_url = f"{parsed_curr.scheme}://{parsed_curr.netloc}"
            req_headers = {"Referer": current_url, "Origin": origin_url}

            is_spa_form = "SPA" in getattr(target_form, "form_type", "") or "/api/" in action_url.lower()

            if method == "POST":
                if is_spa_form:
                    resp_login = self.session.post(action_url, json=payload, headers=req_headers, timeout=self.timeout)
                    if resp_login.status_code in (400, 404, 405, 415, 422):
                        resp_login = self.session.post(action_url, data=payload, headers=req_headers, timeout=self.timeout)
                else:
                    resp_login = self.session.post(action_url, data=payload, headers=req_headers, timeout=self.timeout)
                    # Eğer sunucu JSON bekliyorsa (400/415) JSON olarak da dene
                    if resp_login.status_code in (400, 415) or "application/json" in (resp_login.headers.get("Content-Type") or ""):
                        try:
                            resp_json_try = self.session.post(action_url, json=payload, headers=req_headers, timeout=self.timeout)
                            if resp_json_try.status_code < resp_login.status_code:
                                resp_login = resp_json_try
                        except requests.RequestException:
                            pass
            else:
                resp_login = self.session.get(action_url, params=payload, headers=req_headers, timeout=self.timeout)

            # DVWA gibi özel güvenlik çerezi kullanan sistemler için security=low çerezini de ekle
            if "login.php" in action_url.lower():
                self.session.cookies.set("security", "low")

            # 5. Eğer yanıt JSON ise ve içinde JWT / Bearer token döndüyse oturum başlığına otomatik ekle
            ctype = (resp_login.headers.get("Content-Type") or "").lower()
            if "json" in ctype or resp_login.text.strip().startswith("{"):
                try:
                    jdata = resp_login.json()
                    if isinstance(jdata, dict):
                        token_val = (
                            jdata.get("token")
                            or jdata.get("access_token")
                            or jdata.get("accessToken")
                            or jdata.get("jwt")
                            or (jdata.get("data", {}) if isinstance(jdata.get("data"), dict) else {}).get("token")
                        )
                        if token_val and isinstance(token_val, str):
                            self.session.headers["Authorization"] = f"Bearer {token_val}"
                except ValueError:
                    pass

            # 6. Giriş sonrası açılan yeni sayfadaki formları/inputları tespit et (unlocked_forms)
            post_soup = BeautifulSoup(resp_login.text, "html.parser")
            post_url = resp_login.url or action_url
            log_entry.unlocked_forms = helper_crawler._extract_forms(post_soup, post_url)

            log_entry.elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            self._populate_response_details(log_entry, resp_login, injectable_names, payload)

        except requests.RequestException as exc:
            log_entry.elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            log_entry.error_message = str(exc)

        return log_entry

    def send_all_from_crawl(self, crawl_result: CrawlResult) -> InputRequestReport:
        """CrawlResult içindeki tüm test edilebilir formlara ve parametreli URL'lere sırayla istek atar."""
        report = InputRequestReport()
        if crawl_result is None:
            return report

        # 1. Formlara istek gönder
        for form in crawl_result.forms:
            if not form.injectable_inputs:
                continue
            log_item = self.send_form_request(form)
            report.logs.append(log_item)
            time.sleep(self.delay)

        # 2. Parametreli URL'lere istek gönder
        for p_url in crawl_result.param_urls:
            if not p_url.params:
                continue
            log_item = self.send_param_url_request(p_url)
            report.logs.append(log_item)
            time.sleep(self.delay)

        return report


def print_input_request_summary(report: InputRequestReport):
    """Gönderilen girdi isteklerinin sonuçlarını terminale düzenli biçimde yazdırır."""
    print("\n" + "=" * 65)
    print("GİRDİ ALANLARINA İSTEK GÖNDERİM (INPUT REQUESTER) SONUÇLARI")
    print("=" * 65)
    print(
        f"[+] Toplam Gönderilen İstek: {len(report.logs)} "
        f"(Başarılı: {len(report.successful_requests)}, Hatalı: {len(report.failed_requests)})\n"
    )

    for idx, item in enumerate(report.logs, start=1):
        param_str = ", ".join(f"{k}='{v}'" for k, v in item.sent_params.items())
        if item.error_message:
            print(f"  {idx}. [{item.source_type}] [{item.method}] {item.target_url} -> HATA: {item.error_message}")
            continue

        print(
            f"  {idx}. [{item.source_type}] [{item.method}] {item.target_url} "
            f"-> Durum: {item.status_code} | Süre: {item.elapsed_ms} ms | Boyut: {item.response_length} B"
        )
        print(f"     Gönderilen Veriler : {{{param_str}}}")
        if item.final_url and item.final_url != item.target_url:
            print(f"     Güncel Sayfa (URL) : {item.final_url}")
        if item.page_title:
            print(f"     Sayfa Başlığı      : {item.page_title}")
        if item.reflected_inputs:
            print(f"     Yanıtta Yansıyanlar: {item.reflected_inputs}")
        if item.db_errors:
            print(f"     [!] Veritabanı Hatası: {', '.join(item.db_errors)}")
        if item.response_text_summary:
            short_preview = " | ".join(item.response_text_summary.splitlines()[:4])[:220]
            print(f"     Sayfa Cevap Özeti  : {short_preview}")


def main():
    parser = argparse.ArgumentParser(
        description="Crawler ile keşfedilen tüm girdi alanlarına (Form ve URL) HTTP isteği gönderir."
    )
    parser.add_argument("--target", required=True, help="Hedef site adresi (Örn: http://localhost:8080)")
    parser.add_argument("--max-pages", type=int, default=50, help="Maksimum taranacak sayfa sayısı")
    parser.add_argument("--max-depth", type=int, default=3, help="Maksimum tarama derinliği")
    parser.add_argument("--dvwa-login", action="store_true", help="DVWA test ortamına otomatik giriş yap")
    parser.add_argument("--cookie", help="Özel oturum çerezi (Örn: 'PHPSESSID=xyz; security=low')")
    parser.add_argument("--test-value", default=None, help="Tüm girdilere gönderilecek özel test metni")
    args = parser.parse_args()

    from main import normalize_url, build_session

    base_url = normalize_url(args.target)
    session = build_session(base_url, use_dvwa_login=args.dvwa_login, cookie_str=args.cookie)

    print(f"[*] Hedef taranıyor: {base_url}...")
    crawl_res = Crawler(
        base_url,
        session=session,
        max_pages=args.max_pages,
        max_depth=args.max_depth
    ).crawl()

    print(f"[*] Keşfedilen {len(crawl_res.forms)} form ve {len(crawl_res.param_urls)} parametreli URL'ye istek gönderiliyor...")
    requester = InputRequester(session=session, custom_test_value=args.test_value)
    req_report = requester.send_all_from_crawl(crawl_res)
    print_input_request_summary(req_report)


if __name__ == "__main__":
    main()
