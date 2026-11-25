"""Web crawler: hedef sitenin tam adres haritasını çıkarır ve içine input alabilen adresleri tespit eder.

Temel Yetenekler:
1. Sitenin Adres Haritası (Site Map) Çıkarma:
   - BFS (Genişlik Öncelikli Arama) ve alt-dizin önceliklendirmesi ile derinlik kontrollü tarama
   - HTML bağlantıları (<a href>, <area href>, <iframe src>, <frame src>, <form action>, <meta refresh>)
   - <base href> desteği ve ters eğik çizgi (\\ -> /) URL normalizasyonu
   - robots.txt ve sitemap.xml keşfi
   - JavaScript / SPA yönlendirmeleri ve Headless Tarayıcı (Chrome/Edge) canlı DOM link keşfi
   - Kırık (404/410) linklerin harita kotasını tüketmesini engelleme

2. Haritadan İçine Input Alabilen Adresleri Listeleme:
   - Standart HTML <form> içindeki <input>, <textarea>, <select>, <button> elemanları (HTML5 form="..." dahil)
   - <form> etiketi dışında kalan bağımsız (AJAX / Modal / React / Vue) input elemanları
   - name veya id özniteliği olmayan inputları placeholder, autocomplete, aria-label veya <label> ile tanıma
   - React / Vite / Webpack / SPA JS paketlerindeki dinamik JSX inputları ve Headless DOM inputları
   - URL üzerinden GET parametresi (?id=1&sayfa=2) alan uç noktalar
   - HTTP 401 (WWW-Authenticate Basic/Digest) kimlik doğrulama ekranları
"""
import os
import re
import subprocess
import tempfile
import time
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, urldefrag, parse_qsl, quote

import requests
from bs4 import BeautifulSoup

# Oturumu sonlandırabilecek veya veriyi sıfırlayabilecek bağlantılar atlanır.
SKIP_KEYWORDS = ("logout", "signout", "setup.php", "cikis", "oturum-kapat")

# Harici link incelemesinde (1-hop) atlanacak genel sosyal medya, CDN ve akademik indeks alan adları
IGNORED_EXTERNAL_DOMAINS = (
    "google.com", "google.com.tr", "scholar.google", "googleapis.com", "gstatic.com",
    "youtube.com", "youtu.be", "facebook.com", "twitter.com", "x.com", "instagram.com",
    "linkedin.com", "github.com", "microsoft.com", "apple.com", "adobe.com", "w3.org",
    "wikipedia.org", "orcid.org", "researchgate.net", "scopus.com", "webofscience.com",
    "clarivate.com", "dergipark.org.tr", "yok.gov.tr", "tubitak.gov.tr", "cloudflare.com",
    "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com"
)

# Statik medya/dosya uzantıları (HTML/input içermeyen ikili dosyalar)
STATIC_EXTENSIONS = (
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico", ".bmp",
    ".css", ".less", ".scss", ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".mkv",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".pdf", ".doc", ".docx",
    ".xls", ".xlsx", ".ppt", ".pptx", ".exe", ".dll", ".iso"
)

# Sadece formu tetikleyen ve veri taşımayan buton tipleri
NON_INJECTABLE_BUTTON_TYPES = ("submit", "reset", "button", "image")

# Doğrudan girdi/veri kabul etmeye uygun tüm HTML girdi türleri
INJECTABLE_INPUT_TYPES = (
    "text", "password", "hidden", "search", "email", "url", "tel",
    "textarea", "select", "number", "range", "date", "datetime-local",
    "month", "week", "time", "color", "file", "radio", "checkbox"
)

# Login ekranı / kimlik doğrulama formu tespitinde kullanılan anahtar kelimeler
LOGIN_KEYWORDS = (
    "login", "log-in", "signin", "sign-in", "giris", "giriş", "oturum",
    "auth", "authenticate", "account", "uye-giris", "uyegiris", "admin",
    "kullanici", "kullanıcı", "parola", "sifre", "şifre", "passwd", "password"
)

LOGIN_USER_FIELD_HINTS = (
    "user", "username", "userid", "user_name", "kullanici", "kullanıcı",
    "email", "e-mail", "eposta", "e-posta", "mail", "login", "account",
    "tc", "tcno", "ogrenci", "öğrenci", "student", "phone", "tel", "no", "numara"
)

LOGIN_PASS_FIELD_HINTS = (
    "pass", "password", "passwd", "pwd", "sifre", "şifre", "parola", "pin", "otp"
)

# Normal gezinme sırasında sayfada açık unutulmuş veritabanı hata izleri (Pasif CWE-209 kontrolü)
PASSIVE_DB_ERROR_PATTERNS = {
    "MySQL / MariaDB": ("you have an error in your sql syntax", "mysql_fetch", "warning: mysql"),
    "PostgreSQL": ("postgresql query failed", "pg_query()", "unterminated quoted string at or near"),
    "Microsoft SQL Server": ("unclosed quotation mark after the character string", "microsoft ole db provider for sql server"),
    "SQLite": ("sqlite3::SQLException", "sqlite_error", "unrecognized token:"),
    "Oracle": ("ora-00933", "ora-01756", "quoted string not properly terminated"),
    "Genel PDO / Veritabanı": ("pdoexception", "sqlstate["),
}


def detect_db_errors_in_text(html_text: str) -> list:
    """Metin veya HTML yanıtında veritabanı hata imzalarını pasif olarak tespit eder."""
    if not html_text:
        return []
    found = []
    lower_html = html_text.lower()
    for db_name, patterns in PASSIVE_DB_ERROR_PATTERNS.items():
        for pat in patterns:
            if pat.lower() in lower_html:
                found.append(f"{db_name} ({pat})")
                break
    return found


@dataclass
class InputField:
    """Form veya sayfa içindeki tek bir girdi alanı detayı."""
    name: str
    type: str = "text"
    value: str = ""
    is_injectable: bool = True
    placeholder: str = ""

    def __repr__(self):
        durum = "test_edilebilir" if self.is_injectable else "sabit"
        return f"{self.name} ({self.type}, {durum})"


@dataclass
class FormInfo:
    """Bir HTML formunun, bağımsız input grubunun veya Login ekranının bilgileri."""
    page_url: str
    action: str
    method: str
    inputs: list = field(default_factory=list)  # list of InputField
    is_login_form: bool = False
    form_type: str = "Standart Form"

    @property
    def injectable_inputs(self):
        """İçine veri gönderilebilecek (test edilebilir) alanları döndürür."""
        return [i for i in self.inputs if i.is_injectable]


@dataclass
class ParamURL:
    """URL üzerinden GET parametresi (?key=val) kabul eden adres bilgisi."""
    url: str               # Parametresiz temel adres
    full_url: str          # Parametreleri içeren tam adres
    params: dict = field(default_factory=dict)  # Ayrıştırılmış parametreler

    def __str__(self):
        return self.full_url


@dataclass
class PageInfo:
    """Adres haritasındaki (Site Map) tek bir sayfanın durumu ve kabul ettiği inputların özeti."""
    url: str
    status_code: int
    content_type: str
    depth: int
    title: str = ""
    has_inputs: bool = False
    input_count: int = 0
    input_details: list = field(default_factory=list)  # Sayfadaki inputların okunabilir listesi
    is_login_page: bool = False
    headers: dict = field(default_factory=dict)
    passive_db_errors: list = field(default_factory=list)

    def __str__(self):
        return self.url


@dataclass
class CrawlResult:
    """Kapsamlı site adres haritası ve input keşif sonucu."""
    pages: list = field(default_factory=list)              # Sitenin Adres Haritası (list of PageInfo)
    forms: list = field(default_factory=list)              # Sayfa içi Formlar ve Input Grupları (list of FormInfo)
    param_urls: list = field(default_factory=list)         # URL Parametresi Alan Adresler (list of ParamURL)
    disallowed_paths: list = field(default_factory=list)   # robots.txt bulguları

    @property
    def input_accepting_pages(self):
        """Adres haritasından sadece içine input alabilen sayfaları filtreler."""
        return [p for p in self.pages if p.has_inputs]


class Crawler:
    """Gelişmiş Site Adres Haritası ve Girdi Noktası Keşif Motoru."""

    DEFAULT_USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    )

    def __init__(self, base_url, session=None, max_pages=100, max_depth=5, delay=0.15, timeout=6):
        raw_base = base_url.strip()
        parsed_initial = urlparse(raw_base)
        self.host = parsed_initial.netloc
        self.scheme = parsed_initial.scheme or "http"
        # Eğer alt dizin verilmişse (örn: /panel) başlangıç yolunu kaydet
        self.start_path_prefix = parsed_initial.path.rstrip("/") or ""
        self.base_url = raw_base.rstrip("/") if parsed_initial.path in ("", "/") else raw_base
        self.root_origin = f"{self.scheme}://{self.host}"

        self.session = session or requests.Session()
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.delay = delay
        self.timeout = timeout

        if "User-Agent" not in self.session.headers:
            self.session.headers.update({"User-Agent": self.DEFAULT_USER_AGENT})

    def _canonicalize_url(self, url):
        """URL'yi tekilleştirme için standart formata getirir (fragment temizler, boş yolu '/' yapar)."""
        if not url:
            return ""
        clean = urldefrag(url.strip())[0]
        p = urlparse(clean)
        path = p.path if p.path else "/"
        # Çift eğik çizgileri (//) tek eğik çizgiye indirge
        path = re.sub(r"/{2,}", "/", path)
        return p._replace(path=path).geturl()

    def _same_host(self, url):
        """Linkin hedef alan adında veya alt alan adında kalıp kalmadığını kontrol eder."""
        target_netloc = urlparse(url).netloc.lower().split(":")[0]
        base_netloc = self.host.lower().split(":")[0]
        if not target_netloc or not base_netloc:
            return False
        if target_netloc == base_netloc:
            return True
        clean_target = target_netloc[4:] if target_netloc.startswith("www.") else target_netloc
        clean_base = base_netloc[4:] if base_netloc.startswith("www.") else base_netloc
        return clean_target == clean_base or clean_target.endswith("." + clean_base)

    def _should_skip(self, url):
        """Oturum kapatıcı bağlantıları ve statik medya/belge dosyalarını eler."""
        lower_url = url.lower()
        if any(k in lower_url for k in SKIP_KEYWORDS):
            return True
        parsed_path = urlparse(lower_url).path
        if parsed_path.endswith(STATIC_EXTENSIONS):
            return True
        return False

    def check_robots_txt(self):
        """robots.txt dosyasını kontrol eder ve yasaklı/gizli dizinleri listeler."""
        disallowed = []
        robots_url = f"{self.root_origin}/robots.txt"
        try:
            resp = self.session.get(robots_url, timeout=self.timeout)
            if resp.status_code == 200 and "text/plain" in (resp.headers.get("Content-Type") or "text/plain").lower():
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith(("disallow:", "allow:")):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            disallowed.append(path)
        except requests.RequestException:
            pass
        return disallowed

    def check_sitemap_xml(self):
        """sitemap.xml varsa içindeki <loc> adreslerini adres haritası kuyruğu için çeker."""
        sitemap_urls = []
        sitemap_endpoint = f"{self.root_origin}/sitemap.xml"
        try:
            resp = self.session.get(sitemap_endpoint, timeout=self.timeout)
            if resp.status_code == 200 and "<loc>" in resp.text:
                for m in re.finditer(r"<loc>\s*([^<\s]+)\s*</loc>", resp.text, re.IGNORECASE):
                    cand = self._normalize_candidate_url(self.root_origin + "/", m.group(1))
                    if cand:
                        sitemap_urls.append(cand)
        except requests.RequestException:
            pass
        return sitemap_urls

    def _is_allowed_external_app(self, url):
        """Hedef sitedeki bir linkin harici bir uygulama/login ekranı olup olmadığını (sosyal medya/CDN hariç) kontrol eder."""
        netloc = urlparse(url).netloc.lower().split(":")[0]
        if not netloc:
            return False
        for ignored in IGNORED_EXTERNAL_DOMAINS:
            if netloc == ignored or netloc.endswith("." + ignored) or ignored in netloc:
                return False
        return True

    def _normalize_candidate_url(self, base_for_join, raw_ref, allow_external=False):
        """Aday bağlantıyı (Windows ters eğik çizgileri '\\' dahil) tam URL'ye dönüştürür."""
        if not raw_ref:
            return None
        href = str(raw_ref).strip().strip("'\"")
        if not href or href.lower().startswith(("javascript:", "mailto:", "tel:", "data:", "vbscript:", "#")):
            return None
        # Windows / eski FrontPage tarzı ters eğik çizgileri (\40yayinlar.html -> /40yayinlar.html) düzelt
        href = href.replace("\\", "/")
        joined = urljoin(base_for_join, href)
        url = self._canonicalize_url(joined)
        if not url.startswith(("http://", "https://")) or self._should_skip(url):
            return None
        if self._same_host(url):
            return url
        if allow_external and self._is_allowed_external_app(url):
            return url
        return None

    def _get_effective_base_url(self, soup, page_url):
        """Sayfada <base href="..."> varsa onu, yoksa sayfa URL'ini baz alır."""
        base_tag = soup.find("base", href=True) if soup else None
        if base_tag:
            base_href = str(base_tag.get("href") or "").strip().replace("\\", "/")
            if base_href:
                return urljoin(page_url, base_href)
        # Eğer page_url bir dizin gibi görünüyorsa (son segmentte nokta yoksa ve '/' ile bitmiyorsa)
        parsed = urlparse(page_url)
        last_seg = parsed.path.rsplit("/", 1)[-1]
        if parsed.path and not parsed.path.endswith("/") and "." not in last_seg:
            return page_url + "/"
        return page_url

    def _extract_links(self, soup, page_url, raw_html="", allow_external=False):
        """Sayfadaki tüm geçerli iç bağlantıları (a, area, iframe, frame, form, meta, onclick, JS) ayıklar."""
        links = set()
        base_for_join = self._get_effective_base_url(soup, page_url)

        # 1. <a href="..."> ve <area href="...">
        for tag in soup.find_all(["a", "area"], href=True):
            url = self._normalize_candidate_url(base_for_join, tag.get("href"), allow_external=allow_external)
            if url:
                links.add(url)

        # 2. <iframe src="...">, <frame src="...">, <embed src="...">
        for tag in soup.find_all(["iframe", "frame", "embed"], src=True):
            url = self._normalize_candidate_url(base_for_join, tag.get("src"), allow_external=allow_external)
            if url:
                links.add(url)

        # 3. <form action="...">
        for form_tag in soup.find_all("form", action=True):
            url = self._normalize_candidate_url(base_for_join, form_tag.get("action"))
            if url:
                links.add(url)

        # 4. <meta http-equiv="refresh" content="0; url=...">
        for meta in soup.find_all("meta"):
            if (meta.get("http-equiv") or "").lower() == "refresh":
                content = meta.get("content") or ""
                m = re.search(r"url\s*=\s*['\"]?([^'\";>\s]+)", content, re.IGNORECASE)
                if m:
                    url = self._normalize_candidate_url(base_for_join, m.group(1), allow_external=allow_external)
                    if url:
                        links.add(url)

        # 5. data-href, data-url ve onclick="location.href='...'"
        for tag in soup.find_all(True):
            for attr_name in ("data-href", "data-url", "data-link", "data-target"):
                val = tag.get(attr_name)
                if val and not str(val).startswith("#"):
                    url = self._normalize_candidate_url(base_for_join, str(val), allow_external=allow_external)
                    if url:
                        links.add(url)
            onclick = tag.get("onclick") or ""
            if onclick:
                for m in re.finditer(
                    r"(?:location(?:\.href)?|window\.open|location\.replace|location\.assign)\s*(?:=|\()\s*['\"]([^'\"]+)['\"]",
                    onclick,
                    re.IGNORECASE
                ):
                    url = self._normalize_candidate_url(base_for_join, m.group(1), allow_external=allow_external)
                    if url:
                        links.add(url)

        # 6. Sayfa içi <script> yönlendirmeleri ve ham HTML href/src yedek taraması
        if raw_html:
            for m in re.finditer(
                r"(?:window\.location(?:\.href)?|location\.href|location\.replace|fetch|axios\.(?:get|post))\s*(?:=|\()\s*['\"]([^'\"]+)['\"]",
                raw_html,
                re.IGNORECASE
            ):
                url = self._normalize_candidate_url(base_for_join, m.group(1), allow_external=allow_external)
                if url:
                    links.add(url)

            # Bozuk HTML etiketlerinde bile href=... veya src=... bağlantılarını kaçırmamak için ham regex taraması
            for m in re.finditer(
                r"\b(?:href|src)\s*=\s*['\"]([^'\"]+)['\"]",
                raw_html,
                re.IGNORECASE
            ):
                ref_cand = m.group(1)
                if not ref_cand.lower().endswith((".js", ".css")):
                    url = self._normalize_candidate_url(base_for_join, ref_cand, allow_external=allow_external)
                    if url:
                        links.add(url)

            for m in re.finditer(
                r"['\"]((?:/|[a-zA-Z0-9_-]+/)[a-zA-Z0-9_./-]*(?:login|signin|giris|auth|admin|account|search|iletisim|contact)[a-zA-Z0-9_./-]*)['\"]",
                raw_html,
                re.IGNORECASE
            ):
                candidate_path = m.group(1)
                if not candidate_path.lower().endswith(STATIC_EXTENSIONS) and not candidate_path.lower().endswith(".js"):
                    url = self._normalize_candidate_url(base_for_join, candidate_path)
                    if url:
                        links.add(url)

        return links

    def _infer_element_name(self, el, soup=None, fallback_index=1):
        """name veya id özniteliği olmayan inputlar için placeholder, autocomplete veya <label> metninden ad üretir."""
        for attr in ("name", "id", "formcontrolname", "v-model", "ng-model", "data-name"):
            val = (el.get(attr) or "").strip()
            if val:
                return val

        placeholder = (el.get("placeholder") or el.get("aria-label") or el.get("title") or "").strip()
        autocomplete = (el.get("autocomplete") or el.get("autoComplete") or "").strip()
        if autocomplete.lower() in ("off", "on", "false", "true", "new-password", "current-password"):
            if "password" in autocomplete.lower() and not placeholder:
                autocomplete = "password"
            else:
                autocomplete = ""

        # Üst veya komşu <label> etiketini kontrol et
        label_text = ""
        parent_label = el.find_parent("label")
        if parent_label:
            label_text = parent_label.get_text(" ", strip=True)
        elif el.parent:
            prev_label = el.find_previous_sibling("label")
            if prev_label:
                label_text = prev_label.get_text(" ", strip=True)

        if placeholder and autocomplete:
            return f"{placeholder} ({autocomplete})"
        if placeholder:
            return placeholder
        if label_text and len(label_text) <= 40:
            return label_text
        if autocomplete:
            return autocomplete

        itype = (el.get("type") or el.name or "text").lower()
        if itype == "password":
            return "password"
        if itype == "email":
            return "email"
        return f"input_{itype}_{fallback_index}"

    def _parse_input_element(self, el, soup=None, fallback_index=1):
        """Tek bir HTML girdi elemanını (<input>, <textarea>, <select>, <button>) InputField'a çevirir."""
        tag_name = el.name.lower()

        if tag_name == "button":
            btype = (el.get("type") or "submit").lower()
            name = (el.get("name") or el.get("id") or "").strip()
            if not name:
                return None
            val = el.get("value", "")
            is_inj = btype not in NON_INJECTABLE_BUTTON_TYPES
            return InputField(name=name, type=btype, value=val, is_injectable=is_inj)

        name = self._infer_element_name(el, soup=soup, fallback_index=fallback_index)
        placeholder = (el.get("placeholder") or el.get("aria-label") or "").strip()

        if tag_name == "textarea":
            val = el.text or el.get("value", "")
            return InputField(name=name, type="textarea", value=val, is_injectable=True, placeholder=placeholder)

        if tag_name == "select":
            opt = el.find("option", selected=True) or el.find("option")
            val = (opt.get("value") if opt and opt.has_attr("value") else (opt.text.strip() if opt else "")) or ""
            return InputField(name=name, type="select", value=val, is_injectable=True, placeholder=placeholder)

        itype = (el.get("type") or "").strip().lower()
        if not itype:
            ac_lower = (el.get("autocomplete") or "").lower()
            ph_lower = placeholder.lower()
            if "password" in ac_lower or any(k in ph_lower for k in ("şifre", "sifre", "parola", "password")):
                itype = "password"
            else:
                itype = "text"

        val = el.get("value", "")
        is_inj = (itype in INJECTABLE_INPUT_TYPES) and (itype not in NON_INJECTABLE_BUTTON_TYPES)
        return InputField(name=name, type=itype, value=val, is_injectable=is_inj, placeholder=placeholder)

    def _classify_form_as_login(self, action_url, page_url, inputs, form_el=None):
        """Bir formun veya input grubunun Login (Giriş) ekranı olup olmadığını tespit eder."""
        has_password_input = any(
            i.type == "password" or any(h in i.name.lower() for h in LOGIN_PASS_FIELD_HINTS)
            for i in inputs
        )
        has_user_input = any(
            i.type in ("text", "email", "tel", "number") and any(
                h in (i.name + " " + getattr(i, "placeholder", "")).lower() for h in LOGIN_USER_FIELD_HINTS
            )
            for i in inputs
        )
        url_has_login = any(k in (action_url + " " + page_url).lower() for k in LOGIN_KEYWORDS)

        form_text_has_login = False
        if form_el is not None:
            form_attrs_and_text = (
                " ".join(str(v) for v in form_el.attrs.values()) + " " + form_el.get_text(" ", strip=True)
            ).lower()
            form_text_has_login = any(k in form_attrs_and_text for k in LOGIN_KEYWORDS)

        if has_password_input:
            return True, "Login Formu (Parola Alanlı)"
        if has_user_input and (url_has_login or form_text_has_login or len(inputs) <= 4):
            return True, "Login / Kimlik Doğrulama Formu"
        if url_has_login and any(i.is_injectable for i in inputs):
            return True, "Login Sayfası Formu"
        return False, "Girdi Formu"

    def _extract_http_auth_form(self, resp, page_url):
        """Sadece HTTP 401 Unauthorized dönen adresler için HTTP Auth giriş bilgisini üretir."""
        if resp.status_code != 401:
            return None
        www_auth = resp.headers.get("WWW-Authenticate") or resp.headers.get("www-authenticate") or ""
        auth_scheme = www_auth.split()[0] if www_auth else "Basic"
        return FormInfo(
            page_url=page_url,
            action=page_url,
            method="http-auth",
            inputs=[
                InputField(name="username", type="text", value="", is_injectable=True, placeholder="HTTP Auth Kullanıcı Adı"),
                InputField(name="password", type="password", value="", is_injectable=True, placeholder="HTTP Auth Şifresi"),
            ],
            is_login_form=True,
            form_type=f"HTTP 401 {auth_scheme} Giriş Kapısı"
        )

    def _find_headless_browser(self):
        """Sistemde kurulu Chrome veya Microsoft Edge yürütülebilir dosyasını bulur."""
        if hasattr(self, "_cached_browser_path"):
            return self._cached_browser_path
        candidates = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        ]
        for path in candidates:
            if os.path.exists(path):
                self._cached_browser_path = path
                return path
        self._cached_browser_path = None
        return None

    def _render_dom_with_headless_browser(self, url, orig_html="", fetched_js_cache=None):
        """React/Vue/SPA sayfalarını izole profil ile Headless Chrome/Edge'de çalıştırıp canlı DOM'u döndürür."""
        browser_bin = self._find_headless_browser()
        if not browser_bin:
            return None
        target_render_url = url
        creds = getattr(self.session, "_zt_credentials", None)
        if creds and creds[0] and self._same_host(url):
            parsed_u = urlparse(url)
            if "@" not in parsed_u.netloc:
                enc_user = quote(str(creds[0]), safe="")
                enc_pass = quote(str(creds[1]), safe="")
                authed_netloc = f"{enc_user}:{enc_pass}@{parsed_u.netloc}"
                target_render_url = parsed_u._replace(netloc=authed_netloc).geturl()

        def _is_valid_rendered_dom(dom_str):
            if not dom_str or "<" not in dom_str:
                return False
            low = dom_str.lower()
            if "could not verify that you are authorized" in low or "<title>401 unauthorized" in low:
                return False
            return True

        try:
            with tempfile.TemporaryDirectory(prefix="zt_headless_") as tmp_profile:
                base_flags = [
                    browser_bin,
                    f"--user-data-dir={tmp_profile}",
                    "--headless=new",
                    "--disable-gpu",
                    "--no-sandbox",
                    "--ignore-certificate-errors",
                    "--allow-running-insecure-content",
                    "--disable-dev-shm-usage",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--virtual-time-budget=4500",
                    "--dump-dom",
                ]
                proc = subprocess.run(
                    base_flags + [target_render_url],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="ignore",
                    timeout=12
                )
                direct_dom = proc.stdout if proc.returncode == 0 else ""
                if _is_valid_rendered_dom(direct_dom) and ("<input" in direct_dom.lower() or "<form" in direct_dom.lower()):
                    return direct_dom

                # Eğer sayfa HTTP 401 veya Cookie arkasındaysa ve self.session JS paketlerini indirdiyse,
                # indirilen JS paketlerini yerel HTML içine gömerek Headless Chrome'da çalıştır
                if orig_html and fetched_js_cache:
                    soup_inline = BeautifulSoup(orig_html, "html.parser")
                    base_for_join = self._get_effective_base_url(soup_inline, url)
                    inlined_any = False
                    for s_tag in soup_inline.find_all("script", src=True):
                        s_url = self._normalize_candidate_url(base_for_join, s_tag.get("src"))
                        if s_url and s_url in fetched_js_cache and fetched_js_cache[s_url]:
                            del s_tag["src"]
                            s_tag.string = fetched_js_cache[s_url]
                            inlined_any = True
                    if inlined_any:
                        local_html_path = os.path.join(tmp_profile, "offline_spa.html")
                        with open(local_html_path, "w", encoding="utf-8", errors="ignore") as f_out:
                            f_out.write(str(soup_inline))
                        proc_local = subprocess.run(
                            base_flags + [local_html_path],
                            capture_output=True,
                            text=True,
                            encoding="utf-8",
                            errors="ignore",
                            timeout=12
                        )
                        if proc_local.returncode == 0 and _is_valid_rendered_dom(proc_local.stdout):
                            return proc_local.stdout

                if _is_valid_rendered_dom(direct_dom):
                    return direct_dom
        except Exception:
            pass
        return None

    def _unescape_js_unicode(self, js_text):
        """JS paketlerindeki \\u00d6\\u011frenci gibi Unicode kaçış dizilerini gerçek Türkçe karakterlere çevirir."""
        return re.sub(
            r"\\u([0-9a-fA-F]{4})",
            lambda m: chr(int(m.group(1), 16)),
            js_text
        )

    def _extract_balanced_jsx_props(self, js_text):
        """JS/React kodundaki ('input', { ... }) çağrılarının içindeki { ... } bloğunu parantez derinliğiyle çıkarır."""
        results = []
        tag_pattern = re.compile(r"['\"](input|textarea|select)['\"]\s*,\s*\{", re.IGNORECASE)
        for m in tag_pattern.finditer(js_text):
            tag_type = m.group(1).lower()
            start_idx = m.end() - 1
            depth = 0
            in_str = None
            escape = False
            end_idx = min(len(js_text), start_idx + 3500)
            for pos in range(start_idx, end_idx):
                ch = js_text[pos]
                if escape:
                    escape = False
                    continue
                if ch == "\\":
                    escape = True
                    continue
                if in_str:
                    if ch == in_str:
                        in_str = None
                    continue
                if ch in ("'", '"', "`"):
                    in_str = ch
                    continue
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        results.append((tag_type, js_text[start_idx + 1:pos]))
                        break
        return results

    def _extract_js_and_spa_inputs(self, soup, page_url, raw_html, fetched_js_cache=None):
        """React / Vite / Vue / Angular JS paketlerindeki JSX inputlarını, formları ve SPA rotalarını çıkarır."""
        js_forms = []
        extra_links = set()
        if fetched_js_cache is None:
            fetched_js_cache = {}

        base_for_join = self._get_effective_base_url(soup, page_url)
        scripts_content = [raw_html]

        script_urls = []
        for s_tag in soup.find_all("script", src=True):
            s_url = self._normalize_candidate_url(base_for_join, s_tag.get("src"))
            if s_url and s_url not in script_urls:
                lower_s = s_url.lower()
                if not any(lib in lower_s for lib in ("jquery", "bootstrap", "popper", "analytics", "gtag")):
                    script_urls.append(s_url)

        for l_tag in soup.find_all("link", href=True):
            href_val = l_tag.get("href") or ""
            if href_val.lower().endswith(".js"):
                s_url = self._normalize_candidate_url(base_for_join, href_val)
                if s_url and s_url not in script_urls:
                    script_urls.append(s_url)

        def _fetch_js_url(target_js_url):
            if target_js_url in fetched_js_cache:
                return fetched_js_cache[target_js_url]
            try:
                s_resp = self.session.get(target_js_url, timeout=self.timeout)
                if s_resp.status_code == 200 and len(s_resp.text) < 15_000_000:
                    decoded_js = self._unescape_js_unicode(s_resp.text)
                    fetched_js_cache[target_js_url] = decoded_js
                    return decoded_js
            except requests.RequestException:
                pass
            return ""

        for s_url in list(script_urls[:8]):
            js_body = _fetch_js_url(s_url)
            if js_body:
                scripts_content.append(js_body)
                for chunk_m in re.finditer(r"['\"]((?:\./|/|assets/|static/js/)[a-zA-Z0-9_./-]+\.js)['\"]", js_body):
                    chunk_ref = chunk_m.group(1)
                    chunk_url = self._normalize_candidate_url(s_url, chunk_ref)
                    if chunk_url and chunk_url not in script_urls and len(script_urls) < 16:
                        script_urls.append(chunk_url)
                        chunk_body = _fetch_js_url(chunk_url)
                        if chunk_body:
                            scripts_content.append(chunk_body)

        combined_js = self._unescape_js_unicode("\n".join(scripts_content))

        # 1. JS paketleri içindeki SPA rotalarını keşfet
        for m in re.finditer(
            r"(?:path|to|href|url|route)\s*:\s*['\"](/[a-zA-Z0-9_./-]+)['\"]",
            combined_js
        ):
            r_path = m.group(1)
            if not r_path.startswith("//") and not r_path.lower().endswith(STATIC_EXTENSIONS) and not r_path.lower().endswith(".js"):
                cand = self._normalize_candidate_url(base_for_join, r_path)
                if cand:
                    extra_links.add(cand)

        # 2. React / JSX ("input", { ... }) yapılarını yakala
        jsx_inputs = []
        seen_jsx_names = set()
        jsx_blocks = self._extract_balanced_jsx_props(combined_js)

        for custom_m in re.finditer(r"\{([^{}]{1,800}\bplaceholder\s*:\s*['\"][^'\"]+['\"][^{}]{0,800})\}", combined_js):
            jsx_blocks.append(("input", custom_m.group(1)))

        for idx, (tag_type, props_str) in enumerate(jsx_blocks, start=1):
            def _get_prop(prop_regex):
                pm = re.search(prop_regex, props_str, re.IGNORECASE)
                return pm.group(1).strip() if pm else ""

            name_val = _get_prop(r"\bname\s*:\s*['\"]([^'\"]+)['\"]")
            id_val = _get_prop(r"\bid\s*:\s*['\"]([^'\"]+)['\"]")
            ph_val = _get_prop(r"\bplaceholder\s*:\s*['\"]([^'\"]+)['\"]")
            ac_val = _get_prop(r"\bauto[Cc]omplete\s*:\s*['\"]([^'\"]+)['\"]")
            type_val = _get_prop(r"\btype\s*:\s*['\"]([^'\"]+)['\"]").lower()

            if not name_val and not id_val and not ph_val and not ac_val and not type_val:
                continue

            if name_val or id_val:
                field_name = name_val or id_val
            elif ph_val and ac_val:
                field_name = f"{ph_val} ({ac_val})"
            elif ph_val:
                field_name = ph_val
            elif ac_val:
                field_name = ac_val
            else:
                field_name = f"js_{tag_type}_{idx}"

            if not type_val:
                if tag_type in ("textarea", "select"):
                    type_val = tag_type
                elif "password" in ac_val.lower() or any(k in ph_val.lower() for k in ("şifre", "sifre", "parola", "password")):
                    type_val = "password"
                else:
                    type_val = "text"

            if field_name not in seen_jsx_names:
                seen_jsx_names.add(field_name)
                is_inj = type_val not in NON_INJECTABLE_BUTTON_TYPES
                jsx_inputs.append(
                    InputField(name=field_name, type=type_val, value="", is_injectable=is_inj, placeholder=ph_val)
                )

        action_url = page_url
        ep_match = re.search(
            r"['\"]((?:/|[a-zA-Z0-9_-]+/)[a-zA-Z0-9_./-]*(?:login|signin|giris|auth|api|token|session)[a-zA-Z0-9_./-]*)['\"]",
            combined_js,
            re.IGNORECASE
        )
        if ep_match:
            cand = self._normalize_candidate_url(base_for_join, ep_match.group(1))
            if cand:
                action_url = cand

        if jsx_inputs:
            is_login, _ = self._classify_form_as_login(action_url, page_url, jsx_inputs)
            form_label = "React / SPA Dinamik Login Formu" if is_login else "React / SPA Dinamik Girdi Formu"
            js_forms.append(
                FormInfo(
                    page_url=page_url,
                    action=action_url,
                    method="post",
                    inputs=jsx_inputs,
                    is_login_form=is_login,
                    form_type=form_label
                )
            )
            return js_forms, extra_links

        lower_js = combined_js.lower()
        has_js_password = bool(
            re.search(r"type\s*[:=]\s*['\"]password['\"]", lower_js)
            or re.search(r"['\"](?:password|parola|sifre|şifre|user_password)['\"]\s*:", lower_js)
        )
        has_js_login_keyword = any(
            k in lower_js for k in ("login", "signin", "giris", "giriş", "authenticate", "oturum", "öğrenci no", "ogrenci no")
        )

        if has_js_password and has_js_login_keyword:
            user_field_name = "username"
            for candidate_name in ("username", "email", "user", "kullanici_adi", "kullanici", "tc", "ogrenci_no"):
                if re.search(rf"['\"]{candidate_name}['\"]", lower_js):
                    user_field_name = candidate_name
                    break

            js_forms.append(
                FormInfo(
                    page_url=page_url,
                    action=action_url,
                    method="post",
                    inputs=[
                        InputField(name=user_field_name, type="text", value="", is_injectable=True),
                        InputField(name="password", type="password", value="", is_injectable=True),
                    ],
                    is_login_form=True,
                    form_type="JS / SPA Dinamik Login Formu"
                )
            )

        return js_forms, extra_links

    def _extract_forms(self, soup, page_url):
        """Sayfadaki HTML formlarını, Login ekranlarını ve form dışı bağımsız girdi alanlarını çıkarır."""
        forms = []
        processed_elements = set()
        base_for_join = self._get_effective_base_url(soup, page_url)

        for f in soup.find_all("form"):
            raw_action = (f.get("action") or "").strip().replace("\\", "/")
            action = self._canonicalize_url(urljoin(base_for_join, raw_action)) if raw_action else page_url
            method = (f.get("method") or "get").lower()
            inputs = []

            form_elements = list(f.find_all(["input", "textarea", "select", "button"]))

            form_id = f.get("id")
            if form_id:
                external_els = soup.find_all(
                    ["input", "textarea", "select", "button"],
                    attrs={"form": form_id}
                )
                for ext_el in external_els:
                    if ext_el not in form_elements:
                        form_elements.append(ext_el)

            for idx, el in enumerate(form_elements, start=1):
                processed_elements.add(id(el))
                parsed_field = self._parse_input_element(el, soup=soup, fallback_index=idx)
                if parsed_field:
                    inputs.append(parsed_field)

            if not inputs:
                continue

            is_login, f_type = self._classify_form_as_login(action, page_url, inputs, form_el=f)
            forms.append(
                FormInfo(
                    page_url=page_url,
                    action=action,
                    method=method,
                    inputs=inputs,
                    is_login_form=is_login,
                    form_type=f_type
                )
            )

        # <form> etiketi dışında kalan bağımsız girdi elemanlarını (<input>, <textarea>, <select>) yakala
        orphan_inputs = []
        for idx, el in enumerate(soup.find_all(["input", "textarea", "select"]), start=1):
            if id(el) in processed_elements:
                continue
            parsed_field = self._parse_input_element(el, soup=soup, fallback_index=idx)
            if parsed_field:
                orphan_inputs.append(parsed_field)

        if orphan_inputs:
            is_login, f_type = self._classify_form_as_login(page_url, page_url, orphan_inputs, form_el=None)
            inferred_method = "post" if is_login else "get"
            f_type = "Sayfa İçi Login Alanı (Formsuz)" if is_login else "Sayfa İçi Bağımsız Input Alanı"
            forms.append(
                FormInfo(
                    page_url=page_url,
                    action=page_url,
                    method=inferred_method,
                    inputs=orphan_inputs,
                    is_login_form=is_login,
                    form_type=f_type
                )
            )

        return forms

    def _parse_param_url(self, url):
        """URL'deki GET sorgu parametrelerini (?id=1&name=test) ayıklar."""
        parsed = urlparse(url)
        if not parsed.query:
            return None
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if not params:
            return None
        return ParamURL(url=base, full_url=url, params=params)

    def _detect_passive_db_errors(self, html_text):
        """Sayfa içeriğinde veritabanı hata izlerini pasif olarak tespit eder."""
        return detect_db_errors_in_text(html_text)

    def _register_param_url(self, url, seen_param_signatures, result):
        """URL sorgu parametresi içeriyorsa tekilleştirerek result.param_urls listesine ekler."""
        param_obj = self._parse_param_url(url)
        if param_obj and param_obj.params:
            sig = (param_obj.url, tuple(sorted(param_obj.params.keys())))
            if sig not in seen_param_signatures:
                seen_param_signatures.add(sig)
                result.param_urls.append(param_obj)
        return param_obj

    def _is_likely_spa_shell(self, soup, raw_html):
        """Sayfanın React/Vue/Angular/Next gibi bir SPA kabuğu olup olmadığını kontrol eder."""
        if soup.find(id=re.compile(r"^(root|app|__next|__nuxt|main-app)$", re.I)):
            return True
        if soup.find("script", attrs={"type": "module"}):
            return True
        if "enable javascript" in raw_html.lower():
            return True
        return False

    def crawl(self, start_url=None):
        """Sitenin tam adres haritasını çıkarır ve her adresteki input noktalarını tespit eder."""
        start = self._canonicalize_url(start_url or self.base_url)
        queue = deque([(start, 0)])
        visited = set()
        seen_param_signatures = set()
        seen_form_signatures = set()
        param_pattern_visit_counts = {}
        fetched_js_cache = {}
        result = CrawlResult()

        # 1. robots.txt ve sitemap.xml adreslerini harita kuyruğuna ekle
        result.disallowed_paths = self.check_robots_txt()
        for r_path in result.disallowed_paths:
            if "*" not in r_path and "$" not in r_path:
                candidate = self._normalize_candidate_url(self.root_origin + "/", r_path.lstrip("/"))
                if candidate and candidate not in visited:
                    queue.append((candidate, 1))

        for sm_url in self.check_sitemap_xml():
            if sm_url not in visited:
                queue.append((sm_url, 1))

        valid_page_count = 0
        total_attempts = 0
        max_attempts = max(self.max_pages * 3, 60)
        headless_render_count = 0
        max_headless_renders = 6

        while queue and valid_page_count < self.max_pages and total_attempts < max_attempts:
            url, depth = queue.popleft()
            url = self._canonicalize_url(url)

            if not url or url in visited or self._should_skip(url):
                continue

            param_obj = self._register_param_url(url, seen_param_signatures, result)
            if param_obj and param_obj.params:
                pattern_key = (param_obj.url, tuple(sorted(param_obj.params.keys())))
                count = param_pattern_visit_counts.get(pattern_key, 0)
                if count >= 3:
                    continue
                param_pattern_visit_counts[pattern_key] = count + 1

            visited.add(url)
            total_attempts += 1

            try:
                resp = self.session.get(url, timeout=self.timeout)
            except requests.RequestException as exc:
                print(f"[!] Bağlantı Hatası: {url} ({exc})")
                continue

            if resp.encoding and resp.encoding.lower() == "iso-8859-1" and resp.apparent_encoding:
                resp.encoding = resp.apparent_encoding

            effective_url = self._canonicalize_url(resp.url) if getattr(resp, "url", None) else url
            visited.add(effective_url)

            # 404 / 410 (Bulunamadı) yanıtlarını adres haritasına ve form analizine dahil etme
            if resp.status_code in (404, 410):
                continue

            ctype = (resp.headers.get("Content-Type") or "").lower()
            if not any(t in ctype for t in ("text/html", "application/xhtml+xml")) and resp.status_code != 401:
                continue

            valid_page_count += 1

            html_to_parse = resp.text
            soup = BeautifulSoup(html_to_parse, "html.parser")
            page_title = ""
            if soup.title and soup.title.string:
                page_title = soup.title.string.strip()

            page_forms = []

            # A) HTTP 401 Kimlik Doğrulama Kapısı kontrolü
            http_auth_form = self._extract_http_auth_form(resp, effective_url)
            if http_auth_form:
                page_forms.append(http_auth_form)

            # B) Standart HTML Formları, JS/SPA Paketleri ve Canlı DOM (Headless) Analizi
            dom_extra_links = set()
            if resp.status_code != 401:
                html_forms = self._extract_forms(soup, effective_url)
                page_forms.extend(html_forms)

                # Önce orijinal (kimlik doğrulaması yapılmış) HTML üzerinden JS paketlerini indir ve analiz et
                js_forms, js_extra_links = self._extract_js_and_spa_inputs(
                    soup,
                    effective_url,
                    html_to_parse,
                    fetched_js_cache=fetched_js_cache
                )

                # Sayfa bir React/Vue/SPA uygulamasıysa veya hiç input bulunamadıysa Headless Tarayıcı ile canlı DOM'u çöz
                # (Orijinal soup ve html_to_parse asla ezilmez; sadece canlı DOM'dan çıkan yeni formlar ve linkler eklenir)
                if headless_render_count < max_headless_renders and (
                    self._is_likely_spa_shell(soup, html_to_parse) or (not page_forms and soup.find("script"))
                ):
                    headless_render_count += 1
                    rendered_dom = self._render_dom_with_headless_browser(
                        effective_url,
                        orig_html=html_to_parse,
                        fetched_js_cache=fetched_js_cache
                    )
                    if rendered_dom:
                        dom_soup = BeautifulSoup(rendered_dom, "html.parser")
                        if not page_title and dom_soup.title and dom_soup.title.string:
                            page_title = dom_soup.title.string.strip()
                        dom_forms = self._extract_forms(dom_soup, effective_url)
                        for df in dom_forms:
                            if df not in page_forms:
                                page_forms.append(df)
                        dom_extra_links = self._extract_links(
                            dom_soup,
                            effective_url,
                            raw_html=rendered_dom,
                            allow_external=self._same_host(effective_url)
                        )

                if not page_forms or not any(f.is_login_form for f in page_forms):
                    for jf in js_forms:
                        if jf not in page_forms:
                            page_forms.append(jf)
            else:
                js_extra_links = set()

            # Bu sayfadaki formları genel sonuca kaydet ve sayfa bazlı input özetini oluştur
            page_input_details = []
            page_input_count = 0
            page_is_login = False

            for form in page_forms:
                if form.is_login_form:
                    page_is_login = True
                inj_fields = form.injectable_inputs
                page_input_count += len(inj_fields)
                if inj_fields:
                    field_strs = ", ".join(f"{i.name} ({i.type})" for i in inj_fields)
                    page_input_details.append(f"[{form.method.upper()}] {field_strs}")

                form_sig = (
                    form.action,
                    form.method,
                    tuple((i.name, i.type) for i in form.inputs)
                )
                if form_sig not in seen_form_signatures:
                    seen_form_signatures.add(form_sig)
                    result.forms.append(form)

            # Eğer bu sayfanın kendi URL'inde GET parametreleri varsa (?id=1 vb.) onu da sayfanın inputlarına ekle
            if param_obj and param_obj.params:
                page_input_count += len(param_obj.params)
                param_strs = ", ".join(f"?{k}" for k in param_obj.params.keys())
                page_input_details.append(f"[URL GET] {param_strs}")

            page_info = PageInfo(
                url=effective_url,
                status_code=resp.status_code,
                content_type=ctype or "text/html",
                depth=depth,
                title=page_title,
                has_inputs=(page_input_count > 0),
                input_count=page_input_count,
                input_details=page_input_details,
                is_login_page=page_is_login,
                headers=dict(resp.headers),
                passive_db_errors=self._detect_passive_db_errors(resp.text)
            )
            result.pages.append(page_info)

            # E) Sayfadaki tüm bağlantıları çıkar ve harita kuyruğuna ekle
            # (Hedef sitedeki bir sayfadaysak 1-adımlık harici uygulama linklerini de incelemeye izin ver)
            is_on_target_host = self._same_host(effective_url)
            if resp.status_code != 401 and is_on_target_host:
                all_page_links = (
                    self._extract_links(soup, effective_url, raw_html=html_to_parse, allow_external=True)
                    | dom_extra_links
                    | js_extra_links
                )
                for link in sorted(all_page_links):
                    # Her keşfedilen linkte GET parametresi varsa (?id=...) kaydet
                    self._register_param_url(link, seen_param_signatures, result)
                    if link not in visited and depth < self.max_depth:
                        # Eğer kullanıcı belirli bir alt dizini hedeflediyse (örn: /panel), o dizinin altındaki sayfaları kuyrukta öne al
                        if self.start_path_prefix and urlparse(link).path.startswith(self.start_path_prefix):
                            queue.appendleft((link, depth + 1))
                        else:
                            queue.append((link, depth + 1))

            time.sleep(self.delay)

        # Eğer parametreli URL'ler başka bir sayfadaki linkten keşfedildiyse ama henüz ziyaret edilmediyse,
        # ilgili hedef sayfayı da adres haritasında "input alabiliyor" olarak işaretle
        pages_by_base_url = {}
        for p in result.pages:
            base_p = p.url.split("?", 1)[0]
            pages_by_base_url[base_p] = p

        for pu in result.param_urls:
            matched_page = pages_by_base_url.get(pu.url)
            param_label = f"[URL GET] " + ", ".join(f"?{k}={v}" for k, v in pu.params.items())
            if matched_page:
                if param_label not in matched_page.input_details:
                    matched_page.input_details.append(param_label)
                    matched_page.input_count += len(pu.params)
                    matched_page.has_inputs = True
            else:
                result.pages.append(
                    PageInfo(
                        url=pu.full_url,
                        status_code=200,
                        content_type="text/html",
                        depth=1,
                        title="Parametreli Adres (URL Input)",
                        has_inputs=True,
                        input_count=len(pu.params),
                        input_details=[param_label],
                    )
                )

        return result
