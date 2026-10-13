"""Web crawler: hedef sitedeki sayfaları, linkleri ve formları keşfeder.

Faz 1 Güçlendirilmiş Keşif Motoru:
- BFS (Genişlik Öncelikli Arama) ile derinlik (max_depth) kontrollü tarama
- URL Query parametrelerini ayrıştırma (parse_qs)
- Form girdi türlerini sınıflandırma (injectable / non-injectable)
- HTTP durum kodları, başlıkları ve robots.txt keşfi
- Oturum çerezi ve hız sınırı (rate limit / politeness delay) desteği
"""
import time
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, urldefrag, parse_qsl

import requests
from bs4 import BeautifulSoup

# Oturumu sonlandırabilecek veya veriyi sıfırlayabilecek bağlantılar atlanır.
SKIP_KEYWORDS = ("logout", "signout", "setup.php", "cikis", "oturum-kapat")

# Doğrudan saldırı payload'ı kabul etmeye uygun girdi türleri
INJECTABLE_INPUT_TYPES = ("text", "password", "hidden", "search", "email", "url", "tel", "textarea")


@dataclass
class InputField:
    """Form içindeki girdi alanı detayları."""
    name: str
    type: str = "text"
    value: str = ""
    is_injectable: bool = True

    def __repr__(self):
        durum = "test_edilebilir" if self.is_injectable else "sabit"
        return f"{self.name} ({self.type}, {durum})"


@dataclass
class FormInfo:
    """Bir HTML formunun güvenlik taraması için gereken bilgileri."""
    page_url: str
    action: str
    method: str
    inputs: list = field(default_factory=list)  # list of InputField

    @property
    def injectable_inputs(self):
        """Zafiyet testi yapılabilecek alanları döndürür."""
        return [i for i in self.inputs if i.is_injectable]


@dataclass
class ParamURL:
    """Zafiyet testine hazır parametreli URL bilgisi."""
    url: str               # Parametresiz temel adres
    full_url: str          # Parametreleri içeren tam adres
    params: dict = field(default_factory=dict)  # Ayrıştırılmış parametreler

    def __str__(self):
        return self.full_url


@dataclass
class PageInfo:
    """Taranan sayfanın HTTP yanıt ve derinlik bilgileri."""
    url: str
    status_code: int
    content_type: str
    depth: int
    headers: dict = field(default_factory=dict)

    def __str__(self):
        return self.url


@dataclass
class CrawlResult:
    """Kapsamlı tarama ve keşif sonucu."""
    pages: list = field(default_factory=list)              # list of PageInfo
    forms: list = field(default_factory=list)              # list of FormInfo
    param_urls: list = field(default_factory=list)         # list of ParamURL
    disallowed_paths: list = field(default_factory=list)   # robots.txt bulguları


class Crawler:
    """Gelişmiş, modüler ve etik Web Keşif Motoru (Crawler)."""

    DEFAULT_USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "ZaafiyetTarayici/1.0 (+NKU Bilgisayar Muhendisligi Projesi)"
    )

    def __init__(self, base_url, session=None, max_pages=50, max_depth=3, delay=0.3, timeout=5):
        self.base_url = base_url.rstrip("/")
        parsed = urlparse(self.base_url)
        self.host = parsed.netloc
        self.scheme = parsed.scheme or "http"
        self.session = session or requests.Session()
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.delay = delay
        self.timeout = timeout

        # İstemci kimliğini belirle
        if "User-Agent" not in self.session.headers:
            self.session.headers.update({"User-Agent": self.DEFAULT_USER_AGENT})

    def _same_host(self, url):
        """Linkin hedef alan adında kalıp kalmadığını kontrol eder."""
        return urlparse(url).netloc == self.host

    def _should_skip(self, url):
        """Oturum kapatıcı veya riskli bağlantıları eler."""
        return any(k in url.lower() for k in SKIP_KEYWORDS)

    def check_robots_txt(self):
        """robots.txt dosyasını kontrol eder ve yasaklı/gizli dizinleri listeler."""
        disallowed = []
        robots_url = f"{self.scheme}://{self.host}/robots.txt"
        try:
            resp = self.session.get(robots_url, timeout=self.timeout)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            disallowed.append(path)
        except requests.RequestException:
            pass
        return disallowed

    def _extract_links(self, soup, page_url):
        """Sayfadaki tüm geçerli ve aynı alan adına ait bağlantıları ayıklar."""
        links = set()
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue
            url = urldefrag(urljoin(page_url, href))[0]
            if url.startswith(("http://", "https://")) and self._same_host(url):
                links.add(url)
        return links

    def _extract_forms(self, soup, page_url):
        """Sayfadaki HTML formlarını ve girdi türlerini ayrıntılı olarak çıkarır."""
        forms = []
        for f in soup.find_all("form"):
            action = urljoin(page_url, f.get("action") or page_url)
            method = (f.get("method") or "get").lower()
            inputs = []

            # <input> etiketleri
            for el in f.find_all("input"):
                name = el.get("name")
                if not name:
                    continue
                itype = (el.get("type") or "text").lower()
                val = el.get("value", "")
                is_inj = itype in INJECTABLE_INPUT_TYPES
                inputs.append(InputField(name=name, type=itype, value=val, is_injectable=is_inj))

            # <textarea> etiketleri (her zaman test edilebilir)
            for el in f.find_all("textarea"):
                name = el.get("name")
                if name:
                    val = el.text or ""
                    inputs.append(InputField(name=name, type="textarea", value=val, is_injectable=True))

            # <select> etiketleri
            for el in f.find_all("select"):
                name = el.get("name")
                if name:
                    opt = el.find("option", selected=True) or el.find("option")
                    val = opt.get("value", "") if opt else ""
                    inputs.append(InputField(name=name, type="select", value=val, is_injectable=True))

            forms.append(FormInfo(page_url=page_url, action=action, method=method, inputs=inputs))
        return forms

    def _parse_param_url(self, url):
        """URL'deki sorgu parametrelerini ayıklar."""
        parsed = urlparse(url)
        if not parsed.query:
            return None
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = dict(parse_qsl(parsed.query))
        return ParamURL(url=base, full_url=url, params=params)

    def crawl(self, start_url=None):
        """BFS algoritması ve derinlik kontrolü ile siteyi haritalandırır."""
        start = start_url or self.base_url
        # Kuyrukta (URL, derinlik) ikilisi saklanır
        queue = deque([(start, 0)])
        visited = set()
        seen_param_signatures = set()
        result = CrawlResult()

        # robots.txt dosyasını önceden incele
        result.disallowed_paths = self.check_robots_txt()

        while queue and len(visited) < self.max_pages:
            url, depth = queue.popleft()

            if url in visited or self._should_skip(url):
                continue
            visited.add(url)

            try:
                resp = self.session.get(url, timeout=self.timeout)
            except requests.RequestException as exc:
                print(f"[!] Bağlantı Hatası: {url} ({exc})")
                continue

            ctype = resp.headers.get("Content-Type", "")
            if "text/html" not in ctype:
                continue

            # Sayfa bilgilerini kaydet
            page_info = PageInfo(
                url=url,
                status_code=resp.status_code,
                content_type=ctype,
                depth=depth,
                headers=dict(resp.headers)
            )
            result.pages.append(page_info)

            # Parametreli URL'leri çözümle
            param_obj = self._parse_param_url(url)
            if param_obj:
                sig = (param_obj.url, tuple(sorted(param_obj.params.keys())))
                if sig not in seen_param_signatures:
                    seen_param_signatures.add(sig)
                    result.param_urls.append(param_obj)

            # Formları ayıkla
            soup = BeautifulSoup(resp.text, "html.parser")
            result.forms.extend(self._extract_forms(soup, url))

            # Maksimum derinliğe ulaşılmadıysa çocuk bağlantıları kuyruğa ekle
            if depth < self.max_depth:
                for link in self._extract_links(soup, url):
                    if link not in visited:
                        queue.append((link, depth + 1))

            time.sleep(self.delay)

        return result
