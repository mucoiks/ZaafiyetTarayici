"""Web crawler: hedef sitedeki sayfaları, linkleri ve formları keşfeder.

Yalnızca keşif yapar, hedefe herhangi bir saldırı verisi göndermez.
Sadece izinli sistemlerde kullanın.
"""
import time
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, urldefrag

import requests
from bs4 import BeautifulSoup

# Oturumu sonlandırabilecek veya veriyi sıfırlayabilecek bağlantılar taranmaz.
SKIP_KEYWORDS = ("logout", "signout", "setup.php")


@dataclass
class FormInfo:
    """Bir HTML formunun tarama için gereken bilgileri."""
    page_url: str
    action: str
    method: str
    inputs: list = field(default_factory=list)  # [{"name", "type", "value"}]


@dataclass
class CrawlResult:
    """Tarama sonucu: bulunan sayfalar, parametreli URL'ler ve formlar."""
    pages: list = field(default_factory=list)
    forms: list = field(default_factory=list)
    param_urls: list = field(default_factory=list)  # query string içeren URL'ler


class Crawler:
    def __init__(self, base_url, session=None, max_pages=50, delay=0.3, timeout=5):
        self.base_url = base_url.rstrip("/")
        self.host = urlparse(self.base_url).netloc
        self.session = session or requests.Session()
        self.max_pages = max_pages
        self.delay = delay
        self.timeout = timeout

    def _same_host(self, url):
        return urlparse(url).netloc == self.host

    def _should_skip(self, url):
        return any(k in url.lower() for k in SKIP_KEYWORDS)

    def _extract_links(self, soup, page_url):
        links = set()
        for a in soup.find_all("a", href=True):
            url = urldefrag(urljoin(page_url, a["href"]))[0]
            if url.startswith(("http://", "https://")) and self._same_host(url):
                links.add(url)
        return links

    def _extract_forms(self, soup, page_url):
        forms = []
        for f in soup.find_all("form"):
            action = urljoin(page_url, f.get("action") or page_url)
            method = (f.get("method") or "get").lower()
            inputs = []
            for el in f.find_all(["input", "textarea", "select"]):
                name = el.get("name")
                if name:
                    inputs.append({
                        "name": name,
                        "type": el.get("type", el.name),
                        "value": el.get("value", ""),
                    })
            forms.append(FormInfo(page_url, action, method, inputs))
        return forms

    def crawl(self, start_url=None):
        start = start_url or self.base_url
        queue = deque([start])
        visited = set()
        result = CrawlResult()

        while queue and len(visited) < self.max_pages:
            url = queue.popleft()
            if url in visited or self._should_skip(url):
                continue
            visited.add(url)

            try:
                resp = self.session.get(url, timeout=self.timeout)
            except requests.RequestException as exc:
                print(f"[!] Hata: {url} ({exc})")
                continue

            ctype = resp.headers.get("Content-Type", "")
            if "text/html" not in ctype:
                continue

            result.pages.append(url)
            if urlparse(url).query:
                result.param_urls.append(url)

            soup = BeautifulSoup(resp.text, "html.parser")
            result.forms.extend(self._extract_forms(soup, url))
            for link in self._extract_links(soup, url):
                if link not in visited:
                    queue.append(link)

            time.sleep(self.delay)

        return result
