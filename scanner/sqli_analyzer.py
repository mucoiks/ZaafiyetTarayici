"""Hibrit SQL Injection (CWE-89) ve Veritabanı Güvenliği Denetim Modülü.

Bu modül hedef sisteme hiçbir aktif saldırı yükü (payload) göndermeden iki katmanlı
savunma odaklı analiz gerçekleştirir:
1. Pasif Web Analizi (Saldırı Yüzeyi & Hata İfşası Denetimi):
   - Crawler tarafından keşfedilen sayfalarda açık unutulmuş veritabanı hata mesajlarını (CWE-209),
   - URL sorgu parametrelerindeki (GET) veritabanı ilişkili aday noktaları,
   - HTML formlarındaki veri giriş alanlarını ve CSRF/metod güvenliğini pasif olarak denetler.
2. Statik Kaynak Kod Analizi - SAST (Beyaz Kutu Denetimi):
   - Hedef uygulamanın kaynak kodlarını (.php, .py) satır satır tarayarak,
   - Kullanıcı girdilerinin doğrudan SQL sorgularına metin birleştirme (string concatenation /
     interpolation) ile eklendiği güvensiz kod satırlarını (CWE-89) tespit eder,
   - Parametreli sorgu (Prepared Statement / PDO) kullanan güvenli kod satırlarını doğrular.
"""
import os
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

# Veritabanı sorgularında sık kullanılan parametre isimleri
DB_RELATED_PARAM_NAMES = {
    "id", "user_id", "userid", "uid", "item", "item_id", "product", "product_id",
    "cat", "cat_id", "category", "page", "p", "sort", "order", "orderby",
    "search", "q", "query", "filter", "view", "article", "post", "no", "num"
}

# Formlarda CSRF koruması için kullanılan yaygın gizli alan isimleri
CSRF_TOKEN_NAMES = {
    "user_token", "csrf_token", "csrf", "_token", "_csrf",
    "authenticity_token", "csrfmiddlewaretoken", "__requestverificationtoken"
}


@dataclass
class SQLiFinding:
    """Tespit edilen güvenlik bulgusu veya mimari risk kaydı."""
    category: str       # "SAST (Kaynak Kod Analizi)" veya "Pasif Web Denetimi"
    cwe: str            # Örn: "CWE-89 (SQL Injection)" veya "CWE-209 (Bilgi İfşası)"
    severity: str       # "YÜKSEK", "ORTA", "DÜŞÜK", "BİLGİ"
    location: str       # URL veya dosya_yolu:satir_no
    parameter: str      # İlgili parametre veya değişken adı
    evidence: str       # Kod satırı veya pasif gözlem kanıtı
    remediation: str    # Geliştirici için güvenli kodlama / çözüm önerisi


@dataclass
class SafeSQLUsage:
    """Kaynak kodda tespit edilen güvenli (Prepared Statement) SQL kullanımı."""
    location: str       # dosya_yolu:satir_no
    mechanism: str      # Örn: "PDO Prepared Statement (prepare / bindParam)"
    evidence: str       # İlgili güvenli kod satırı


@dataclass
class SQLiAuditResult:
    """Hibrit SQL Injection denetim sonucu."""
    passive_findings: list = field(default_factory=list)   # list of SQLiFinding
    sast_findings: list = field(default_factory=list)      # list of SQLiFinding
    safe_usages: list = field(default_factory=list)        # list of SafeSQLUsage
    scanned_files: int = 0

    @property
    def all_findings(self):
        return self.sast_findings + self.passive_findings


class HybridSQLiAnalyzer:
    """Pasif Web Saldırı Yüzeyi Analizi ve Statik Kaynak Kod (SAST) Denetçisi."""

    # SAST: PHP ve Python'da güvensiz SQL sorgu birleştirme desenleri
    PHP_UNSAFE_SQL_REGEX = re.compile(
        r"(SELECT\s+.+?\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)"
        r"[^;]*?(\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*|\$_(GET|POST|REQUEST|COOKIE)\b)",
        re.IGNORECASE
    )

    PYTHON_UNSAFE_SQL_REGEX = re.compile(
        r"(execute|executemany)\s*\(\s*"
        r"(f['\"].*?(SELECT|INSERT|UPDATE|DELETE).*?\{.+?\}"
        r"|['\"].*?(SELECT|INSERT|UPDATE|DELETE).*?['\"]\s*(\+|\.format\s*\(|%\s*))",
        re.IGNORECASE
    )

    # SAST: Güvenli (Prepared Statement / Parametreli Sorgu) desenleri
    PHP_SAFE_SQL_REGEX = re.compile(
        r"(->\s*prepare\s*\(|mysqli_prepare\s*\(|->\s*bindParam\s*\(|->\s*bindValue\s*\(|mysqli_stmt_bind_param\s*\()",
        re.IGNORECASE
    )

    PYTHON_SAFE_SQL_REGEX = re.compile(
        r"\.\s*execute\s*\(\s*['\"](SELECT|INSERT|UPDATE|DELETE).*?(\?|%s).*?['\"]\s*,\s*[\(\[]",
        re.IGNORECASE
    )

    def analyze_crawl_result(self, crawl_result):
        """Crawler çıktısını pasif olarak (ek istek veya saldırı yükü göndermeden) inceler."""
        findings = []

        # 1. Pasif Veritabanı Hata İfşası Kontrolü (CWE-209)
        for page in crawl_result.pages:
            for err_sig in getattr(page, "passive_db_errors", []):
                findings.append(SQLiFinding(
                    category="Pasif Web Denetimi",
                    cwe="CWE-209 (Veritabanı Hata Mesajı İfşası)",
                    severity="YÜKSEK",
                    location=page.url,
                    parameter="HTTP Yanıt Gövdesi",
                    evidence=f"Sayfa içeriğinde ham veritabanı hata izi tespit edildi: {err_sig}",
                    remediation=(
                        "Üretim ortamında detaylı veritabanı hatalarını (display_errors) kapatın. "
                        "Hataları sunucu tarafında güvenli log dosyalarına kaydedip kullanıcıya "
                        "genel bir hata mesajı gösterin."
                    )
                ))

        # 2. Parametreli URL'lerde Veritabanı Sorgu Adayı Analizi
        for p_url in crawl_result.param_urls:
            parsed_path = urlparse(p_url.url).path.lower()
            is_sqli_module_path = "sqli" in parsed_path or "sql" in parsed_path

            for param_name, param_val in p_url.params.items():
                p_lower = param_name.lower()
                # Submit/buton parametrelerini atla
                if p_lower in ("submit", "login", "btn", "button", "action"):
                    continue

                is_db_param = (
                    p_lower in DB_RELATED_PARAM_NAMES
                    or param_val.isdigit()
                    or is_sqli_module_path
                )

                if is_db_param:
                    severity = "YÜKSEK" if (is_sqli_module_path or p_lower in ("id", "user_id", "cat", "item")) else "ORTA"
                    findings.append(SQLiFinding(
                        category="Pasif Web Denetimi",
                        cwe="CWE-89 (SQL Injection Aday Girdi Noktası)",
                        severity=severity,
                        location=p_url.url,
                        parameter=f"GET '{param_name}' (Örnek değer: '{param_val}')",
                        evidence=(
                            f"URL sorgu parametresi ('{param_name}={param_val}') doğrudan veri sorgulama "
                            f"imzası taşıyor ({p_url.full_url})."
                        ),
                        remediation=(
                            f"Arka planda '{param_name}' parametresi SQL sorgusuna metin birleştirme ile "
                            f"eklenmemelidir. PDO / Prepared Statement (Örn: WHERE {param_name} = ?) ve "
                            f"tür doğrulaması (intval / tip dönüşümü) kullanılmalıdır."
                        )
                    ))

        # 3. Form Girdi Yüzeyi ve Güvenlik Yapılandırması Analizi
        for form in crawl_result.forms:
            inj_inputs = form.injectable_inputs
            if not inj_inputs:
                continue

            input_names = [i.name for i in inj_inputs]
            has_csrf = any(i.name.lower() in CSRF_TOKEN_NAMES for i in form.inputs)
            data_inputs = [i for i in inj_inputs if i.name.lower() not in CSRF_TOKEN_NAMES]

            if not data_inputs:
                continue

            parsed_action = urlparse(form.action).path.lower()
            is_sqli_form = "sqli" in parsed_action or any(
                i.name.lower() in ("id", "user_id", "query", "search") for i in data_inputs
            )

            if is_sqli_form:
                findings.append(SQLiFinding(
                    category="Pasif Web Denetimi",
                    cwe="CWE-89 (Form Tabanlı Veritabanı Girdi Adayı)",
                    severity="ORTA",
                    location=form.action,
                    parameter=", ".join(i.name for i in data_inputs),
                    evidence=(
                        f"[{form.method.upper()}] formunda veritabanı sorgusuyla ilişkili girdi alanları "
                        f"tespit edildi (Kaynak: {form.page_url})."
                    ),
                    remediation=(
                        "Formdan gelen tüm kullanıcı girdileri sunucu katmanında Prepared Statement "
                        "(Parametreli Sorgu) ile işlenmeli ve ORM/PDO bağlamaları kullanılmalıdır."
                    )
                ))

            # Parola alanının GET metodu ile gönderilmesi kontrolü
            has_password = any(i.type == "password" for i in form.inputs)
            if has_password and form.method.lower() == "get":
                findings.append(SQLiFinding(
                    category="Pasif Web Denetimi",
                    cwe="CWE-598 (Hassas Verinin GET Sorgusu ile İletimi)",
                    severity="ORTA",
                    location=form.action,
                    parameter="password (GET)",
                    evidence=f"Parola alanı içeren form GET metodu kullanıyor ({form.page_url}).",
                    remediation="Kimlik doğrulama ve hassas veri formlarında her zaman POST metodu ve HTTPS kullanılmalıdır."
                ))

            # POST formlarında CSRF token eksikliği
            if form.method.lower() == "post" and not has_csrf:
                findings.append(SQLiFinding(
                    category="Pasif Web Denetimi",
                    cwe="CWE-352 (Eksik CSRF Token Koruması)",
                    severity="DÜŞÜK",
                    location=form.action,
                    parameter=", ".join(input_names),
                    evidence=f"POST formunda CSRF koruma anahtarı (hidden token) bulunamadı ({form.page_url}).",
                    remediation="Durum değiştiren tüm POST formlarına oturuma özel benzersiz CSRF token eklenmelidir."
                ))

        return findings

    def analyze_source_file(self, file_path):
        """Tek bir kaynak kod dosyasını (.php veya .py) statik olarak (SAST) inceler."""
        sast_findings = []
        safe_usages = []

        ext = os.path.splitext(file_path)[1].lower()
        if ext not in (".php", ".py"):
            return sast_findings, safe_usages

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except OSError:
            return sast_findings, safe_usages

        for idx, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            # Yorum satırlarını atla
            if not line or line.startswith(("//", "#", "/*", "*")):
                continue

            # Çok satırlı SQL ifadelerini yakalamak için ardışık 2 satırlık pencere
            window = line
            if idx < len(lines):
                next_line = lines[idx].strip()
                if not next_line.startswith(("//", "#", "/*", "*")):
                    window = f"{line} {next_line}"

            loc = f"{file_path}:{idx}"

            if ext == ".php":
                # 1. Güvensiz SQL sorgu birleştirmesi kontrolü
                match = self.PHP_UNSAFE_SQL_REGEX.search(line) or (
                    any(k in line.upper() for k in ("SELECT ", "INSERT ", "UPDATE ", "DELETE "))
                    and self.PHP_UNSAFE_SQL_REGEX.search(window)
                )
                if match:
                    var_name = match.group(2)
                    sast_findings.append(SQLiFinding(
                        category="SAST (Kaynak Kod Analizi)",
                        cwe="CWE-89 (SQL Injection - Güvensiz Sorgu Birleştirme)",
                        severity="YÜKSEK",
                        location=loc,
                        parameter=var_name,
                        evidence=line[:140],
                        remediation=(
                            f"'{var_name}' değişkenini doğrudan SQL metnine birleştirmek yerine "
                            f"PDO::prepare() ve bindParam() kullanın: "
                            f"$stmt = $db->prepare('SELECT ... WHERE col = :val'); "
                            f"$stmt->bindParam(':val', {var_name});"
                        )
                    ))

                # 2. Güvenli Prepared Statement kullanımı kontrolü
                if self.PHP_SAFE_SQL_REGEX.search(line):
                    safe_usages.append(SafeSQLUsage(
                        location=loc,
                        mechanism="PHP PDO / MySQLi Prepared Statement",
                        evidence=line[:140]
                    ))

            elif ext == ".py":
                # 1. Python güvensiz SQL sorgu birleştirmesi kontrolü
                match = self.PYTHON_UNSAFE_SQL_REGEX.search(line)
                if match:
                    sast_findings.append(SQLiFinding(
                        category="SAST (Kaynak Kod Analizi)",
                        cwe="CWE-89 (SQL Injection - Dinamik Metin Formatlama)",
                        severity="YÜKSEK",
                        location=loc,
                        parameter="Dinamik SQL Sorgu Değişkeni",
                        evidence=line[:140],
                        remediation=(
                            "f-string, .format() veya '+' ile SQL sorgusu oluşturmayın. "
                            "Parametreli sorgu kullanın: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
                        )
                    ))

                # 2. Python güvenli parametreli sorgu kontrolü
                if self.PYTHON_SAFE_SQL_REGEX.search(line):
                    safe_usages.append(SafeSQLUsage(
                        location=loc,
                        mechanism="Python DB-API Parametreli Sorgu (Parameterized Query)",
                        evidence=line[:140]
                    ))

        return sast_findings, safe_usages

    def analyze_source_path(self, target_path):
        """Bir dosya veya klasör altındaki tüm .php ve .py dosyalarını SAST ile tarar."""
        all_sast = []
        all_safe = []
        scanned_count = 0

        if not target_path or not os.path.exists(target_path):
            return all_sast, all_safe, scanned_count

        if os.path.isfile(target_path):
            sast, safe = self.analyze_source_file(target_path)
            return sast, safe, 1

        for root, dirs, files in os.walk(target_path):
            # Sanal ortam ve gizli klasörleri atla
            dirs[:] = [d for d in dirs if d not in ("venv", ".git", "__pycache__", "node_modules")]
            for fname in sorted(files):
                if fname.lower().endswith((".php", ".py")):
                    fpath = os.path.join(root, fname)
                    sast, safe = self.analyze_source_file(fpath)
                    all_sast.extend(sast)
                    all_safe.extend(safe)
                    scanned_count += 1

        return all_sast, all_safe, scanned_count

    def run_hybrid_audit(self, crawl_result=None, source_path=None):
        """Hem Pasif Web Denetimini hem de SAST Kaynak Kod Analizini çalıştırıp birleştirir."""
        report = SQLiAuditResult()
        if crawl_result is not None:
            report.passive_findings = self.analyze_crawl_result(crawl_result)
        if source_path:
            sast, safe, count = self.analyze_source_path(source_path)
            report.sast_findings = sast
            report.safe_usages = safe
            report.scanned_files = count
        return report
