"""Kara Kutu (Black-Box) SQL Injection (CWE-89) ve Web Güvenliği Denetim Modülü.

Bu modül hedef web uygulamasının kaynak koduna erişim gerektirmeden, tamamen dışarıdan
(Kara Kutu / Black-Box yaklaşımıyla) iki aşamalı analiz gerçekleştirir:
1. Saldırı Yüzeyi ve Pasif Web Analizi:
   - Crawler tarafından çıkarılan adres haritasında açık unutulmuş veritabanı hata mesajlarını (CWE-209),
   - URL sorgu parametrelerindeki (GET) veritabanı ilişkili aday noktaları (CWE-89),
   - HTML formlarındaki, bağımsız inputlardaki ve Login ekranlarındaki girdi alanlarını,
   - GET metoduyla şifre iletimini (CWE-598) ve eksik CSRF korumasını (CWE-352) denetler.
2. HTTP İstek / Yanıt Metni (Response Text) Analizi:
   - InputRequester tarafından gönderilen GET/POST isteklerinin yanıt metinlerinde oluşan
     veritabanı hata mesajlarını (Error-Based SQLi - CWE-89 / CWE-209) ve
   - Gönderilen girdinin yanıt metni içinde doğrudan yansımasını (In-Band / Yansımalı Girdi) raporlar.
"""
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
    """Kara kutu taramada tespit edilen güvenlik bulgusu kaydı."""
    category: str       # "Kara Kutu İstek/Yanıt Analizi" veya "Kara Kutu Saldırı Yüzeyi Denetimi"
    cwe: str            # Örn: "CWE-89 (SQL Injection)" veya "CWE-209 (Veritabanı Hata İfşası)"
    severity: str       # "YÜKSEK", "ORTA", "DÜŞÜK", "BİLGİ"
    location: str       # Hedef URL veya uç nokta adresi
    parameter: str      # İlgili input veya GET/POST parametresi
    evidence: str       # HTTP yanıt metni veya gözlem kanıtı
    remediation: str    # Güvenli yapılandırma / çözüm önerisi


@dataclass
class SQLiAuditResult:
    """Kara kutu SQL Injection ve web güvenlik denetimi sonucu."""
    passive_findings: list = field(default_factory=list)   # list of SQLiFinding

    @property
    def all_findings(self):
        return self.passive_findings


class HybridSQLiAnalyzer:
    """Kara Kutu (Black-Box) Web Saldırı Yüzeyi ve İstek/Yanıt Denetçisi."""

    def analyze_crawl_result(self, crawl_result):
        """Crawler tarafından çıkarılan adres haritasını ve input noktalarını inceler."""
        findings = []
        if crawl_result is None:
            return findings

        # 1. Sayfa Yanıtlarında Veritabanı Hata İfşası Kontrolü (CWE-209)
        for page in crawl_result.pages:
            for err_sig in getattr(page, "passive_db_errors", []):
                findings.append(SQLiFinding(
                    category="Kara Kutu Yanıt Analizi",
                    cwe="CWE-209 / CWE-89 (Veritabanı Hata Mesajı İfşası)",
                    severity="YÜKSEK",
                    location=page.url,
                    parameter="HTTP Yanıt Gövdesi (Response Text)",
                    evidence=f"Sayfa yanıt metninde veritabanı hata izi tespit edildi: {err_sig}",
                    remediation=(
                        "Sunucu tarafında detaylı veritabanı hata mesajlarını (display_errors) kapatın "
                        "ve tüm kullanıcı girdilerini parametreli sorgularla (Prepared Statement) işleyin."
                    )
                ))

        # 2. Parametreli URL'lerde (GET) Veritabanı Sorgu Adayı Analizi
        for p_url in crawl_result.param_urls:
            parsed_path = urlparse(p_url.url).path.lower()
            is_sqli_module_path = "sqli" in parsed_path or "sql" in parsed_path

            for param_name, param_val in p_url.params.items():
                p_lower = param_name.lower()
                if p_lower in ("submit", "login", "btn", "button", "action"):
                    continue

                is_db_param = (
                    p_lower in DB_RELATED_PARAM_NAMES
                    or str(param_val).isdigit()
                    or is_sqli_module_path
                )

                if is_db_param:
                    severity = "YÜKSEK" if (is_sqli_module_path or p_lower in ("id", "user_id", "cat", "item")) else "ORTA"
                    findings.append(SQLiFinding(
                        category="Kara Kutu Saldırı Yüzeyi Denetimi",
                        cwe="CWE-89 (SQL Injection Aday GET Parametresi)",
                        severity=severity,
                        location=p_url.url,
                        parameter=f"GET '{param_name}' (Değer: '{param_val}')",
                        evidence=(
                            f"URL sorgu parametresi ('{param_name}={param_val}') veritabanı kayıt sorgulama "
                            f"yapısı taşıyor ({p_url.full_url})."
                        ),
                        remediation=(
                            f"'{param_name}' parametresi sunucu tarafında tip doğrulamasından geçirilmeli ve "
                            f"parametreli sorgu (Prepared Statement) ile kullanılmalıdır."
                        )
                    ))

        # 3. Formlar, Bağımsız Inputlar ve Login Ekranları Analizi
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
            is_login_form = getattr(form, "is_login_form", False)
            is_sqli_form = (
                is_login_form
                or "sqli" in parsed_action
                or "login" in parsed_action
                or any(
                    any(k in i.name.lower() for k in (
                        "id", "user", "query", "search", "email", "pass",
                        "sifre", "şifre", "no", "ogrenci", "öğrenci", "ara"
                    ))
                    for i in data_inputs
                )
            )

            if is_sqli_form:
                form_label = "Login / Kimlik Doğrulama Formu" if is_login_form else "Veritabanı İlişkili Girdi Formu"
                findings.append(SQLiFinding(
                    category="Kara Kutu Saldırı Yüzeyi Denetimi",
                    cwe=f"CWE-89 ({form_label} - SQLi Girdi Adayı)",
                    severity="ORTA",
                    location=form.action,
                    parameter=", ".join(i.name for i in data_inputs),
                    evidence=(
                        f"[{form.method.upper()}] formunda veritabanı sorgusuna bağlanan girdi alanları "
                        f"tespit edildi (Bulunduğu Sayfa: {form.page_url})."
                    ),
                    remediation=(
                        "Formdan gönderilen POST/GET verileri doğrudan SQL metnine eklenmemeli, "
                        "parametreli sorgular (Prepared Statements) kullanılmalıdır."
                    )
                ))

            # Parola alanının GET metodu ile gönderilmesi kontrolü
            has_password = any(i.type == "password" for i in form.inputs)
            if has_password and form.method.lower() == "get":
                findings.append(SQLiFinding(
                    category="Kara Kutu Güvenlik Denetimi",
                    cwe="CWE-598 (Hassas Verinin GET Sorgusu ile İletimi)",
                    severity="ORTA",
                    location=form.action,
                    parameter="password (GET)",
                    evidence=f"Parola alanı içeren form GET metodu kullanıyor ({form.page_url}).",
                    remediation="Kimlik doğrulama formlarında her zaman POST metodu ve HTTPS kullanılmalıdır."
                ))

            # POST formlarında CSRF token eksikliği
            if form.method.lower() == "post" and not has_csrf:
                findings.append(SQLiFinding(
                    category="Kara Kutu Güvenlik Denetimi",
                    cwe="CWE-352 (Eksik CSRF Token Koruması)",
                    severity="DÜŞÜK",
                    location=form.action,
                    parameter=", ".join(input_names),
                    evidence=f"POST formunda CSRF koruma anahtarı (hidden token) bulunamadı ({form.page_url}).",
                    remediation="Durum değiştiren tüm POST formlarına oturuma özel benzersiz CSRF token eklenmelidir."
                ))

        return findings

    def analyze_request_logs(self, req_report):
        """InputRequester ile gönderilen GET/POST isteklerinin yanıt metinlerini (Response Text) inceler."""
        findings = []
        if req_report is None or not getattr(req_report, "logs", None):
            return findings

        for log in req_report.logs:
            # 1. İstek sonrasında dönen yanıt metninde SQL Veritabanı Hatası oluştuysa
            if getattr(log, "db_errors", None):
                err_str = ", ".join(log.db_errors)
                sent_str = ", ".join(f"{k}={v}" for k, v in (log.sent_params or {}).items())
                findings.append(SQLiFinding(
                    category="Kara Kutu İstek/Yanıt (Text) Analizi",
                    cwe="CWE-89 / CWE-209 (İstek Sonrası Veritabanı SQL Hatası)",
                    severity="YÜKSEK",
                    location=log.target_url,
                    parameter=f"[{log.method}] {sent_str}",
                    evidence=f"Gönderilen istek sonrasında dönen sayfa metninde SQL hatası yakalandı: {err_str}",
                    remediation=(
                        "İlgili uç noktada kullanıcı girdisi doğrudan SQL sorgusunu bozmaktadır. "
                        "Parametreli sorgu (Prepared Statement) kullanılmalı ve hata çıktıları gizlenmelidir."
                    )
                ))

            # 2. Gönderilen girdi yanıt metninde doğrudan yansıdıysa (In-Band / Yansıma Tespiti)
            if getattr(log, "reflected_inputs", None):
                refl_str = ", ".join(log.reflected_inputs)
                findings.append(SQLiFinding(
                    category="Kara Kutu İstek/Yanıt (Text) Analizi",
                    cwe="CWE-89 / CWE-79 (Yanıt Metninde Yansıyan Kullanıcı Girdisi)",
                    severity="ORTA",
                    location=log.target_url,
                    parameter=f"[{log.method}] {refl_str}",
                    evidence=(
                        f"Gönderilen '{refl_str}' parametresi sunucudan dönen güncel sayfa metni "
                        f"içerisinde doğrudan yansıdı (HTTP {log.status_code})."
                    ),
                    remediation=(
                        "Kullanıcıdan alınan ve yanıt metninde ekrana yansıtılan tüm veriler hem veritabanı "
                        "katmanında parametreli sorguyla işlenmeli hem de çıktı kodlaması (Output Encoding) yapılmalıdır."
                    )
                ))

        return findings

    def run_hybrid_audit(self, crawl_result=None, req_report=None, source_path=None):
        """Kara kutu (Black-Box) saldırı yüzeyi ve istek/yanıt analizini çalıştırır."""
        report = SQLiAuditResult()
        if crawl_result is not None:
            report.passive_findings.extend(self.analyze_crawl_result(crawl_result))
        if req_report is not None:
            report.passive_findings.extend(self.analyze_request_logs(req_report))
        return report
