"""Otomatik Zafiyet Tarayıcı — Web Arayüzü (Dashboard & REST API Sunucusu).

Harici bir web framework kurulumu gerektirmeden Python standart kütüphanesi
(http.server.ThreadingHTTPServer) üzerinde çalışır.

Tüm proje modüllerini tek bir modern web arayüzünde birleştirir:
- Web Keşif Motoru (Crawler: Adres Haritası, Form/Input Süzgeci, Parametreli URL, robots.txt, sitemap.xml)
- Girdi İstek Motoru (InputRequester: Keşfedilen inputlara GET/POST isteği & Request Auto-Login)
- Kara Kutu SQLi & Web Güvenlik Denetimi (CWE-89, CWE-209, CWE-352, CWE-598)
- Geçmiş Tarama Loglarını (logs/) Görüntüleme

Çalıştırma:
    python web_app.py
    (Tarayıcıda: http://127.0.0.1:5000)
"""
import argparse
import dataclasses
import importlib
import json
import os
import threading
import traceback
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import requests

import main as main_mod
import scanner.crawler as crawler_mod
import scanner.input_requester as requester_mod
import scanner.sqli_analyzer as sqli_mod
from main import build_session, normalize_url, save_report_to_log
from scanner.crawler import Crawler, FormInfo, InputField, ParamURL
from scanner.input_requester import InputRequester
from scanner.sqli_analyzer import HybridSQLiAnalyzer

_RELOAD_LOCK = threading.Lock()


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Otomatik Zafiyet Tarayıcı — Web Kontrol Paneli</title>
  <style>
    :root {
      --bg-main: #0b1120;
      --bg-card: #111827;
      --bg-card-hover: #1e293b;
      --bg-input: #0f172a;
      --border: #1f2937;
      --border-focus: #3b82f6;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --accent: #3b82f6;
      --accent-hover: #2563eb;
      --success: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
      --purple: #8b5cf6;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      background-color: var(--bg-main);
      color: var(--text-main);
      line-height: 1.5;
      min-height: 100vh;
    }

    header {
      background: linear-gradient(90deg, #0f172a 0%, #1e1b4b 100%);
      border-bottom: 1px solid var(--border);
      padding: 1rem 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 0.85rem;
    }

    .brand-icon {
      width: 42px;
      height: 42px;
      border-radius: 10px;
      background: linear-gradient(135deg, var(--accent), var(--purple));
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      font-size: 1.2rem;
      color: #fff;
      box-shadow: 0 4px 14px rgba(59, 130, 246, 0.35);
    }

    .brand h1 {
      font-size: 1.25rem;
      font-weight: 700;
      letter-spacing: -0.02em;
    }

    .brand p {
      font-size: 0.8rem;
      color: var(--text-muted);
    }

    .status-pill {
      font-size: 0.8rem;
      padding: 0.35rem 0.85rem;
      border-radius: 999px;
      background: rgba(16, 185, 129, 0.12);
      color: var(--success);
      border: 1px solid rgba(16, 185, 129, 0.3);
      font-weight: 600;
    }

    .container {
      max-width: 1440px;
      margin: 0 auto;
      padding: 1.5rem 2rem;
      display: grid;
      grid-template-columns: 360px 1fr;
      gap: 1.5rem;
    }

    @media (max-width: 1024px) {
      .container {
        grid-template-columns: 1fr;
      }
    }

    .card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.25rem;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);
    }

    .card-title {
      font-size: 1rem;
      font-weight: 600;
      margin-bottom: 1rem;
      padding-bottom: 0.6rem;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .form-group {
      margin-bottom: 0.95rem;
    }

    .form-group label {
      display: block;
      font-size: 0.82rem;
      font-weight: 600;
      color: var(--text-muted);
      margin-bottom: 0.35rem;
    }

    .form-control {
      width: 100%;
      padding: 0.6rem 0.75rem;
      background: var(--bg-input);
      border: 1px solid var(--border);
      border-radius: 8px;
      color: var(--text-main);
      font-size: 0.9rem;
      transition: border-color 0.15s;
    }

    .form-control:focus {
      outline: none;
      border-color: var(--border-focus);
    }

    .form-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 0.75rem;
    }

    .checkbox-group {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      font-size: 0.86rem;
      margin: 0.6rem 0;
      cursor: pointer;
    }

    .checkbox-group input {
      width: 16px;
      height: 16px;
      accent-color: var(--accent);
    }

    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
      width: 100%;
      padding: 0.75rem 1rem;
      background: linear-gradient(135deg, var(--accent), #1d4ed8);
      color: #fff;
      font-weight: 600;
      font-size: 0.92rem;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      transition: transform 0.1s, opacity 0.15s;
    }

    .btn:hover {
      opacity: 0.95;
    }

    .btn:active {
      transform: scale(0.99);
    }

    .btn:disabled {
      opacity: 0.55;
      cursor: not-allowed;
    }

    .btn-sm {
      width: auto;
      padding: 0.35rem 0.75rem;
      font-size: 0.78rem;
      border-radius: 6px;
    }

    .btn-secondary {
      background: var(--bg-card-hover);
      border: 1px solid var(--border);
    }

    /* KPI Summary Grid */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(155px, 1fr));
      gap: 0.9rem;
      margin-bottom: 1.25rem;
    }

    .kpi-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 0.95rem 1rem;
    }

    .kpi-label {
      font-size: 0.76rem;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }

    .kpi-value {
      font-size: 1.65rem;
      font-weight: 700;
      margin-top: 0.2rem;
    }

    /* Tabs */
    .tabs {
      display: flex;
      gap: 0.4rem;
      border-bottom: 1px solid var(--border);
      margin-bottom: 1rem;
      overflow-x: auto;
      padding-bottom: 0.4rem;
    }

    .tab-btn {
      background: transparent;
      color: var(--text-muted);
      border: 1px solid transparent;
      padding: 0.5rem 0.9rem;
      border-radius: 8px;
      font-size: 0.85rem;
      font-weight: 600;
      cursor: pointer;
      white-space: nowrap;
      transition: all 0.15s;
    }

    .tab-btn:hover {
      color: var(--text-main);
      background: rgba(255, 255, 255, 0.03);
    }

    .tab-btn.active {
      color: #fff;
      background: rgba(59, 130, 246, 0.18);
      border-color: rgba(59, 130, 246, 0.45);
    }

    .tab-content {
      display: none;
    }

    .tab-content.active {
      display: block;
    }

    /* Tables & Lists */
    .table-wrap {
      overflow-x: auto;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.86rem;
    }

    th, td {
      text-align: left;
      padding: 0.65rem 0.75rem;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }

    th {
      color: var(--text-muted);
      font-weight: 600;
      font-size: 0.78rem;
      text-transform: uppercase;
      background: rgba(15, 23, 42, 0.6);
    }

    tr:hover td {
      background: rgba(30, 41, 59, 0.35);
    }

    .badge {
      display: inline-block;
      padding: 0.18rem 0.55rem;
      border-radius: 6px;
      font-size: 0.73rem;
      font-weight: 700;
      margin: 0.1rem;
    }

    .badge-get { background: rgba(59, 130, 246, 0.18); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.35); }
    .badge-post { background: rgba(16, 185, 129, 0.18); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.35); }
    .badge-inj { background: rgba(139, 92, 246, 0.18); color: #c4b5fd; border: 1px solid rgba(139, 92, 246, 0.35); }
    .badge-fixed { background: rgba(148, 163, 184, 0.15); color: #94a3b8; }
    .badge-high { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }
    .badge-med { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }
    .badge-low { background: rgba(59, 130, 246, 0.2); color: #93c5fd; border: 1px solid rgba(59, 130, 246, 0.4); }
    .badge-ok { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }

    .mono {
      font-family: 'Consolas', 'Courier New', monospace;
      font-size: 0.82rem;
      word-break: break-all;
    }

    .empty-state {
      text-align: center;
      padding: 2.5rem 1rem;
      color: var(--text-muted);
      font-size: 0.9rem;
    }

    .finding-box {
      border: 1px solid var(--border);
      background: rgba(15, 23, 42, 0.55);
      border-radius: 10px;
      padding: 0.9rem 1rem;
      margin-bottom: 0.75rem;
    }

    .finding-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 0.5rem;
      margin-bottom: 0.45rem;
      flex-wrap: wrap;
    }

    .code-snippet {
      background: #090d16;
      border: 1px solid #1e293b;
      padding: 0.5rem 0.7rem;
      border-radius: 6px;
      font-family: Consolas, monospace;
      font-size: 0.8rem;
      color: #e2e8f0;
      margin: 0.4rem 0;
      overflow-x: auto;
    }

    .loader {
      display: none;
      align-items: center;
      gap: 0.6rem;
      padding: 0.75rem 1rem;
      border-radius: 8px;
      background: rgba(59, 130, 246, 0.12);
      border: 1px solid rgba(59, 130, 246, 0.3);
      color: #93c5fd;
      font-size: 0.86rem;
      margin-bottom: 1rem;
    }

    .spinner {
      width: 16px;
      height: 16px;
      border: 2px solid rgba(147, 197, 253, 0.3);
      border-top-color: #60a5fa;
      border-radius: 50%;
      animation: spin 0.75s linear infinite;
    }

    @keyframes spin {
      to { transform: rotate(360deg); }
    }

    /* Modal for single custom request */
    .modal-backdrop {
      display: none;
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.7);
      z-index: 999;
      align-items: center;
      justify-content: center;
      padding: 1rem;
    }

    .modal {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      max-width: 960px;
      width: 100%;
      padding: 1.35rem;
      max-height: 92vh;
      overflow-y: auto;
    }

    .preview-iframe {
      width: 100%;
      height: 420px;
      border: 1px solid var(--border);
      border-radius: 8px;
      background: #ffffff;
    }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <div class="brand-icon">ZT</div>
      <div>
        <h1>Otomatik Zafiyet Tarayıcı — Web Arayüzü</h1>
        <p>Tekirdağ Namık Kemal Üniversitesi • Bilgisayar Mühendisliği (Crawler + Input Requester + Hibrit SQLi/SAST)</p>
      </div>
    </div>
    <div class="status-pill" id="serverStatus">Sistem Hazır</div>
  </header>

  <div class="container">
    <!-- SOL PANEL: TARAMA AYARLARI -->
    <aside class="card">
      <div class="card-title">
        <span>Tarama ve Modül Ayarları</span>
      </div>

      <form id="scanForm" onsubmit="runScan(event)">
        <div class="form-group">
          <label for="mode">Çalışma Modülü</label>
          <select id="mode" class="form-control" onchange="toggleModeFields()">
            <option value="crawler" selected>1. Sitenin Adres Haritası & Input Alabilenleri Listele (Önerilen)</option>
            <option value="requester">2. Adres Haritası + Bulunan Tüm Inputlara Otomatik İstek Gönder</option>
            <option value="full">3. Tam Kapsamlı Kara Kutu (Adres Haritası + İstek Gönder + SQLi Denetimi)</option>
            <option value="sqli-passive">4. Adres Haritası + Kara Kutu SQLi ve Web Denetimi</option>
          </select>
        </div>

        <div id="webTargetSection">
          <div class="form-group">
            <label for="targetUrl">Hedef Site Adresi (URL)</label>
            <input type="text" id="targetUrl" class="form-control" value="http://localhost:8080" placeholder="https://ornek-site.com" />
          </div>

          <div class="form-group">
            <label for="authType">Oturum / Kimlik Doğrulama (Auto-Login)</label>
            <select id="authType" class="form-control" onchange="toggleCookieInput()">
              <option value="none">Standart Tarama (Oturumsuz)</option>
              <option value="auto-login">Request ile Otomatik Giriş (Auto-Login: Kullanıcı Adı / Öğrenci No & Şifre)</option>
              <option value="http-auth">Sadece HTTP 401 Klasör Girişi (Basic / Digest Auth)</option>
              <option value="dvwa">DVWA Otomatik Giriş (admin / password)</option>
              <option value="cookie">Özel Cookie (Çerez) ile Tarama</option>
            </select>
          </div>

          <div class="form-group" id="httpAuthGroup" style="display:none;">
            <div class="form-row">
              <div>
                <label for="httpAuthUser">Kullanıcı Adı / Öğrenci No</label>
                <input type="text" id="httpAuthUser" class="form-control" placeholder="Örn: Öğrenci No / admin" />
              </div>
              <div>
                <label for="httpAuthPass">Şifre / Parola</label>
                <input type="password" id="httpAuthPass" class="form-control" placeholder="Şifre" />
              </div>
            </div>
            <button type="button" id="autoLoginTestBtn" class="btn btn-secondary" style="margin-top:0.55rem; font-size:0.82rem; padding:0.5rem;" onclick="runAutoLoginNow()">
              Şimdi Request ile Otomatik Giriş Yap ve Sayfayı Gör
            </button>
          </div>

          <div class="form-group" id="cookieGroup" style="display:none;">
            <label for="cookieStr">Cookie Değeri</label>
            <input type="text" id="cookieStr" class="form-control" placeholder="PHPSESSID=xyz; security=low" />
          </div>

          <div class="form-row">
            <div class="form-group">
              <label for="maxPages">Maks. Sayfa (Harita Sınırı)</label>
              <input type="number" id="maxPages" class="form-control" value="100" min="1" max="1000" />
            </div>
            <div class="form-group">
              <label for="maxDepth">Maks. Derinlik</label>
              <input type="number" id="maxDepth" class="form-control" value="5" min="1" max="15" />
            </div>
          </div>

          <div class="form-group" id="requesterOptions">
            <label class="checkbox-group">
              <input type="checkbox" id="sendRequestsCheck" />
              <span>Tarama bitince tüm inputlara otomatik test isteği gönder</span>
            </label>
            <label for="customTestValue" style="margin-top:0.4rem;">Özel Test Değeri (Opsiyonel)</label>
            <input type="text" id="customTestValue" class="form-control" placeholder="Boş bırakılırsa tipe göre otomatik doldurulur" />
          </div>
        </div>

        <button type="submit" class="btn" id="startBtn">
          <span>Adres Haritasını Çıkar & Inputları Listele</span>
        </button>
      </form>

      <div style="margin-top: 1.25rem; padding-top: 1rem; border-top: 1px solid var(--border);">
        <button type="button" class="btn btn-secondary" onclick="loadLogsList()">
          Geçmiş Raporları (logs/) Yenile
        </button>
      </div>
    </aside>

    <!-- SAĞ PANEL: SONUÇLAR VE SEKMELER -->
    <main>
      <div class="loader" id="loaderBox">
        <div class="spinner"></div>
        <span id="loaderText">Sitenin adres haritası çıkarılıyor ve input alabilen sayfalar analiz ediliyor...</span>
      </div>

      <!-- ÖZET KARTLARI -->
      <div class="kpi-grid">
        <div class="kpi-card">
          <div class="kpi-label">Sitenin Adres Haritası</div>
          <div class="kpi-value" id="kpiPages">0</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Input Alabilen Adres</div>
          <div class="kpi-value" id="kpiInputPages" style="color: var(--success);">0</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Form / Input Grubu</div>
          <div class="kpi-value" id="kpiForms" style="color: var(--purple);">0</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Parametreli URL (GET)</div>
          <div class="kpi-value" id="kpiParams">0</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Gönderilen İstek</div>
          <div class="kpi-value" id="kpiRequests" style="color: var(--accent);">0</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Güvenlik Bulgusu</div>
          <div class="kpi-value" id="kpiFindings" style="color: var(--danger);">0</div>
        </div>
      </div>

      <!-- ANA SONUÇ KARTI -->
      <div class="card">
        <div class="tabs">
          <button class="tab-btn active" onclick="switchTab('tabPages', this)">1. Sitenin Adres Haritası & Input Alabilenler</button>
          <button class="tab-btn" onclick="switchTab('tabInputs', this)">2. Input Noktası Detayları (Formlar & GET)</button>
          <button class="tab-btn" onclick="switchTab('tabRequester', this)">3. Gönderilen İstek Cevapları (HTTP)</button>
          <button class="tab-btn" onclick="switchTab('tabSecurity', this)">4. Kara Kutu SQLi & Güvenlik Raporu</button>
          <button class="tab-btn" onclick="switchTab('tabLogs', this)">5. Kaydedilen Loglar</button>
        </div>

        <!-- SEKME 1: SİTENİN ADRES HARİTASI VE INPUT ALABİLENLER -->
        <div id="tabPages" class="tab-content active">
          <div id="pagesContainer" class="empty-state">
            Henüz tarama başlatılmadı. Sol panelden hedef URL'yi girip <b>Adres Haritasını Çıkar & Inputları Listele</b> düğmesine tıklayın.
          </div>
        </div>

        <!-- SEKME 2: FORMLAR, INPUTLAR VE PARAMETRELİ URL'LER -->
        <div id="tabInputs" class="tab-content">
          <div id="inputsContainer" class="empty-state">
            Keşfedilen form ve input elemanlarının detayları burada görüntülenecektir.
          </div>
        </div>

        <!-- SEKME 3: INPUT REQUESTER SONUÇLARI -->
        <div id="tabRequester" class="tab-content">
          <div id="requesterContainer" class="empty-state">
            Girdi istek sonuçları burada görüntülenecektir.
          </div>
        </div>

        <!-- SEKME 4: KARA KUTU GÜVENLİK RAPORU -->
        <div id="tabSecurity" class="tab-content">
          <div id="securityContainer" class="empty-state">
            Kara kutu SQL Injection ve web güvenlik denetimi bulguları burada görüntülenecektir.
          </div>
        </div>

        <!-- SEKME 5: LOG DOSYALARI -->
        <div id="tabLogs" class="tab-content">
          <div id="logsContainer" class="empty-state">
            Log dosyalarını görmek için sol panelden "Geçmiş Raporları Yenile" düğmesine tıklayın.
          </div>
        </div>
      </div>
    </main>
  </div>

  <!-- MANUEL İSTEK GÖNDERME MODALI -->
  <div class="modal-backdrop" id="customReqModal">
    <div class="modal">
      <div class="card-title">
        <span>Girdi Noktasına Özel İstek Gönder</span>
        <button class="btn btn-sm btn-secondary" onclick="closeModal()">Kapat</button>
      </div>
      <div id="modalBody"></div>
    </div>
  </div>

  <script>
    let lastScanData = null;

    function toggleCookieInput() {
      const auth = document.getElementById('authType').value;
      document.getElementById('cookieGroup').style.display = (auth === 'cookie') ? 'block' : 'none';
      document.getElementById('httpAuthGroup').style.display = (auth === 'http-auth' || auth === 'auto-login') ? 'block' : 'none';
      const testBtn = document.getElementById('autoLoginTestBtn');
      if (testBtn) {
        testBtn.style.display = (auth === 'auto-login' || auth === 'http-auth') ? 'inline-flex' : 'none';
      }
    }

    async function runAutoLoginNow(customTargetUrl) {
      const targetUrl = (customTargetUrl || document.getElementById('targetUrl').value).trim();
      const username = document.getElementById('httpAuthUser').value.trim();
      const password = document.getElementById('httpAuthPass').value;

      if (!targetUrl) {
        alert('Lütfen önce Hedef Site Adresini (URL) girin.');
        return;
      }
      if (!username) {
        alert('Lütfen otomatik giriş (Auto-Login) için Kullanıcı Adı / Öğrenci No bilgisini girin.');
        return;
      }

      const modalBody = document.getElementById('modalBody');
      modalBody.innerHTML = `<div style="padding:1rem; color:var(--text-muted);"><b>Request ile Otomatik Giriş (Auto-Login)</b> yapılıyor: Sayfadaki login formu, CSRF tokenları ve girdi alanları analiz edilip giriş isteği gönderiliyor...</div>`;
      document.getElementById('customReqModal').style.display = 'flex';

      try {
        const res = await fetch('/api/auto-login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            target_url: targetUrl,
            username: username,
            password: password
          })
        });
        const data = await res.json();
        if (!res.ok || data.error || data.error_message) {
          modalBody.innerHTML = `<div style="color:var(--danger); padding:0.75rem;">Auto-Login Hatası: ${escapeHtml(data.error || data.error_message)}</div>`;
          return;
        }
        const sentList = Object.entries(data.sent_params || {})
          .map(([k, v]) => `<span class="badge badge-inj">${escapeHtml(k)} = ${escapeHtml(v)}</span>`)
          .join(' ');
        modalBody.innerHTML = `
          <div style="margin-bottom:0.5rem; font-size:0.85rem;">
            <b>Otomatik Eşleştirilen & Gönderilen Login Alanları (${escapeHtml(data.method)}):</b> ${sentList}
          </div>
          ${buildResponseViewerHtml(data, 'autologinmodal')}
        `;
        populatePreviewIframe('autologinmodal', data);
      } catch (err) {
        modalBody.innerHTML = `<div style="color:var(--danger); padding:0.75rem;">İstek hatası: ${escapeHtml(err.message)}</div>`;
      }
    }

    function toggleModeFields() {
      const mode = document.getElementById('mode').value;
      const reqOpt = document.getElementById('requesterOptions');

      reqOpt.style.display = (mode === 'full' || mode === 'requester' || mode === 'crawler') ? 'block' : 'none';

      if (mode === 'requester' || mode === 'full') {
        document.getElementById('sendRequestsCheck').checked = true;
      } else if (mode === 'crawler') {
        document.getElementById('sendRequestsCheck').checked = false;
      }
    }

    function switchTab(tabId, btnEl) {
      document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
      document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
      document.getElementById(tabId).classList.add('active');
      if (btnEl) btnEl.classList.add('active');
    }

    function escapeHtml(str) {
      if (str === null || str === undefined) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

    async function runScan(e) {
      e.preventDefault();
      const startBtn = document.getElementById('startBtn');
      const loader = document.getElementById('loaderBox');
      const statusPill = document.getElementById('serverStatus');

      const payload = {
        mode: document.getElementById('mode').value,
        target_url: document.getElementById('targetUrl').value.trim(),
        auth_type: document.getElementById('authType').value,
        cookie_str: document.getElementById('cookieStr').value.trim(),
        http_auth_user: document.getElementById('httpAuthUser').value.trim(),
        http_auth_pass: document.getElementById('httpAuthPass').value,
        max_pages: parseInt(document.getElementById('maxPages').value || '100', 10),
        max_depth: parseInt(document.getElementById('maxDepth').value || '5', 10),
        send_requests: document.getElementById('sendRequestsCheck').checked,
        custom_test_value: document.getElementById('customTestValue').value
      };

      startBtn.disabled = true;
      loader.style.display = 'flex';
      statusPill.textContent = 'Tarama Çalışıyor...';

      try {
        const res = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (!res.ok || data.error) {
          alert('Hata: ' + (data.error || 'Bilinmeyen sunucu hatası'));
          statusPill.textContent = 'Hata Oluştu';
          return;
        }
        lastScanData = data;
        renderDashboard(data);
        statusPill.textContent = 'Tarama Tamamlandı';
      } catch (err) {
        alert('İstek hatası: ' + err.message);
        statusPill.textContent = 'Bağlantı Hatası';
      } finally {
        startBtn.disabled = false;
        loader.style.display = 'none';
      }
    }

    function renderDashboard(data) {
      const crawl = data.crawl || { pages: [], forms: [], param_urls: [], disallowed_paths: [] };
      const reqLogs = (data.input_requests && data.input_requests.logs) ? data.input_requests.logs : [];
      const audit = data.audit || { passive_findings: [] };

      const totalFindings = audit.passive_findings ? audit.passive_findings.length : 0;
      const inputPagesCount = (crawl.pages || []).filter(p => p.has_inputs).length;

      document.getElementById('kpiPages').textContent = (crawl.pages || []).length;
      document.getElementById('kpiInputPages').textContent = inputPagesCount;
      document.getElementById('kpiForms').textContent = (crawl.forms || []).length;
      document.getElementById('kpiParams').textContent = (crawl.param_urls || []).length;
      document.getElementById('kpiRequests').textContent = reqLogs.length;
      document.getElementById('kpiFindings').textContent = totalFindings;

      renderPagesTab(crawl);
      renderInputsTab(crawl);
      renderRequesterTab(reqLogs);
      renderSecurityTab(audit);
    }

    function renderInputsTab(crawl) {
      const container = document.getElementById('inputsContainer');
      let html = '';

      html += `<h3 style="font-size:0.95rem; margin-bottom:0.6rem;">1. Keşfedilen Formlar ve Sayfa İçi Girdi Alanları (${crawl.forms.length})</h3>`;
      if (crawl.forms.length === 0) {
        html += `<div class="empty-state" style="padding:1rem;">Hiçbir form veya input elemanı bulunamadı.</div>`;
      } else {
        html += `<div class="table-wrap"><table><thead><tr>
          <th>Metod</th>
          <th>Kaynak Dosya / Hedef (Action)</th>
          <th>Test Edilebilir Inputlar</th>
          <th>Sabit / Buton Alanları</th>
          <th>İşlem</th>
        </tr></thead><tbody>`;

        crawl.forms.forEach((f, idx) => {
          const mBadge = f.method.toUpperCase() === 'POST' ? 'badge-post' : 'badge-get';
          const loginBadge = f.is_login_form
            ? `<div style="margin-top:0.25rem;"><span class="badge badge-high">LOGIN EKRANI: ${escapeHtml(f.form_type || 'Login')}</span></div>`
            : `<div style="margin-top:0.25rem;"><span class="badge badge-fixed">${escapeHtml(f.form_type || 'Form')}</span></div>`;
          const injList = f.inputs.filter(i => i.is_injectable);
          const fixedList = f.inputs.filter(i => !i.is_injectable);

          const injHtml = injList.length
            ? injList.map(i => `<span class="badge badge-inj">${escapeHtml(i.name)} <small>(${escapeHtml(i.type)})</small></span>`).join(' ')
            : '<span style="color:var(--text-muted)">Yok</span>';

          const fixedHtml = fixedList.length
            ? fixedList.map(i => `<span class="badge badge-fixed">${escapeHtml(i.name)} (${escapeHtml(i.type)})</span>`).join(' ')
            : '-';

          html += `<tr>
            <td>
              <span class="badge ${mBadge}">${escapeHtml(f.method.toUpperCase())}</span>
              ${loginBadge}
            </td>
            <td class="mono">
              <div><b>Hedef:</b> ${escapeHtml(f.action)}</div>
              <div style="color:var(--text-muted); font-size:0.76rem;">Bulunduğu Sayfa: ${escapeHtml(f.page_url)}</div>
            </td>
            <td>${injHtml}</td>
            <td>${fixedHtml}</td>
            <td>
              <button class="btn btn-sm" onclick="openFormRequestModal(${idx})">Özel İstek At</button>
            </td>
          </tr>`;
        });
        html += `</tbody></table></div>`;
      }

      html += `<h3 style="font-size:0.95rem; margin:1.4rem 0 0.6rem;">2. Parametreli URL'ler (GET Input Alan Dosyalar: ${crawl.param_urls.length})</h3>`;
      if (crawl.param_urls.length === 0) {
        html += `<div class="empty-state" style="padding:1rem;">Parametreli URL bulunamadı.</div>`;
      } else {
        html += `<div class="table-wrap"><table><thead><tr>
          <th>Temel Dosya / Uç Nokta</th>
          <th>Tam Adres</th>
          <th>Parametreler</th>
          <th>İşlem</th>
        </tr></thead><tbody>`;

        crawl.param_urls.forEach((p, idx) => {
          const paramBadges = Object.entries(p.params || {})
            .map(([k, v]) => `<span class="badge badge-inj">${escapeHtml(k)} = ${escapeHtml(v)}</span>`)
            .join(' ');
          html += `<tr>
            <td class="mono">${escapeHtml(p.url)}</td>
            <td class="mono" style="color:var(--text-muted)">${escapeHtml(p.full_url)}</td>
            <td>${paramBadges}</td>
            <td>
              <button class="btn btn-sm" onclick="openParamRequestModal(${idx})">Özel İstek At</button>
            </td>
          </tr>`;
        });
        html += `</tbody></table></div>`;
      }

      container.innerHTML = html;
    }

    function buildResponseViewerHtml(item, prefix) {
      const finalUrl = item.final_url || item.target_url || '';
      const redirected = finalUrl && item.target_url && finalUrl !== item.target_url;
      const redirectsInfo = (item.redirect_chain && item.redirect_chain.length)
        ? `<div style="font-size:0.8rem; color:var(--warning); margin-top:0.2rem;"><b>Yönlendirme Zinciri:</b> ${escapeHtml(item.redirect_chain.join(' ➔ '))} ➔ ${escapeHtml(finalUrl)}</div>`
        : '';

      const headersText = Object.entries(item.response_headers || {})
        .map(([k, v]) => `${k}: ${v}`)
        .join('\n');

      const authHintHtml = (item.status_code === 401)
        ? `<div style="background:rgba(245, 158, 11, 0.14); border:1px solid rgba(245, 158, 11, 0.4); color:#fbbf24; padding:0.65rem 0.8rem; border-radius:8px; font-size:0.82rem; margin-bottom:0.65rem;">
            <b>[!] HTTP 401 Yetki Uyarısı:</b> Sunucu bu klasöre/sayfaya erişim için geçerli bir <b>HTTP Klasör Kullanıcı Adı ve Şifresi</b> istiyor. Yanlış şifre gönderildiği için sunucu asıl sayfayı (örn. içerideki Öğrenci No formunu) göndermek yerine <i>"This server could not verify that you are authorized..."</i> hatası döndürdü. Yukarıdaki <b>username / password</b> alanlarına bu klasörün gerçek giriş bilgilerini yazıp <b>İsteği Gönder</b>'e tıklarsanız veya sol panelden <b>HTTP 401 Klasör/Sayfa Girişi</b> seçip taratırsanız içerideki asıl sayfa ve inputlar açılacaktır.
          </div>`
        : '';

      let unlockedHtml = '';
      if (item.unlocked_forms && item.unlocked_forms.length > 0) {
        const innerBadges = item.unlocked_forms.map(uf =>
          (uf.inputs || []).map(inp => `<span class="badge badge-inj">${escapeHtml(inp.name)} (${escapeHtml(inp.type)})</span>`).join(' ')
        ).join(' ');
        unlockedHtml = `<div style="background:rgba(16, 185, 129, 0.14); border:1px solid rgba(16, 185, 129, 0.4); color:#34d399; padding:0.65rem 0.8rem; border-radius:8px; font-size:0.83rem; margin-bottom:0.65rem;">
            <b>[+] Giriş / Sayfa Sonrası Tespit Edilen Yeni Formlar ve Inputlar:</b><br/>
            <div style="margin-top:0.35rem;">${innerBadges}</div>
          </div>`;
      }

      let cookiesHtml = '';
      if (item.session_cookies && Object.keys(item.session_cookies).length > 0) {
        const cookieBadges = Object.entries(item.session_cookies)
          .map(([k, v]) => `<span class="badge badge-ok mono">${escapeHtml(k)}=${escapeHtml(v)}</span>`)
          .join(' ');
        cookiesHtml = `<div style="margin-bottom:0.55rem; font-size:0.82rem;">
            <b>Aktif Oturum Çerezleri / Tokenlar (Session):</b> ${cookieBadges}
          </div>`;
      }

      return `
        <div class="finding-box" style="margin-top:0.75rem;">
          ${authHintHtml}
          ${unlockedHtml}
          ${cookiesHtml}
          <div style="display:flex; justify-content:space-between; flex-wrap:wrap; gap:0.5rem; margin-bottom:0.5rem;">
            <div>
              <b>HTTP Durum:</b> <span class="badge badge-ok">${item.status_code}</span>
              • <b>Süre:</b> ${item.elapsed_ms} ms
              • <b>Boyut:</b> ${item.response_length} B
            </div>
            <div>
              ${item.page_title ? `<span class="badge badge-inj">Başlık: ${escapeHtml(item.page_title)}</span>` : ''}
            </div>
          </div>

          <div style="font-size:0.84rem; margin-bottom:0.35rem;">
            <div><b>İstek Atılan Adres:</b> <span class="mono">${escapeHtml(item.target_url)}</span></div>
            <div><b>Güncel / Yenilenen Sayfa Adresi:</b> <span class="mono" style="color:#34d399; font-weight:600;">${escapeHtml(finalUrl)}</span>
              ${redirected ? '<span class="badge badge-med">Sayfa Yönlendirildi</span>' : ''}
            </div>
            ${redirectsInfo}
          </div>

          <div style="font-size:0.83rem; margin-bottom:0.65rem;">
            <b>Yanıtta Yansıyan Inputlar:</b> ${item.reflected_inputs && item.reflected_inputs.length ? `<span class="badge badge-med">${escapeHtml(item.reflected_inputs.join(', '))}</span>` : 'Yok'}
            &nbsp;|&nbsp;
            <b>Veritabanı Hataları:</b> ${item.db_errors && item.db_errors.length ? `<span class="badge badge-high">${escapeHtml(item.db_errors.join(', '))}</span>` : 'Yok'}
          </div>

          <div class="tabs" style="margin-bottom:0.6rem;">
            <button type="button" class="tab-btn active" onclick="switchSubTab('${prefix}', 'visual', this)">1. Güncel Sayfa Görünümü (Canlı Önizleme)</button>
            <button type="button" class="tab-btn" onclick="switchSubTab('${prefix}', 'text', this)">2. Sayfadaki Görünür Metin / Cevap</button>
            <button type="button" class="tab-btn" onclick="switchSubTab('${prefix}', 'raw', this)">3. Ham HTML Kaynak Kodu & Başlıklar</button>
          </div>

          <div id="${prefix}_visual" style="display:block;">
            <iframe id="${prefix}_iframe" class="preview-iframe" sandbox=""></iframe>
          </div>

          <div id="${prefix}_text" style="display:none;">
            <div class="code-snippet" style="max-height:380px; overflow-y:auto; white-space:pre-wrap;">${escapeHtml(item.response_text_summary || 'Görünür metin bulunamadı.')}</div>
          </div>

          <div id="${prefix}_raw" style="display:none;">
            <div style="font-size:0.78rem; color:var(--text-muted); margin-bottom:0.25rem;">HTTP Yanıt Başlıkları (Response Headers):</div>
            <div class="code-snippet" style="max-height:140px; overflow-y:auto; white-space:pre-wrap;">${escapeHtml(headersText)}</div>
            <div style="font-size:0.78rem; color:var(--text-muted); margin:0.5rem 0 0.25rem;">HTML Kaynak Kodu:</div>
            <div class="code-snippet" style="max-height:320px; overflow-y:auto; white-space:pre-wrap;">${escapeHtml(item.response_html || '')}</div>
          </div>
        </div>
      `;
    }

    function populatePreviewIframe(prefix, item) {
      const iframe = document.getElementById(prefix + '_iframe');
      if (!iframe) return;
      const baseUrl = item.final_url || item.target_url || '';
      const rawHtml = item.response_html || '<p style="font-family:sans-serif;padding:1rem;">Boş yanıt döndü.</p>';
      const baseTag = baseUrl ? `<base href="${escapeHtml(baseUrl)}">` : '';
      iframe.srcdoc = baseTag + rawHtml;
    }

    function switchSubTab(prefix, subName, btnEl) {
      ['visual', 'text', 'raw'].forEach(name => {
        const el = document.getElementById(prefix + '_' + name);
        if (el) el.style.display = (name === subName) ? 'block' : 'none';
      });
      if (btnEl && btnEl.parentElement) {
        btnEl.parentElement.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        btnEl.classList.add('active');
      }
    }

    function openResponseDetailModal(logIdx) {
      if (!lastScanData || !lastScanData.input_requests || !lastScanData.input_requests.logs) return;
      const item = lastScanData.input_requests.logs[logIdx];
      if (!item) return;

      const sentList = Object.entries(item.sent_params || {})
        .map(([k, v]) => `<span class="badge badge-inj">${escapeHtml(k)} = ${escapeHtml(v)}</span>`)
        .join(' ');

      const modalBody = document.getElementById('modalBody');
      modalBody.innerHTML = `
        <div style="margin-bottom:0.5rem; font-size:0.85rem;">
          <b>Gönderilen Inputlar (${escapeHtml(item.method)}):</b> ${sentList}
        </div>
        ${buildResponseViewerHtml(item, 'logmodal')}
      `;
      document.getElementById('customReqModal').style.display = 'flex';
      populatePreviewIframe('logmodal', item);
    }

    function renderRequesterTab(logs) {
      const container = document.getElementById('requesterContainer');
      if (!logs || logs.length === 0) {
        container.innerHTML = `<div class="empty-state">Gönderilmiş HTTP girdi isteği bulunmuyor. Sol panelden "Bulunan tüm inputlara test isteği gönder" seçeneğini işaretleyip tarama yapabilirsiniz.</div>`;
        return;
      }

      let html = `<div class="table-wrap"><table><thead><tr>
        <th>Tür / Metod</th>
        <th>İstek Atılan & Güncel Sayfa (URL)</th>
        <th>Gönderilen Input Değerleri</th>
        <th>Durum / Süre / Boyut</th>
        <th>Güncel Sayfa Cevap Özeti</th>
        <th>İşlem</th>
      </tr></thead><tbody>`;

      logs.forEach((item, idx) => {
        const mBadge = item.method === 'POST' ? 'badge-post' : 'badge-get';
        const paramsHtml = Object.entries(item.sent_params || {})
          .map(([k, v]) => `<div><span class="mono"><b>${escapeHtml(k)}</b>: ${escapeHtml(v)}</span></div>`)
          .join('');

        let statusHtml = '';
        if (item.error_message) {
          statusHtml = `<span class="badge badge-high">HATA</span><div style="font-size:0.78rem; color:var(--danger)">${escapeHtml(item.error_message)}</div>`;
        } else {
          const sBadge = (item.status_code >= 200 && item.status_code < 400) ? 'badge-ok' : 'badge-med';
          statusHtml = `<span class="badge ${sBadge}">HTTP ${item.status_code}</span>
            <div style="font-size:0.78rem; color:var(--text-muted); margin-top:0.25rem;">
              ${item.elapsed_ms} ms • ${item.response_length} B
            </div>`;
        }

        const finalUrl = item.final_url || item.target_url;
        const redirected = finalUrl && finalUrl !== item.target_url;
        const urlHtml = `
          <div><b>Hedef:</b> ${escapeHtml(item.target_url)}</div>
          <div style="color:#34d399; font-size:0.78rem; margin-top:0.15rem;">
            <b>Güncel Sayfa:</b> ${escapeHtml(finalUrl)}
            ${redirected ? '<span class="badge badge-med">Yönlendirildi</span>' : ''}
          </div>
          ${item.page_title ? `<div style="color:var(--text-muted); font-size:0.76rem;">Başlık: ${escapeHtml(item.page_title)}</div>` : ''}
        `;

        let analysisHtml = '';
        if (item.reflected_inputs && item.reflected_inputs.length > 0) {
          analysisHtml += `<div><span class="badge badge-med">Yansıyan: ${escapeHtml(item.reflected_inputs.join(', '))}</span></div>`;
        }
        if (item.db_errors && item.db_errors.length > 0) {
          analysisHtml += `<div><span class="badge badge-high">DB Hatası: ${escapeHtml(item.db_errors.join(', '))}</span></div>`;
        }
        const shortText = (item.response_text_summary || '').split('\n').slice(0, 3).join(' • ').slice(0, 140);
        if (shortText) {
          analysisHtml += `<div style="font-size:0.78rem; color:var(--text-muted); margin-top:0.2rem;">${escapeHtml(shortText)}...</div>`;
        } else if (!analysisHtml) {
          analysisHtml = `<span style="color:var(--text-muted); font-size:0.8rem;">Normal Yanıt</span>`;
        }

        html += `<tr>
          <td>
            <span class="badge badge-fixed">${escapeHtml(item.source_type)}</span>
            <span class="badge ${mBadge}">${escapeHtml(item.method)}</span>
          </td>
          <td class="mono">${urlHtml}</td>
          <td>${paramsHtml}</td>
          <td>${statusHtml}</td>
          <td>${analysisHtml}</td>
          <td>
            <button class="btn btn-sm" onclick="openResponseDetailModal(${idx})">Cevabı & Güncel Sayfayı Gör</button>
          </td>
        </tr>`;
      });

      html += `</tbody></table></div>`;
      container.innerHTML = html;
    }

    let currentSiteMapFilter = 'all';

    function setSiteMapFilter(filterMode) {
      currentSiteMapFilter = filterMode;
      if (lastScanData && lastScanData.crawl) {
        renderPagesTab(lastScanData.crawl);
      }
    }

    function openPageActionButtonsHtml(pageUrl, crawl) {
      const forms = crawl.forms || [];
      const paramUrls = crawl.param_urls || [];
      const btns = [];

      forms.forEach((f, idx) => {
        if (f.page_url === pageUrl || f.action === pageUrl) {
          const label = f.is_login_form ? 'Login İsteği At' : `Form İsteği At (${(f.method || 'GET').toUpperCase()})`;
          btns.push(`<button class="btn btn-sm" style="margin:0.15rem;" onclick="openFormRequestModal(${idx})">${escapeHtml(label)}</button>`);
        }
      });

      paramUrls.forEach((pu, idx) => {
        if (pu.url === pageUrl || pu.full_url === pageUrl || pageUrl.startsWith(pu.url + '?')) {
          btns.push(`<button class="btn btn-sm btn-secondary" style="margin:0.15rem;" onclick="openParamRequestModal(${idx})">GET Param İsteği At</button>`);
        }
      });

      if (btns.length === 0) {
        return '<span style="color:var(--text-muted); font-size:0.78rem;">-</span>';
      }
      return btns.join(' ');
    }

    function renderPagesTab(crawl) {
      const container = document.getElementById('pagesContainer');
      const pages = crawl.pages || [];
      const inputPages = pages.filter(p => p.has_inputs);
      const loginPages = pages.filter(p => p.is_login_page);
      let html = '';

      if (crawl.disallowed_paths && crawl.disallowed_paths.length > 0) {
        html += `<div style="margin-bottom:1.1rem; padding:0.75rem 1rem; background:rgba(245, 158, 11, 0.08); border:1px solid rgba(245, 158, 11, 0.25); border-radius:8px;">
          <div style="font-size:0.84rem; font-weight:600; color:#fbbf24; margin-bottom:0.35rem;">robots.txt / sitemap.xml Üzerinden Keşfedilen Özel Yollar (${crawl.disallowed_paths.length})</div>
          <div>${crawl.disallowed_paths.map(p => `<span class="badge badge-med mono" style="margin:0.1rem;">${escapeHtml(p)}</span>`).join(' ')}</div>
        </div>`;
      }

      if (pages.length === 0) {
        html += `<div class="empty-state">Keşfedilen sayfa yok.</div>`;
        container.innerHTML = html;
        return;
      }

      // BÖLÜM 1: HARİTADAN SEÇİLEN İÇİNE INPUT ALABİLEN ADRESLER LİSTESİ
      html += `<div style="margin-bottom:1.6rem;">
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem; margin-bottom:0.65rem;">
          <h3 style="font-size:0.98rem; color:#34d399; margin:0;">
            ★ 1. Haritadan Seçilen İçine Input Alabilen Adresler (${inputPages.length} Adres)
          </h3>
          <span style="font-size:0.8rem; color:var(--text-muted);">
            Toplam ${pages.length} site adresinden içine form, input, arama kutusu, login ekranı veya GET parametresi alabilenler
          </span>
        </div>`;

      if (inputPages.length === 0) {
        html += `<div class="empty-state" style="padding:1.1rem;">Taranan ${pages.length} adresin hiçbirinde dışarıdan veri/input alan bir form veya parametre tespit edilmedi.</div>`;
      } else {
        html += `<div class="table-wrap"><table><thead><tr>
          <th>#</th>
          <th>Durum & Tür</th>
          <th>Input Alabilen Adres (URL) & Başlık</th>
          <th>Kabul Edilen Inputlar (Girdi Detayları)</th>
          <th>İşlem</th>
        </tr></thead><tbody>`;

        inputPages.forEach((p, idx) => {
          const sBadge = (p.status_code >= 200 && p.status_code < 300) ? 'badge-ok' : 'badge-med';
          const loginBadge = p.is_login_page
            ? `<div style="margin-top:0.25rem;"><span class="badge badge-high">LOGIN / GİRİŞ EKRANI</span></div>`
            : `<div style="margin-top:0.25rem;"><span class="badge badge-inj">${p.input_count || 1} GİRDİ ALANI</span></div>`;

          const detailsHtml = (p.input_details && p.input_details.length)
            ? p.input_details.map(d => `<div style="margin-bottom:0.25rem;"><span class="badge badge-fixed mono" style="white-space:normal; text-align:left;">${escapeHtml(d)}</span></div>`).join('')
            : '<span class="badge badge-inj">Girdi Alanı Mevcut</span>';

          html += `<tr style="background:rgba(16, 185, 129, 0.04);">
            <td class="mono"><b>${idx + 1}</b></td>
            <td>
              <span class="badge ${sBadge}">HTTP ${p.status_code}</span>
              ${loginBadge}
            </td>
            <td class="mono">
              <div><a href="${escapeHtml(p.url)}" target="_blank" rel="noopener" style="color:#60a5fa; text-decoration:none; font-weight:600;">${escapeHtml(p.url)}</a></div>
              ${p.title ? `<div style="color:var(--text-muted); font-size:0.77rem; margin-top:0.15rem;">Sayfa Başlığı: ${escapeHtml(p.title)}</div>` : ''}
            </td>
            <td>${detailsHtml}</td>
            <td>${openPageActionButtonsHtml(p.url, crawl)}</td>
          </tr>`;
        });

        html += `</tbody></table></div>`;
      }
      html += `</div>`;

      // BÖLÜM 2: SİTENİN TAM ADRES HARİTASI (SITE MAP)
      let filteredPages = pages;
      if (currentSiteMapFilter === 'inputs') {
        filteredPages = inputPages;
      } else if (currentSiteMapFilter === 'logins') {
        filteredPages = loginPages;
      }

      html += `<div>
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.6rem; margin-bottom:0.65rem;">
          <h3 style="font-size:0.96rem; margin:0;">
            2. Sitenin Tam Adres Haritası (${filteredPages.length} / ${pages.length} Sayfa)
          </h3>
          <div style="display:flex; gap:0.4rem; flex-wrap:wrap;">
            <button type="button" class="btn btn-sm ${currentSiteMapFilter === 'all' ? '' : 'btn-secondary'}" onclick="setSiteMapFilter('all')">
              Tüm Harita (${pages.length})
            </button>
            <button type="button" class="btn btn-sm ${currentSiteMapFilter === 'inputs' ? '' : 'btn-secondary'}" onclick="setSiteMapFilter('inputs')">
              Sadece Input Alabilenler (${inputPages.length})
            </button>
            <button type="button" class="btn btn-sm ${currentSiteMapFilter === 'logins' ? '' : 'btn-secondary'}" onclick="setSiteMapFilter('logins')">
              Login Ekranları (${loginPages.length})
            </button>
          </div>
        </div>

        <div class="table-wrap"><table><thead><tr>
          <th>#</th>
          <th>Durum</th>
          <th>Derinlik</th>
          <th>Sayfa / Dosya Adresi (URL)</th>
          <th>Input Alabiliyor mu?</th>
          <th>İçerdiği Input Özeti</th>
          <th>İşlem</th>
        </tr></thead><tbody>`;

      filteredPages.forEach((p, idx) => {
        const sBadge = (p.status_code >= 200 && p.status_code < 300) ? 'badge-ok' : 'badge-med';
        const inputStatusHtml = p.has_inputs
          ? `<span class="badge badge-ok">EVET (${p.input_count || 1} Input)</span>${p.is_login_page ? ' <span class="badge badge-high">LOGIN</span>' : ''}`
          : `<span class="badge badge-fixed" style="opacity:0.65;">Hayır (Statik)</span>`;

        const summaryHtml = (p.input_details && p.input_details.length)
          ? `<span class="mono" style="font-size:0.78rem; color:#a7f3d0;">${escapeHtml(p.input_details.join(' | '))}</span>`
          : `<span style="color:var(--text-muted); font-size:0.78rem;">-</span>`;

        html += `<tr>
          <td class="mono">${idx + 1}</td>
          <td><span class="badge ${sBadge}">${p.status_code}</span></td>
          <td>Seviye ${p.depth}</td>
          <td class="mono">
            <div><a href="${escapeHtml(p.url)}" target="_blank" rel="noopener" style="color:var(--text); text-decoration:none;">${escapeHtml(p.url)}</a></div>
            ${p.title ? `<div style="color:var(--text-muted); font-size:0.75rem;">${escapeHtml(p.title)}</div>` : ''}
          </td>
          <td>${inputStatusHtml}</td>
          <td>${summaryHtml}</td>
          <td>${openPageActionButtonsHtml(p.url, crawl)}</td>
        </tr>`;
      });

      html += `</tbody></table></div></div>`;

      container.innerHTML = html;
    }

    function renderSecurityTab(audit) {
      const container = document.getElementById('securityContainer');
      const allFindings = [...(audit.passive_findings || [])];

      if (allFindings.length === 0) {
        container.innerHTML = `<div class="empty-state">Herhangi bir kara kutu SQLi veya web güvenlik bulgusu bulunmuyor.</div>`;
        return;
      }

      let html = `<h3 style="font-size:0.95rem; margin-bottom:0.75rem;">Tespit Edilen Kara Kutu Güvenlik Bulguları (${allFindings.length})</h3>`;
      allFindings.forEach(f => {
        const sevBadge = f.severity === 'YÜKSEK' ? 'badge-high' : (f.severity === 'ORTA' ? 'badge-med' : 'badge-low');
        html += `<div class="finding-box">
          <div class="finding-header">
            <div>
              <span class="badge ${sevBadge}">${escapeHtml(f.severity)}</span>
              <span class="badge badge-fixed">${escapeHtml(f.category)}</span>
              <strong style="margin-left:0.35rem;">${escapeHtml(f.cwe)}</strong>
            </div>
            <span class="mono" style="color:var(--text-muted)">${escapeHtml(f.location)}</span>
          </div>
          <div style="font-size:0.84rem; margin-bottom:0.3rem;"><b>İlgili Parametre / Input:</b> <span class="mono">${escapeHtml(f.parameter)}</span></div>
          <div class="code-snippet">${escapeHtml(f.evidence)}</div>
          <div style="font-size:0.83rem; color:#a7f3d0;"><b>Çözüm Önerisi:</b> ${escapeHtml(f.remediation)}</div>
        </div>`;
      });

      container.innerHTML = html;
    }

    function openFormRequestModal(formIdx) {
      if (!lastScanData || !lastScanData.crawl) return;
      const form = lastScanData.crawl.forms[formIdx];
      if (!form) return;

      let fieldsHtml = '';
      form.inputs.forEach(inp => {
        fieldsHtml += `<div class="form-group">
          <label>${escapeHtml(inp.name)} <small>(${escapeHtml(inp.type)} - ${inp.is_injectable ? 'Test Edilebilir' : 'Sabit'})</small></label>
          <input type="text" class="form-control custom-req-input" data-name="${escapeHtml(inp.name)}" value="${escapeHtml(inp.value || 'test_deger')}" />
        </div>`;
      });

      const modalBody = document.getElementById('modalBody');
      modalBody.innerHTML = `
        <div style="margin-bottom:0.8rem; font-size:0.85rem;">
          <div><b>Hedef Adres:</b> <span class="mono">${escapeHtml(form.action)}</span></div>
          <div><b>Metod:</b> <span class="badge badge-get">${escapeHtml(form.method.toUpperCase())}</span></div>
        </div>
        ${fieldsHtml}
        <button class="btn" onclick="sendSingleCustomRequest('${escapeHtml(form.action)}', '${escapeHtml(form.method)}')">İsteği Gönder</button>
        <div id="singleReqResult" style="margin-top:1rem;"></div>
      `;
      document.getElementById('customReqModal').style.display = 'flex';
    }

    function openParamRequestModal(paramIdx) {
      if (!lastScanData || !lastScanData.crawl) return;
      const pUrl = lastScanData.crawl.param_urls[paramIdx];
      if (!pUrl) return;

      let fieldsHtml = '';
      Object.entries(pUrl.params || {}).forEach(([k, v]) => {
        fieldsHtml += `<div class="form-group">
          <label>${escapeHtml(k)} <small>(GET Parametresi)</small></label>
          <input type="text" class="form-control custom-req-input" data-name="${escapeHtml(k)}" value="${escapeHtml(v)}" />
        </div>`;
      });

      const modalBody = document.getElementById('modalBody');
      modalBody.innerHTML = `
        <div style="margin-bottom:0.8rem; font-size:0.85rem;">
          <div><b>Hedef Adres:</b> <span class="mono">${escapeHtml(pUrl.url)}</span></div>
          <div><b>Metod:</b> <span class="badge badge-get">GET</span></div>
        </div>
        ${fieldsHtml}
        <button class="btn" onclick="sendSingleCustomRequest('${escapeHtml(pUrl.url)}', 'get')">İsteği Gönder</button>
        <div id="singleReqResult" style="margin-top:1rem;"></div>
      `;
      document.getElementById('customReqModal').style.display = 'flex';
    }

    function closeModal() {
      document.getElementById('customReqModal').style.display = 'none';
    }

    async function sendSingleCustomRequest(targetUrl, method) {
      const inputs = document.querySelectorAll('.custom-req-input');
      const params = {};
      inputs.forEach(el => {
        params[el.getAttribute('data-name')] = el.value;
      });

      const resBox = document.getElementById('singleReqResult');
      resBox.innerHTML = `<div style="color:var(--text-muted)">İstek gönderiliyor...</div>`;

      try {
        const res = await fetch('/api/send-input', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            base_url: document.getElementById('targetUrl').value.trim(),
            auth_type: document.getElementById('authType').value,
            cookie_str: document.getElementById('cookieStr').value.trim(),
            http_auth_user: document.getElementById('httpAuthUser').value.trim(),
            http_auth_pass: document.getElementById('httpAuthPass').value,
            target_url: targetUrl,
            method: method,
            params: params
          })
        });
        const data = await res.json();
        if (data.error || data.error_message) {
          resBox.innerHTML = `<div style="color:var(--danger)">Hata: ${escapeHtml(data.error || data.error_message)}</div>`;
          return;
        }
        resBox.innerHTML = buildResponseViewerHtml(data, 'singlemodal');
        populatePreviewIframe('singlemodal', data);
      } catch (err) {
        resBox.innerHTML = `<div style="color:var(--danger)">İstek hatası: ${escapeHtml(err.message)}</div>`;
      }
    }

    async function loadLogsList() {
      switchTab('tabLogs', document.querySelectorAll('.tab-btn')[4]);
      const container = document.getElementById('logsContainer');
      container.innerHTML = `<div class="empty-state">Loglar yükleniyor...</div>`;
      try {
        const res = await fetch('/api/logs');
        const data = await res.json();
        if (!data.logs || data.logs.length === 0) {
          container.innerHTML = `<div class="empty-state">logs/ klasöründe henüz rapor bulunamadı.</div>`;
          return;
        }
        let html = `<div class="table-wrap"><table><thead><tr><th>Rapor Dosyası</th><th>Boyut</th><th>İşlem</th></tr></thead><tbody>`;
        data.logs.forEach(l => {
          html += `<tr>
            <td class="mono">${escapeHtml(l.name)}</td>
            <td>${l.size} B</td>
            <td><button class="btn btn-sm btn-secondary" onclick="viewLogFile('${escapeHtml(l.name)}')">Görüntüle</button></td>
          </tr>`;
        });
        html += `</tbody></table></div><div id="logFileViewer" style="margin-top:1rem;"></div>`;
        container.innerHTML = html;
      } catch (err) {
        container.innerHTML = `<div class="empty-state">Loglar alınamadı: ${escapeHtml(err.message)}</div>`;
      }
    }

    async function viewLogFile(filename) {
      const viewer = document.getElementById('logFileViewer');
      viewer.innerHTML = `<div style="color:var(--text-muted)">Dosya okunuyor...</div>`;
      const res = await fetch('/api/logs?file=' + encodeURIComponent(filename));
      const data = await res.json();
      viewer.innerHTML = `<div class="code-snippet" style="max-height:420px; overflow-y:auto; white-space:pre-wrap;">${escapeHtml(data.content || '')}</div>`;
    }
  </script>
</body>
</html>
"""


class ScannerWebHandler(BaseHTTPRequestHandler):
    """Web arayüzü ve JSON API uç noktalarını yöneten HTTP işleyicisi."""

    def _send_json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html_text, status=200):
        body = html_text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format_str, *args):
        # Konsolu temiz tutmak için standart erişim loglarını sadeleştir
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send_html(HTML_TEMPLATE)
            return

        if parsed.path == "/api/logs":
            qs = parse_qs(parsed.query)
            logs_dir = "logs"
            os.makedirs(logs_dir, exist_ok=True)
            if "file" in qs:
                fname = os.path.basename(qs["file"][0])
                fpath = os.path.join(logs_dir, fname)
                if os.path.isfile(fpath):
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        self._send_json({"name": fname, "content": f.read()})
                else:
                    self._send_json({"error": "Dosya bulunamadı"}, status=404)
                return

            files = []
            for fn in sorted(os.listdir(logs_dir), reverse=True):
                fp = os.path.join(logs_dir, fn)
                if os.path.isfile(fp):
                    files.append({"name": fn, "size": os.path.getsize(fp)})
            self._send_json({"logs": files[:40]})
            return

        self._send_json({"error": "Bulunamadı"}, status=404)

    def do_POST(self):
        origin = (self.headers.get("Origin") or "").strip().lower()
        if origin:
            origin_host = urlparse(origin).hostname or ""
            if origin_host not in ("127.0.0.1", "localhost"):
                self._send_json({"error": "Yetkisiz istek kaynağı (Origin)"}, status=403)
                return

        parsed = urlparse(self.path)
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json({"error": "Geçersiz Content-Length başlığı"}, status=400)
            return

        if length < 0 or length > 5_000_000:
            self._send_json({"error": "Geçersiz istek boyutu"}, status=400)
            return

        raw_body = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else "{}"

        try:
            data = json.loads(raw_body)
        except json.JSONDecodeError:
            self._send_json({"error": "Geçersiz JSON verisi"}, status=400)
            return

        if parsed.path == "/api/scan":
            self._handle_scan(data)
            return

        if parsed.path == "/api/send-input":
            self._handle_single_input_request(data)
            return

        if parsed.path == "/api/auto-login":
            self._handle_auto_login(data)
            return

        self._send_json({"error": "Geçersiz API uç noktası"}, status=404)

    def _handle_auto_login(self, data):
        """Hedef sayfadaki login formunu/API'sini otomatik tespit edip Request üzerinden giriş yapar ve yanıtı döndürür."""
        target_raw = (data.get("target_url") or "").strip()
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""

        if not target_raw:
            self._send_json({"error": "Hedef URL eksik."}, status=400)
            return

        try:
            with _RELOAD_LOCK:
                importlib.reload(crawler_mod)
                importlib.reload(requester_mod)
                importlib.reload(main_mod)
            base_url = main_mod.normalize_url(target_raw)
            session = main_mod.build_session(
                base_url,
                http_user=username,
                http_pass=password,
                auto_login=True
            )
            login_log = getattr(session, "_auto_login_log", None)
            if login_log is None:
                requester = requester_mod.InputRequester(session=session)
                login_log = requester.perform_auto_login(base_url, username, password)
            self._send_json(dataclasses.asdict(login_log))
        except Exception as exc:
            traceback.print_exc()
            self._send_json({"error": str(exc)}, status=500)

    def _handle_scan(self, data):
        crawl_result = None
        req_report = None
        audit_report = None
        base_url = ""

        try:
            mode = str(data.get("mode") or "crawler")
            target_url = (data.get("target_url") or "").strip()
            auth_type = str(data.get("auth_type") or "none")
            cookie_str = (data.get("cookie_str") or "").strip()
            try:
                max_pages = max(1, min(int(data.get("max_pages") or 100), 1000))
                max_depth = max(1, min(int(data.get("max_depth") or 5), 15))
            except (TypeError, ValueError):
                self._send_json({"error": "Maks. sayfa ve derinlik değerleri sayı olmalıdır."}, status=400)
                return

            send_requests = bool(data.get("send_requests", False))
            custom_test_val = data.get("custom_test_value")
            if custom_test_val == "":
                custom_test_val = None

            # Alt modüllerde yapılan kod güncellemelerinin sunucu yeniden başlatılmadan da aktif olmasını sağla
            with _RELOAD_LOCK:
                importlib.reload(crawler_mod)
                importlib.reload(requester_mod)
                importlib.reload(sqli_mod)
                importlib.reload(main_mod)

            # 1. Web Crawler ve Oturum Hazırlığı
            if mode in ("full", "crawler", "requester", "sqli-passive", "sqli"):
                if not target_url:
                    self._send_json({"error": "Lütfen geçerli bir Hedef URL girin."}, status=400)
                    return

                base_url = main_mod.normalize_url(target_url)
                use_dvwa = (auth_type == "dvwa")
                c_str = cookie_str if auth_type == "cookie" else None
                h_user = (data.get("http_auth_user") or "").strip() if auth_type in ("http-auth", "auto-login") else None
                h_pass = (data.get("http_auth_pass") or "") if auth_type in ("http-auth", "auto-login") else None
                is_auto_login = (auth_type == "auto-login")

                try:
                    session = main_mod.build_session(
                        base_url,
                        use_dvwa_login=use_dvwa,
                        cookie_str=c_str,
                        http_user=h_user,
                        http_pass=h_pass,
                        auto_login=is_auto_login
                    )
                except requests.RequestException as exc:
                    self._send_json({"error": f"Hedef sunucuya bağlanılamadı ({base_url}): {exc}"}, status=400)
                    return

                crawler = crawler_mod.Crawler(base_url, session=session, max_pages=max_pages, max_depth=max_depth)
                crawl_result = crawler.crawl()

                # 2. Input Requester (Keşfedilen inputlara istek gönderme)
                if send_requests or mode == "requester":
                    requester = requester_mod.InputRequester(session=session, custom_test_value=custom_test_val)
                    req_report = requester.send_all_from_crawl(crawl_result)

                # Eğer Auto-Login yapıldıysa, Auto-Login isteğinin kaydını da Input İstek Sonuçlarının en başına ekle
                auto_login_log = getattr(session, "_auto_login_log", None) if session else None
                if auto_login_log is not None:
                    if req_report is None:
                        req_report = requester_mod.InputRequestReport()
                    req_report.logs.insert(0, auto_login_log)

            # 3. Kara Kutu (Black-Box) SQLi ve Web Güvenlik Denetimi
            analyzer = sqli_mod.HybridSQLiAnalyzer()
            if mode in ("sqli-passive", "sqli", "full", "requester"):
                audit_report = analyzer.run_hybrid_audit(crawl_result=crawl_result, req_report=req_report)

            # 4. Raporu logs/ klasörüne kaydet
            log_file = main_mod.save_report_to_log(
                mode_label=f"web_{mode}",
                base_url=base_url,
                max_pages=max_pages,
                max_depth=max_depth,
                crawl_result=crawl_result,
                audit_report=audit_report,
                req_report=req_report
            )

            response_payload = {
                "log_file": log_file,
                "crawl": dataclasses.asdict(crawl_result) if crawl_result else None,
                "input_requests": dataclasses.asdict(req_report) if req_report else None,
                "audit": dataclasses.asdict(audit_report) if audit_report else None,
            }
            self._send_json(response_payload)

        except Exception as exc:
            traceback.print_exc()
            self._send_json({"error": str(exc)}, status=500)

    def _handle_single_input_request(self, data):
        """Arayüzdeki 'Özel İstek At' modalından gelen tekil form/URL isteğini yürütür."""
        base_raw = (data.get("base_url") or data.get("target_url") or "").strip()
        auth_type = data.get("auth_type", "none")
        cookie_str = (data.get("cookie_str") or "").strip()
        target_url = (data.get("target_url") or "").strip()
        method = (data.get("method") or "get").lower()
        params = data.get("params") or {}

        if not target_url:
            self._send_json({"error": "Hedef URL eksik."}, status=400)
            return

        try:
            with _RELOAD_LOCK:
                importlib.reload(crawler_mod)
                importlib.reload(requester_mod)
                importlib.reload(main_mod)
            base_url = main_mod.normalize_url(base_raw)
            h_user = (data.get("http_auth_user") or "").strip() if auth_type in ("http-auth", "auto-login") else None
            h_pass = (data.get("http_auth_pass") or "") if auth_type in ("http-auth", "auto-login") else None
            session = main_mod.build_session(
                base_url,
                use_dvwa_login=(auth_type == "dvwa"),
                cookie_str=(cookie_str if auth_type == "cookie" else None),
                http_user=h_user,
                http_pass=h_pass,
                auto_login=(auth_type == "auto-login")
            )
            requester = requester_mod.InputRequester(session=session)
            inputs = [
                crawler_mod.InputField(name=k, type="text", value=str(v), is_injectable=True)
                for k, v in params.items()
            ]
            form = crawler_mod.FormInfo(page_url=target_url, action=target_url, method=method, inputs=inputs)
            log_item = requester.send_form_request(form)
            res_dict = dataclasses.asdict(log_item)
            self._send_json(res_dict)
        except Exception as exc:
            self._send_json({"error": str(exc)}, status=500)


def run_web_server(host="127.0.0.1", port=5000, open_browser=False):
    """Web arayüzü sunucusunu başlatır."""
    server = ThreadingHTTPServer((host, port), ScannerWebHandler)
    url = f"http://{host}:{port}"
    print("=" * 65)
    print("  OTOMATİK ZAFİYET TARAYICI — WEB ARAYÜZÜ AKTİF")
    print(f"  Tarayıcı Adresi : {url}")
    print("  Durdurmak için  : Ctrl+C")
    print("=" * 65)
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Web sunucusu kapatılıyor...")
        server.server_close()


def main():
    parser = argparse.ArgumentParser(description="Otomatik Zafiyet Tarayıcı Web Arayüzü")
    parser.add_argument("--host", default="127.0.0.1", help="Sunucu adresi (Varsayılan: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Port numarası (Varsayılan: 5000)")
    parser.add_argument("--open", action="store_true", help="Başlangıçta tarayıcıyı otomatik aç")
    args = parser.parse_args()
    run_web_server(host=args.host, port=args.port, open_browser=args.open)


if __name__ == "__main__":
    main()
