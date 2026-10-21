"""Eğitim Amaçlı Örnek 3: Python Veritabanı Sorgu Karşılaştırması (SAST Testi)."""
import sqlite3


def kullanici_getir_guvensiz(conn, user_id):
    cursor = conn.cursor()
    # GÜVENSİZ KULLANIM: f-string ile doğrudan SQL sorgu metnine ekleme (CWE-89)
    cursor.execute(f"SELECT id, username FROM users WHERE id = {user_id}")
    return cursor.fetchall()


def kullanici_getir_guvenli(conn, user_id):
    cursor = conn.cursor()
    # GÜVENLİ KULLANIM: Parametreli sorgu (Parameterized Query) kullanımı
    cursor.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
    return cursor.fetchall()
