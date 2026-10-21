<?php
// Eğitim Amaçlı Örnek 2: Güvenli Parametreli Sorgu Kullanımı (DVWA Impossible Seviyesi Temsili)
// SAST motoru bu dosyadaki PDO Prepared Statement kullanımını güvenli olarak doğrular.

if (isset($_GET['Submit'])) {
    $id = $_GET['id'];

    if (is_numeric($id)) {
        // GÜVENLİ KULLANIM: PDO prepare ve bindParam ile SQL komutu ve veri ayrıştırılmış
        $data = $db->prepare('SELECT first_name, last_name FROM users WHERE user_id = (:id) LIMIT 1;');
        $data->bindParam(':id', $id, PDO::PARAM_INT);
        $data->execute();
    }
}
?>
