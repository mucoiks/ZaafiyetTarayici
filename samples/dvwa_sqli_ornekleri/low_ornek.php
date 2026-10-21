<?php
// Eğitim Amaçlı Örnek 1: Güvensiz SQL Sorgu Birleştirme (DVWA Low Seviyesi Temsili)
// SAST motoru bu dosyadaki CWE-89 zafiyetini satır numarasıyla tespit eder.

if (isset($_REQUEST['Submit'])) {
    $id = $_REQUEST['id'];

    // GÜVENSİZ KULLANIM: Kullanıcı girdisi ($id) doğrudan SQL metnine birleştirilmiş
    $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
    $result = mysqli_query($GLOBALS["___mysqli_ston"], $query);
}
?>
