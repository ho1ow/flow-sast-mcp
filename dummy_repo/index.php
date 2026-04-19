<?php
// PHP file for scanning semgrep and secrets

$db_password = "password123!"; // Secret for secrets_scan

$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id = " . $id; // SQLi for semgrep_scan
$result = $conn->query($sql);

echo "Hello " . $_GET['name']; // XSS
?>
