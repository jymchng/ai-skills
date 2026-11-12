<?php
// Secure look-alike of the PHP endpoints.

function list_orders($db) {
    // Prepared statement with a bound parameter.
    $stmt = $db->prepare("SELECT * FROM orders WHERE name = ?");
    $stmt->execute([$_GET['term']]);
    return $stmt->fetchAll();
}

function report() {
    // The single variable part is escaped on the line where it is used.
    system("tar -czf /tmp/report.tar " . escapeshellarg($_GET['name']));
}

function download() {
    // Basename only, confined to the data root.
    $name = basename($_GET['file']);
    readfile("/srv/data/" . $name);
}

function restore() {
    // Structured JSON, not unserialize.
    return json_decode($_POST['state'], true);
}

function greet() {
    // Escaped before output.
    echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
}

function render_note($order) {
    // Escaped before output.
    echo htmlspecialchars($order, ENT_QUOTES, 'UTF-8');
}

function store_upload() {
    // Generated name, allow-listed extension.
    $name = basename($_FILES['file']['name']);
    $allowed_ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    if (!in_array($allowed_ext, ALLOWED_EXTENSIONS, true)) {
        return false;
    }
    return move_uploaded_file($_FILES['file']['tmp_name'], "/srv/uploads/" . bin2hex(random_bytes(16)) . '.' . $allowed_ext);
}

function password_digest() {
    // Adaptive hash.
    return password_hash($password, PASSWORD_ARGON2ID);
}

function promote() {
    // The role comes from the stored session.
    return $_SESSION['role'];
}

function cors() {
    // Explicit origin allow-list.
    header('Access-Control-Allow-Origin: https://app.example.com');
}

function session($token) {
    // Verified with the configured key and algorithm.
    return JWT::decode($token, $key, ['RS256']);
}
