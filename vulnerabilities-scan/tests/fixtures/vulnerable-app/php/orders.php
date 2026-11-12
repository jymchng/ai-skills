<?php
// Intentionally vulnerable PHP endpoints for the fixture.

function list_orders($db) {
    // php-sql-concat: statement interpolated with request data
    return $db->query("SELECT * FROM orders WHERE name = '$_GET[term]'");
}

function report() {
    // cmd-php: request data handed to a shell function
    system("tar -czf /tmp/report.tar " . $_GET['name']);
}

function download() {
    // path-traversal: request data used to build the path
    readfile("/srv/data/" . $_GET['file']);
}

function restore() {
    // unsafe-deserialization: untrusted input unserialized
    return unserialize($_POST['state']);
}

function greet() {
    // xss-response-request: request data echoed into the page
    echo $_GET['name'];
}

function render_note($order) {
    // xss-stored-unsafe: stored value printed without escaping
    echo $order;
}

function store_upload() {
    // upload-filename: stored under the client-supplied name
    move_uploaded_file($_FILES['file']['tmp_name'], "/srv/uploads/" . $_FILES['file']['name']);
}

function password_digest() {
    // weak-password-hashing: fast hash for a password
    return md5($password);
}

function promote() {
    // missing-authorization: role taken from the request
    $role = $_POST['role'];
    return $role;
}

function cors() {
    // permissive-cors: origin reflected from the request
    header('Access-Control-Allow-Origin: ' . $_SERVER['HTTP_ORIGIN']);
}

function session($token) {
    // weak-jwt-validation: no key, so no signature check
    return JWT::decode($token, null);
}
