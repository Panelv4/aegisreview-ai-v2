<?php
$page = $_GET['page'];
include($page . '.php');

if (isset($_POST['expr'])) {
    eval('$result = ' . $_POST['expr'] . ';');
}

$conn = new mysqli('db.internal', 'root', 'P@ssw0rd2024!', 'shop');
$q = "SELECT * FROM users WHERE name='" . $_GET['name'] . "'";
$conn->query($q);
