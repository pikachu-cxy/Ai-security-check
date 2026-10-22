<?php
$sql = "SELECT * FROM users WHERE name = " . $_GET["name"];
// ruleid: ai-security.php.mysqli-query-injection
mysqli_query($db, $sql);
// ruleid: ai-security.php.mysqli-query-injection
mysqli_query($db, $_POST["query"]);
// ok: ai-security.php.mysqli-query-injection
mysqli_query($db, "SELECT * FROM users");
// ok: ai-security.php.mysqli-query-injection
mysqli_execute_query($db, "SELECT * FROM users WHERE name = ?", [$_GET["name"]]);
