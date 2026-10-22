<?php
$data = $_COOKIE["state"];
// ruleid: ai-security.php.unsafe-unserialize
unserialize($data);
// ruleid: ai-security.php.unsafe-unserialize
unserialize($_POST["state"]);
// ok: ai-security.php.unsafe-unserialize
json_decode($_POST["state"], true);
// ok: ai-security.php.unsafe-unserialize
unserialize("a:0:{}");
