<?php
$code = $_POST["code"];
// ruleid: ai-security.php.request-eval
eval($code);
// ruleid: ai-security.php.request-eval
eval($_GET["expression"]);
// ok: ai-security.php.request-eval
eval("return 1;");
