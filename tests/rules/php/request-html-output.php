<?php
$text = $_GET['name'];
// ruleid: ai-security.php.request-html-output
echo $text;
// ruleid: ai-security.php.request-html-output
echo $_POST['name'];
// ok: ai-security.php.request-html-output
echo htmlspecialchars($text, ENT_QUOTES, "UTF-8");
// ok: ai-security.php.request-html-output
echo "Welcome";
