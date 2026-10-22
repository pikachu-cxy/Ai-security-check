<?php
$cmd = $_GET["cmd"];
// ruleid: ai-security.php.command-injection
system($cmd);
// ruleid: ai-security.php.command-injection
shell_exec($_POST["cmd"]);
// ok: ai-security.php.command-injection
system("date");
// ok: ai-security.php.command-injection
exec("whoami");
$parts = explode('.', $_GET['ip']);
if (is_numeric($parts[0]) && is_numeric($parts[1]) && is_numeric($parts[2]) && is_numeric($parts[3]) && sizeof($parts) == 4) {
    $target = $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.' . $parts[3];
    // ok: ai-security.php.command-injection
    shell_exec('ping ' . $target);
    $target = $_GET['again'];
    // ruleid: ai-security.php.command-injection
    shell_exec('ping ' . $target);
}
if (is_numeric($parts[0]) && sizeof($parts) == 4) {
    $target = $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.' . $parts[3];
    // ruleid: ai-security.php.command-injection
    shell_exec('ping ' . $target);
}
if (is_numeric($parts[0]) && is_numeric($parts[1]) && is_numeric($parts[2]) && is_numeric($parts[3]) && sizeof($parts) == 4) {
    $parts[0] = $_GET['again'];
    $target = $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.' . $parts[3];
    // ruleid: ai-security.php.command-injection
    shell_exec('ping ' . $target);
}
