<?php
$path = $_GET["page"];
// ruleid: ai-security.php.request-include
include $path;
// ruleid: ai-security.php.request-include
require_once $_POST["module"];
// ok: ai-security.php.request-include
include "header.php";
// ok: ai-security.php.request-include
require_once "bootstrap.php";
