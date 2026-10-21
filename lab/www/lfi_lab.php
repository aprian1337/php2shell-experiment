<?php
// LAB ONLY — deliberate LFI sink for demonstrating Chain A (session poison + include)
// against THIS local lab. Never deploy outside an isolated research environment.
$page = $_GET['page'] ?? 'index.php';
echo "including: $page\n";
include $page;
