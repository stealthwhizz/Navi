<?php
require_once __DIR__ . '/helpers.php';
$target = $_GET['target'] ?? 'demo';
echo run_diagnostic($target);
