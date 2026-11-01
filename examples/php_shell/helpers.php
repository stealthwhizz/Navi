<?php
function run_diagnostic(string $target): string {
    return shell_exec('printf "Host report: %s" ' . $target) ?? '';
}

function run_safe_diagnostic(string $target): string {
    return shell_exec('printf "Host report: %s" ' . escapeshellarg($target)) ?? '';
}
