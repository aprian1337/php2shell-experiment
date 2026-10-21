<?php
// PHP2Shell lab target — read-only status endpoint.
// Starts a session so upload-progress data can be read back for verification.
header('Content-Type: text/plain');
ini_set('session.use_cookies', '1');
session_start();

echo "PHP2Shell lab target\n";
echo "version=" . PHP_VERSION . "\n";
echo "upload_progress=" . (ini_get('session.upload_progress.enabled') ? 'On' : 'Off') . "\n";
echo "min_freq=" . ini_get('session.upload_progress.min_freq') . "\n";
echo "sid=" . session_id() . "\n";
echo "session=" . json_encode($_SESSION) . "\n";
