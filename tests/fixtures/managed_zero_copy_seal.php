<?php
define('ABSPATH', __DIR__);
require __DIR__ . '/../../contracts/managed-zero-copy-envelope.php';
$raw = json_decode(stream_get_contents(STDIN), true);
if (!is_array($raw)) { echo "{}"; exit(0); }
$result = SPRSB_Managed_Zero_Copy_Envelope::seal_candidate(
    $raw['installation_id'] ?? '', $raw['request_ref'] ?? '',
    $raw['receiver_public_key_hex'] ?? '',
    $raw['node_id'] ?? '', $raw['node_secret'] ?? '',
    $raw['architecture'] ?? '', $raw['issued_at'] ?? null,
    $raw['expires_at'] ?? null
);
echo json_encode($result ?: new stdClass(), JSON_UNESCAPED_SLASHES);
