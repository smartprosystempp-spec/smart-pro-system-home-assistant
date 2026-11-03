<?php
// Synthetic PHP Broker delivery fixture. Never ships in WordPress.
define( 'ABSPATH', __DIR__ );
require __DIR__ . '/../../contracts/managed-zero-copy-envelope.php';
$raw = json_decode( stream_get_contents( STDIN ), true );
if ( ! is_array( $raw ) ) { echo '{}'; exit; }
$iid = $raw['installation_id'] ?? '';
$ref = $raw['request_ref'] ?? '';
$pub = $raw['receiver_public_key_hex'] ?? '';
$arch = $raw['architecture'] ?? '';
$issued = $raw['issued_at'] ?? null;
$expires = $raw['expires_at'] ?? null;
$original = SPRSB_Managed_Zero_Copy_Envelope::seal_candidate(
    $iid, $ref, $pub, 'SPMN-' . str_repeat( 'B', 32 ),
    'SPMS-' . str_repeat( 'c', 43 ), $arch, $issued, $expires
);
if ( ! is_array( $original ) ) { echo '{}'; exit; }
$original_json = json_encode( $original, JSON_UNESCAPED_SLASHES );
$digest = hash( 'sha256', $original_json );
$end = min( $expires, $issued + 90 );
$nonce = str_repeat( 'd', 64 ); // FIXTURE ONLY — production uses random_bytes(32)
$inner = array(
    'contract' => 'smart-pro-managed-zero-copy-delivery-challenge-content-v1',
    'installation_id' => $iid, 'request_ref' => $ref,
    'receiver_public_key_hex' => $pub, 'architecture' => $arch,
    'envelope_sha256' => $digest,
    'issued_at' => $issued, 'expires_at' => $end, 'nonce_hex' => $nonce,
);
$cipher = sodium_crypto_box_seal(
    json_encode( $inner, JSON_UNESCAPED_SLASHES ), hex2bin( $pub )
);
$challenge = array(
    'contract' => 'smart-pro-managed-zero-copy-delivery-challenge-v1',
    'installation_id' => $iid, 'request_ref' => $ref,
    'receiver_public_key_hex' => $pub, 'architecture' => $arch,
    'envelope_sha256' => $digest,
    'issued_at' => $issued, 'expires_at' => $end,
    'sealed_box_hex' => bin2hex( $cipher ),
    'identity_created' => false, 'runtime_authorized' => false,
    'technician_access_granted' => false,
);
echo json_encode( array(
    'challenge' => $challenge,
    'original_envelope_json' => $original_json,
    'envelope_sha256' => $digest,
    'expected_proof' => hash( 'sha256', 'SPMZ1|delivery_proof|' . $iid . '|' . $ref
        . '|' . $pub . '|' . $digest . '|' . $nonce ),
), JSON_UNESCAPED_SLASHES );
