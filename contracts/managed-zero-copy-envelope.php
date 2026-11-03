<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/** libsodium sealed candidate encryption only; no DB, node writer or REST route. */
final class SPRSB_Managed_Zero_Copy_Envelope {
    const ENVELOPE_CONTRACT = 'smart-pro-managed-zero-copy-sealed-identity-v1';
    const CONTENT_CONTRACT = 'smart-pro-managed-zero-copy-identity-content-v1';
    const MAX_TTL = 600;

    public static function seal_candidate( $installation_id, $request_ref, $receiver_public_hex, $node_id, $node_secret, $architecture, $issued_at, $expires_at ) {
        $installation_id = (string) $installation_id;
        $request_ref = (string) $request_ref;
        $receiver_public_hex = (string) $receiver_public_hex;
        $node_id = (string) $node_id;
        $node_secret = (string) $node_secret;
        $architecture = (string) $architecture;
        if ( ! function_exists( 'sodium_crypto_box_seal' )
            || ! preg_match( '/^ID-[0-9]{5}$/D', $installation_id )
            || ! preg_match( '/^SPMZ-[A-F0-9]{32}$/D', $request_ref )
            || ! preg_match( '/^[a-f0-9]{64}$/D', $receiver_public_hex )
            || ! preg_match( '/^SPMN-[A-F0-9]{32}$/D', $node_id )
            || ! preg_match( '/^SPMS-[A-Za-z0-9_-]{43}$/D', $node_secret )
            || ! in_array( $architecture, array( 'amd64', 'aarch64' ), true )
            || ! is_int( $issued_at ) || ! is_int( $expires_at )
            || $issued_at <= 0 || $expires_at <= $issued_at
            || $expires_at > $issued_at + self::MAX_TTL ) {
            return null;
        }
        try {
            $pub = hex2bin( $receiver_public_hex );
            $content = array(
                'contract' => self::CONTENT_CONTRACT,
                'installation_id' => $installation_id,
                'request_ref' => $request_ref,
                'receiver_public_key_hex' => $receiver_public_hex,
                'architecture' => $architecture,
                'issued_at' => $issued_at,
                'expires_at' => $expires_at,
                'node_id' => $node_id,
                'node_secret' => $node_secret,
            );
            $plaintext = json_encode( $content, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR );
            $cipher = sodium_crypto_box_seal( $plaintext, $pub );
            if ( ! is_string( $cipher ) || strlen( $cipher ) < 100 || strlen( $cipher ) > 2048 ) {
                return null;
            }
            return array(
                'contract' => self::ENVELOPE_CONTRACT,
                'installation_id' => $installation_id,
                'request_ref' => $request_ref,
                'receiver_public_key_hex' => $receiver_public_hex,
                'architecture' => $architecture,
                'issued_at' => $issued_at,
                'expires_at' => $expires_at,
                'sealed_box_hex' => bin2hex( $cipher ),
                'runtime_authorized' => false,
                'technician_access_granted' => false,
            );
        } catch ( Throwable $e ) {
            // No secret or exception text is ever logged.
            return null;
        }
    }
}
