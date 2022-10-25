<?php

declare(strict_types=1);

namespace ValentinRgt\JWT;

class JWA
{
    /** 
     * HMAC
     */
    const HS256 = ['alg' => 'HS256', 'hash' => 'SHA256'];
    const HS384 = ['alg' => 'HS384', 'hash' => 'SHA384'];
    const HS512 = ['alg' => 'HS512', 'hash' => 'SHA512'];

    /** 
     * RSA-PKCS1
     */
    const RS256 = ['alg' => 'RS256', 'hash' => 'id-rsassa-pkcs1-v1_5-with-sha3-256'];
    const RS384 = ['alg' => 'RS384', 'hash' => 'id-rsassa-pkcs1-v1_5-with-sha3-384'];
    const RS512 = ['alg' => 'RS512', 'hash' => 'id-rsassa-pkcs1-v1_5-with-sha3-512'];

    /** 
     * ECDSA
     */
    const ES256 = ['alg' => 'ES256', 'hash' => OPENSSL_ALGO_SHA256];
    const ES384 = ['alg' => 'ES384', 'hash' => OPENSSL_ALGO_SHA384];
    const ES512 = ['alg' => 'ES512', 'hash' => OPENSSL_ALGO_SHA512];

    /** 
     * RSA-PSS
     */
    const PS256 = ['alg' => 'PS256', 'hash' => OPENSSL_ALGO_SHA256];
    const PS384 = ['alg' => 'PS384', 'hash' => OPENSSL_ALGO_SHA384];
    const PS512 = ['alg' => 'PS512', 'hash' => OPENSSL_ALGO_SHA512];

    public static function from(string $name)
    {
        return constant("self::$name");
    }
}