<?php

declare(strict_types=1);

namespace ValentinRgt\JWT;

class JWE
{

    public function __construct(string $algorithm, JWK $key)
    {
        $this->algorithm = JWA::from($algorithm);
        $this->key = $key;
    }

    public function sign(string $header, string $payload)
    {
        $token = $header.'.'.$payload;

        switch ($this->algorithm['alg']) {
            case 'HS256':
            case 'HS384':
            case 'HS512':
                return JWS::encode(hash_hmac($this->algorithm['hash'], $token, $this->key->passphrase, true));
                break;
            case 'RS256':
            case 'RS384':
            case 'RS512':
            case 'ES256':
            case 'ES384':
            case 'ES512':
            case 'PS256':
            case 'PS384':
            case 'PS512':
                $signature = "";
                openssl_sign($token, $signature, openssl_get_privatekey($this->key->key, $this->key->passphrase), $this->algorithm['hash']);
                return JWS::encode($signature);
                break;
        }

        return null;
    }

    public function verify(string $header, string $payload, string $signature)
    {
        $token = $header.'.'.$payload;

        switch ($this->algorithm['alg']) {
            case 'HS256':
            case 'HS384':
            case 'HS512':
                return hash_equals(hash_hmac($this->algorithm['hash'], $token, $this->key->passphrase, true), JWS::decode($signature));
                break;
            case 'RS256':
            case 'RS384':
            case 'RS512':
            case 'ES256':
            case 'ES384':
            case 'ES512':
            case 'PS256':
            case 'PS384':
            case 'PS512':
                return openssl_verify($token, JWS::decode($signature), $this->key->key, $this->algorithm['hash']);
                break;
        }

        return null;
    }
}