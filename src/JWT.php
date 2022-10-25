<?php

declare(strict_types=1);

namespace ValentinRgt\JWT;

use DateTime;

class JWT
{
    private array $header;
    private array $payload;
    private JWK $key;

    public function setAlgorithm(array $jwa): self
    {
        $this->header = ['alg' => $jwa['alg'], 'type' => 'JWT'];
        return $this;
    }

    public function setPayload(array $payload): self
    {
        $this->payload = $payload;
        return $this;
    }

    public function setKey(JWK $jwk): self
    {
        $this->key = $jwk;
        return $this;
    }

    public function encode()
    {
        $jwsHeader = JWS::toJson($this->header);
        $jwsPayload = JWS::toJson($this->payload);

        $jwe = new JWE($this->header['alg'], $this->key);
        $jweSignature = $jwe->sign($jwsHeader, $jwsPayload);

        return $jwsHeader.'.'.$jwsPayload.'.'.$jweSignature;
    }

    public function decode(string $token, JWK $key)
    {
        $token_output = explode('.', $token);

        if (count($token_output) != 3) {
            throw new \Exception('Wrong number of segments');
        }
        
        $jwtHeader = JWS::toText($token_output[0]);
        $jwtPayload = JWS::toText($token_output[1]);

        $jwe = new JWE($jwtHeader->alg, $key);
        if(!$jwe->verify($token_output[0], $token_output[1], $token_output[2])){
            throw new \Exception('Signature verification failed');
        }

        if (isset($jwtPayload->exp) && (new DateTime())->getTimestamp() >= $jwtPayload->exp){
            throw new \Exception('Expired token');
        }

        return $jwtPayload;
        
    }
}