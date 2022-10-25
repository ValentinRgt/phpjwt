<?php

declare(strict_types=1);

namespace ValentinRgt\JWT;

class JWS
{
    public static function toJson(array $data)
    {
        return self::encode(json_encode($data));
    }

    public static function toText(string $data)
    {
        return json_decode(self::decode($data));
    }

    public static function encode(string $input) {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    public static function decode(string $input) {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }
}