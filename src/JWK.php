<?php

declare(strict_types=1);

namespace ValentinRgt\JWT;

use phpseclib3\Crypt\RSA;

class JWK
{
    public function __construct(
        public ?string $passphrase, 
        public ?string $key = null
    )
    {
        $this->passphrase = $passphrase;
        $this->key = $key;
    }

    public static function generatePassphrase(int $length = 12)
    {
        $letterLower = "abcdefghijklmnopqrstuvwxyz"; 
        $letterUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; 
        $number = "0123456789"; 
        $specialChar = "&~#'{([-|`_\^@)]=}*+*¨£%!§:/;.,?$";
        $split = str_split($letterLower.$letterUpper.$number.$specialChar);
        $result = "";
        for ($i=0; $i < $length; $i++) { 
            $result = $result.$split[mt_rand(0, count($split))];
        }
        return $result;
    }
}