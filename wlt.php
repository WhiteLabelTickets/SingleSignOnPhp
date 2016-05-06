<?php

/**
 * @author   Mathieu Dupuis <mdupuis@whitelabeltickets.com>
 */
class WLTLoginToken
{

    /**
    * Create a Token for WhiteLabelTickets
    *
    * @param string $firstname      Firstname of the client to create on WhiteLabelTickets.com
    * @param string $lastname       Lastname of the client to create on WhiteLabelTickets.com
    * @param string $email          Email of the client to create on WhiteLabelTickets.com
    * @param string $secretKey      Shared secret between WhiteLabelTickets.com and website
    *
    * @return string An signed token to pass to WhiteLabelTickets.com
    */
    public static function createToken($firstname, $lastname, $email, $secretKey)
    {
        $json = sprintf('{"fn":"%s","ln":"%s","em":"%s"}', $firstname, $lastname, $email);
        print($json  . PHP_EOL);
        return WLTLoginToken::encode($json, $secretKey);
    }

    private function encode($payload, $key)
    {
        $segments = array();
        $segments[] = WLTLoginToken::urlsafeB64Encode($payload);
        $signing_input = implode('.', $segments);

        $signature = WLTLoginToken::sign($signing_input, $key);
        $segments[] = WLTLoginToken::urlsafeB64Encode($signature);

	print(rawurlencode($signature).PHP_EOL);

        return implode('.', $segments);
    }

    private function sign($msg, $key)
    {
        return hash_hmac('SHA256', $msg, $key, true);
    }

    private function urlsafeB64Encode($input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

}

// to test
//
// print(WLTLoginToken::createToken('Mathieu', 'Dupuis', 'mathd1@gmail.com', 'My ultra secret key') . PHP_EOL);
