<?php

namespace derrickleemy\Auth;

use \Carbon\Carbon;
use \Firebase\JWT\JWT;
use CoderCat\JWKToPEM\JWKConverter;
use \GuzzleHttp\Client;

/**
 * Class CognitoToken
 *
 * @property string $token_id
 * @property string $user_id
 * @property boolean $expecting
 * @property int $start_at_unix
 * @property string $start_at
 * @property boolean $incorrect
 * @property int $created_at_unix
 * @property string $created_at
 * @property boolean $expired
 * @property int $expires_at_unix
 * @property string $expires_at
 * @property boolean $error
 * @property array $errors
 * @property boolean $valid
 *
 * @package derrickleemy\Auth
 */
class CognitoToken
{
    private $jwt = null;
    private $properties = array();

    public function __construct($jwt)
    {
        $this->jwt = $jwt;
        $this->properties = static::jwtDecode($jwt);
    }

    /**
     * Decode a Access Token
     *
     * @param string $access_token Access Token
     *
     * @return array
     */
    public static function jwtDecode($jwt)
    {
        $now = Carbon::now()->timestamp;
        $expecting = false;
        $incorrect = false;
        $expired = false;
        $error = false;
        $errors = array();
        $decodedToken = array();
        $token_segments = explode('.', $jwt);

        $header = isset($token_segments[0]) ? json_decode(base64_decode($token_segments[0])) : null;
        $payload = isset($token_segments[1]) ? json_decode(base64_decode($token_segments[1])) : null;
        $signature = isset($token_segments[2]) ? json_decode(base64_decode($token_segments[2])) : null;

        // Local kid
        $localKid = $header->kid;

        // Public kid
        $publicJwk = null;
        $client = new Client();
        $response = $client->get('https://cognito-idp.' . env('AWS_COGNITO_REGION') . '.amazonaws.com/' . env('AWS_COGNITO_USER_POOL_ID') . '/.well-known/jwks.json');
        $decodedResponse = json_decode($response->getBody()->getContents(), true);

        foreach ($decodedResponse['keys'] as $jwk) {
            if ($jwk['kid'] == $localKid) {
                $publicJwk = $jwk;
                break;
            }
        }

        $jwkConverter = new JWKConverter();
        $pem = $jwkConverter->toPEM($publicJwk);
        $decoded = JWT::decode($jwt, $pem, array('RS256'));

        if (count($token_segments) != 3) {
            $error = true;
            $errors[] = "Token has wrong number of segments";
        }
        if (null === $data = json_decode($payload)) {
            $error = true;
            $errors[] = "Decoder has problem with Token encoding";
        }
        if (isset($data->nbf) && $data->nbf > $now) {
            $expecting = true;
        }
        if (isset($data->iat) && $data->iat > $now) {
            $incorrect = true;
        }
        if (isset($data->exp) && $now >= $data->exp) {
            $expired = true;
            $errors[] = "Token has expired";
        }

        $decodedToken = array(
            'token_id' => (isset($data->jti)) ? $data->jti : null,
            'user_id' => (isset($data->sub)) ? $data->sub : null,
            'expecting' => $expecting,
            'start_at_unix' => (isset($data->nbf)) ? $data->nbf : null,
            'start_at' => (isset($data->nbf)) ? Carbon::createFromTimestamp($data->nbf)->setTimezone('Asia/Singapore')->toDateTimeString() : null,
            'incorrect' => $incorrect,
            'created_at_unix' => (isset($data->iat)) ? $data->iat : null,
            'created_at' => (isset($data->iat)) ? Carbon::createFromTimestamp($data->iat)->setTimezone('Asia/Singapore')->toDateTimeString() : null,
            'expired' => $expired,
            'expires_at_unix' => (isset($data->exp)) ? $data->exp : null,
            'expires_at' => (isset($data->exp)) ? Carbon::createFromTimestamp($data->exp)->setTimezone('Asia/Singapore')->toDateTimeString() : null,
            'error' => $error,
            'errors' => $errors,
            'valid' => ($expecting || $incorrect || $expired || $error) ? false : true,
        );

        return $decodedToken;
    }

    public function getToken()
    {
        return $this->jwt;
    }

    public function getProperties()
    {
        return $this->properties;
    }

    public function __get($property)
    {
        if (array_key_exists($property, $this->properties)) {
            return $this->properties[$property];
        }
        return null;
    }
}
