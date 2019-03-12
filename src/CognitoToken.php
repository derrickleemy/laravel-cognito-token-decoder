<?php

namespace derrickleemy\Auth;

use \CoderCat\JWKToPEM\JWKConverter;
use \Carbon\Carbon;
use \Firebase\JWT\JWT;
use \GuzzleHttp\Client;

/**
 * Class CognitoToken
 * @package derrickleemy\Auth
 */
class CognitoToken
{
    private $authCode = null;
    private $jwt = null;
    private $properties = array();

    public function __construct($authCode)
    {
        $this->authCode = $authCode;
        $this->jwt = static::getJwt($authCode);
        $this->properties = static::jwtDecode($this->jwt);
    }

    /**
     * Get the Json Web Token
     *
     * @param string $authCode Auth Code
     *
     * @return array
     */
    public static function getJwt($authCode)
    {
        $client = new Client();
        $response = $client->post(env('AWS_COGNITO_DOMAIN') . '/oauth2/token', [
            'headers' => [
                'Authorization' => 'Basic ' . base64_encode(env('AWS_COGNITO_CLIENT_ID') . ':' . env('AWS_COGNITO_CLIENT_SECRET')),
            ],
            'form_params' => [
                'grant_type' => 'authorization_code',
                'code' => $authCode,
                'client_id' => env('AWS_COGNITO_CLIENT_ID'),
                'redirect_uri' => env('APP_URL'),
            ],
        ]);

        $decodedResponse = json_decode($response->getBody()->getContents(), true);
        $idToken = $decodedResponse['id_token'];

        return $idToken;
    }

    /**
     * Decode the Json Web Token
     *
     * @param string $jwt Json Web Token
     *
     * @return array
     */
    public static function jwtDecode($jwt)
    {
        $now = Carbon::now()->timestamp;
        $error = false;
        $errors = array();
        $decodedToken = array();
        $token_segments = explode('.', $jwt);

        $header = isset($token_segments[0]) ? json_decode(base64_decode($token_segments[0])) : null;
        $payload = isset($token_segments[1]) ? json_decode(base64_decode($token_segments[1])) : null;

        // If Token Segments != 3, do not continue processing
        if (count($token_segments) != 3) {
            $error = true;
            $errors[] = "Token has wrong number of segments";
        } else {
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
            $decodedToken = JWT::decode($jwt, $pem, array('RS256'));

            // Verify that the token is not expired
            if (isset($decodedToken->iat) && $decodedToken->iat > $now) {
                $error = true;
                $errors[] = "Token cannot be issued after current time";
            }

            if (isset($decodedToken->exp) && $now >= $decodedToken->exp) {
                $error = true;
                $errors[] = "Token has already expired";
            }

            // Verify that the audience (aud) claim matches the app client ID created in the Amazon Cognito user pool.
            if (isset($decodedToken->aud) && $decodedToken->aud != env('AWS_COGNITO_CLIENT_ID')) {
                $error = true;
                $errors[] = "Token does not match audience";
            }

            // Verify that the issuer (iss) claim matches your user pool.
            if (isset($decodedToken->iss) && $decodedToken->iss != 'https://cognito-idp.' . env('AWS_COGNITO_REGION') . '.amazonaws.com/' . env('AWS_COGNITO_USER_POOL_ID')) {
                $error = true;
                $errors[] = "Token does not match user pool";
            }

            // Verify that the token_use claim matches 'id'
            if (isset($decodedToken->token_use) && $decodedToken->token_use != 'id') {
                $error = true;
                $errors[] = "Token use claim is incorrect";
            }

            $decodedToken = array_merge((array) $decodedToken, ['error' => $error, 'errors' => $errors]);
        }

        return $decodedToken;
    }

    public function getAuthCode()
    {
        return $this->authCode;
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