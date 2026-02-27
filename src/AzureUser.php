<?php

namespace Metrogistics\AzureSocialite;

use GuzzleHttp\Client;
use Laravel\Socialite\Facades\Socialite;

class AzureUser
{
    protected $user;

    public function __construct($user)
    {
        $this->user = $user;
    }

    public function get()
    {
        $this->user->setExpiresIn($this->user->expiresAt - time());

        return $this->user;
    }

    public function roles()
    {
        $idToken = $this->user->idToken;
        $tokens = explode('.', $idToken);

        if (count($tokens) !== 3) {
            throw new \RuntimeException('Invalid id_token format: expected 3 segments');
        }

        $payload = json_decode(static::urlsafeB64Decode($tokens[1]));

        if (!$payload) {
            throw new \RuntimeException('Invalid id_token: could not decode payload');
        }

        // Validate token expiry
        if (isset($payload->exp) && $payload->exp < time()) {
            throw new \RuntimeException('id_token has expired');
        }

        // Validate audience matches our client_id
        $clientId = config('azure-oath.credentials.client_id');
        if (isset($payload->aud) && $payload->aud !== $clientId) {
            throw new \RuntimeException('id_token audience does not match client_id');
        }

        // Validate issuer is from Microsoft login
        if (isset($payload->iss) && strpos($payload->iss, 'https://sts.windows.net/') !== 0
            && strpos($payload->iss, 'https://login.microsoftonline.com/') !== 0) {
            throw new \RuntimeException('id_token issuer is not a valid Microsoft endpoint');
        }

        if (!isset($payload->roles) || !is_array($payload->roles)) {
            return [];
        }

        return $payload->roles;
    }

    public static function urlsafeB64Decode($input)
    {
        $remainder = strlen($input) % 4;

        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }

        return base64_decode(strtr($input, '-_', '+/'));
    }

    public function refreshAccessToken()
    {
        $guzzle = new Client();

        $response = $guzzle->post('https://login.microsoftonline.com/common/oauth2/token', [
            'form_params' => [
                'client_id' => config('azure-oath.credentials.client_id'),
                'scope' => 'user.read',
                'refresh_token' => $this->get()->refreshToken,
                'redirect_uri' => config('azure-oath.credentials.redirect'),
                'grant_type' => 'refresh_token',
                'client_secret' => config('azure-oath.credentials.client_secret')
            ]
        ]);

        $token_response = json_decode($response->getBody());

        $this->user->token = $token_response->access_token;
        $this->user->refreshToken = $token_response->refresh_token;
        $this->user->expiresAt = $token_response->expires_on;
        $this->user->expiresIn = $token_response->expires_in;

        session([
            'azure_user' => $this->user
        ]);

        return $this->get();
    }
}
