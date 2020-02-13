<?php

/**
 * @copyright (c) Simian B.V. 2019
 * @version       1.0.0
 */

namespace Simianbv\Introspect;

use Closure;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Simianbv\Introspect\Exceptions\InvalidAccessTokenException;
use Simianbv\Introspect\Exceptions\InvalidEndpointException;
use Simianbv\Introspect\Exceptions\InvalidInputException;

/**
 * @description Middleware for verifying the Bearer OAuth2 access token as provided in the HTTP Authorization-header.
 * @class       VerifyAccessToken
 * @package     Simianbv\Introspect
 */
class VerifyAccessToken
{
    /**
     * @var Client
     */
    private $client = null;

    /**
     * Handle an incoming request.
     *
     * @param Request $request
     * @param Closure $next
     * @param array   $scopes
     *
     * @return mixed
     * @throws InvalidAccessTokenException
     * @throws InvalidEndpointException
     * @throws InvalidInputException
     */
    public function handle($request, Closure $next, ...$scopes)
    {
        $authorizationHeader = $request->header('Authorization');

        if (strlen($authorizationHeader) == 0) {
            throw new InvalidInputException ("No Authorization header present");
        }

        $receivedAccessToken = preg_replace('/^Bearer (.*?)$/', '$1', $authorizationHeader);

        # Just to be sure it is really an access token
        if (strlen($receivedAccessToken) <= 1) {
            throw new InvalidInputException ("No Bearer token in the Authorization header present");
        }

        // Now verify the user provided access token
        try {
            $result = $this->getIntrospect($receivedAccessToken);
            if (!$result ['active']) {
                throw new InvalidAccessTokenException ("Invalid token!");
            } else {
                if ($scopes != null) {
                    if (!\is_array($scopes)) {
                        $scopes = [
                            $scopes,
                        ];
                    }

                    $scopesForToken = explode(" ", $result ['scope']);

                    if (count($misingScopes = array_diff($scopes, $scopesForToken)) > 0) {
                        throw new InvalidAccessTokenException ("Missing the following required scopes: " . implode(" ,", $misingScopes));
                    } else {
                    }
                }
            }
        } catch (RequestException $e) {
            if ($e->hasResponse()) {
                $result = json_decode(( string )$e->getResponse()->getBody(), true);

                if (isset ($result ['error'])) {
                    throw new InvalidAccessTokenException ($result ['error'] ['title'] ?? "Invalid token!");
                } else {
                    throw new InvalidAccessTokenException ("Invalid token!");
                }
            } else {
                throw new InvalidAccessTokenException ($e);
            }
        }

        return $next ($request);
    }

    /**
     * @return Client|null
     */
    private function getClient()
    {
        if ($this->client == null) {
            $this->client = new Client();
        }
        return $this->client;
    }

    /**
     * @param Client $client
     */
    public function setClient(Client $client)
    {
        $this->client = $client;
    }

    /**
     * @param string $accessToken
     *
     * @return mixed
     * @throws InvalidEndpointException
     */
    protected function getIntrospect(string $accessToken)
    {
        $guzzle = $this->getClient();

        // @todo: Add the cache driver here to (in)validate the introspection

        // the path to post to
        $url = config('introspect.introspect_introspect_url');
        $tries = 0;
        do {
            try {
                $tries++;

                $body = [
                    'form_params' => [
                        'token_type_hint' => 'access_token',
                        // This is the access token for verifying the user's access token
                        'token' => $accessToken,
                    ],
                    'headers' => [
                        'Authorization' => 'Bearer ' . $this->getAccessToken(),
                    ],
                ];

                $response = $guzzle->post($url, $body);
            } catch (RequestException $e) {
                # Access token might have expired, just retry getting one
                Cache::forget('accessToken');

                if ($tries == 2) {
                    throw $e;
                }
            }
        } while ($tries < 2);

        return json_decode(( string )$response->getBody(), true);
    }

    /**
     * Get the Access Token from the request headers.
     *
     * @return mixed
     * @throws InvalidEndpointException
     */
    protected function getAccessToken()
    {
        $accessToken = Cache::get('accessToken');

        // the path to post to
        $url = config('introspect.introspect_token_url');

        if (!$accessToken) {
            $guzzle = $this->getClient();
            $body = [
                'form_params' => [
                    'grant_type' => 'client_credentials',
                    'client_id' => config('introspect.introspect_client_id'),
                    'client_secret' => config('introspect.introspect_client_secret'),
                    'scope' => '',
                ],
            ];

            $response = $guzzle->post($url, $body);
            $result = json_decode(( string )$response->getBody(), true);

            if ($result && isset ($result ['access_token'])) {
                Cache::add('accessToken', $result ['access_token'], intVal($result ['expires_in']) / 60);
            } else {
                throw new InvalidEndpointException ("Did not receive an access token");
            }
        }

        return $accessToken;
    }
}
