<?php

namespace Simianbv\Introspect;

use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;
use Simianbv\Introspect\Exceptions\InvalidAccessTokenException;
use Simianbv\Introspect\Exceptions\InvalidEndpointException;
use Simianbv\Introspect\Exceptions\InvalidInputException;
use Simianbv\Introspect\Models\ApiUser;

class Introspector
{
    const INTROSPECT_ACCESS_TOKEN_KEY = '_access_token';

    protected  AclVerifier $verifier;

    private Request $request;

    private string $user_access_token;

    private Client $client;

    protected string $cache_prefix = '';

    protected int $max_attempts = 2;
    
    public function __construct ($userToken = null, Request $request = null)
    {
        if (!$request) {
            $request = request();
        }

        $this->request = $request;
        $this->client = new Client;
        $this->verifier = new AclVerifier;

        if ($userToken) {
            $this->user_access_token = $userToken;
        }
    }

    /**
     * @throws InvalidAccessTokenException
     * @throws InvalidInputException
     * @throws Exception
     */
    public function handle (string $receivedUserAccessToken = null, array $scopes = [])
    {
        if (!$receivedUserAccessToken) {
            $authorizationHeader = $this->request->header('Authorization');

            if (strlen($authorizationHeader) == 0) {
                throw new InvalidInputException ("No Authorization header present");
            }

            $this->user_access_token = preg_replace('/^Bearer (.*?)$/', '$1', $authorizationHeader);
        } else {
            $this->user_access_token = $receivedUserAccessToken;
        }

        if (strlen($this->user_access_token) <= 1) {
            throw new InvalidInputException ("No Bearer token in the Authorization header present");
        }

        try {
            $token = $this->verifier->generateAclToken();
            $result = $this->introspect($this->user_access_token);

            if (!$result['active']) {
                throw new InvalidAccessTokenException ("Invalid token, token is inactive.", null, null, $token);
            }

            if (!empty($scopes)) {
                $this->validateScopes($result, $scopes);
            }

            $acl = $this->getAclFromAuthService($this->user_access_token);

            $this->verifier->verify($this->getRequest(), $acl);
        } catch (RequestException $exception) {
            if ($exception->hasResponse()) {
                $result = json_decode(( string )$exception->getResponse()->getBody(), true);
                $errorMessage = isset($result['error']) && is_string($result['error'])
                    ? $result['error']
                    : "Invalid token, unable to get a valid response from the introspection.";
                throw new InvalidAccessTokenException ($errorMessage, null, $exception, $token);
            } else {
                throw new InvalidAccessTokenException ($exception, null, $exception, $token);
            }
        } catch (Exception $exception) {
            throw new InvalidAccessTokenException("Unable to verify user token, cannot continue: " . $exception->getMessage(), null, $exception, $token);
        }
    }

    /**
     * @throws InvalidEndpointException
     */
    protected function introspect (string $userAccessToken): array
    {
        if ($cachedResponse = Cache::get($this->cacheKeyUserToken($userAccessToken))) {
            $response = $cachedResponse;
        } else {
            $response = ['active' => false];
            $tries = 0;
            do {
                try {
                    $tries++;
                    $body = [
                        'form_params' => ['token_type_hint' => 'access_token', 'token' => $userAccessToken,],
                        'headers'     => ['Authorization' => 'Bearer ' . $this->getServiceAccessToken(),],
                    ];
                    $response = $this->performRequest(config('introspect.introspect_introspect_url'), $body);
                    if ($response['active']) {
                        Cache::put($this->cacheKeyUserToken($userAccessToken), $response, now()->addMinutes(5));
                        $tries++;
                    }
                } catch (RequestException $exception) {
                    Cache::forget($this->cacheKeyServiceToken($this->getServiceCacheKey()));
                    if ($tries == $this->getMaxAttempts()) {
                        throw $exception;
                    }
                }
            } while ($tries < $this->getMaxAttempts());
        }

        if ($response && $response['active']) {
            $response['id'] = $response['sub'];
            $user = ApiUser::find($response['sub']);
            Auth::setUser($user);
        }

        return $response;
    }

    protected function getServiceAccessToken (): string
    {
        $microServiceAccessToken = Cache::get($this->cacheKeyServiceToken($this->getServiceCacheKey()));

        if (!$microServiceAccessToken) {
            $body = [
                'form_params' => [
                    'grant_type'    => 'client_credentials',
                    'client_id'     => config('introspect.introspect_client_id'),
                    'client_secret' => config('introspect.introspect_client_secret'),
                    'scope'         => '',
                ],
            ];
            $result = $this->performRequest(config('introspect.introspect_token_url'), $body);

            if (!$result || !isset($result['access_token'])) {
                throw new InvalidEndpointException ("No Access Token received, unable to verify the service.");
            }

            $microServiceAccessToken = $result['access_token'];
            Cache::put(
                $this->cacheKeyServiceToken($this->getServiceCacheKey()),
                $microServiceAccessToken,
                intval($result['expires_in'] / 60)
            );
        }

        return $microServiceAccessToken;
    }
    
    public function getServiceCacheKey (): string 
    {
        if ($this->cache_prefix == '') {
            $this->cache_prefix = config('introspect.introspect_cache_prefix', Str::slug(env('APP_NAME')));
        }

        return self::INTROSPECT_ACCESS_TOKEN_KEY . '_' . $this->cache_prefix;
    }

    /**
     * @throws InvalidAccessTokenException
     */
    protected function validateScopes (array $result, array|string $scopes): void
    {
        if ($scopes != null) {
            $scopes = !is_array($scopes) ? [$scopes] : $scopes;
            $scopesForToken = explode(" ", $result['scope']);
            $missingScopes = array_diff($scopes, $scopesForToken);
            $token = $this->verifier->generateAclToken();
            if (count($missingScopes) > 0) {
                throw new InvalidAccessTokenException ("Missing the following required scopes: " . implode(" ,", $missingScopes), null, null, $token);
            }
        }
    }

    private function getAclFromAuthService (string $receivedUserAccessToken): ?array
    {
        $acl = Cache::get($this->cacheKeyAcl(Auth::id()));

        if (!$acl) {
            $body = ['headers' => ['Authorization' => 'Bearer ' . $receivedUserAccessToken,],];
            $response = $this->getClient()->get(config('introspect.introspect_acl_url'), $body);
            $acl = json_decode(( string )$response->getBody(), true);

            if (!is_array($acl)) {
                $acl = null;
            }
        }

        return $acl;
    }

    protected function performRequest (string $url, array $body): array
    {
        $guzzle = $this->getClient();
        $response = $guzzle->post($url, $body);
        return json_decode(( string )$response->getBody(), true);
    }
    
    protected function getMaxAttempts (): int
    {
        return $this->max_attempts;
    }

    private function getClient (): Client
    {
        return $this->client;
    }
    
    private function getRequest (): Request
    {
        return $this->request;
    }

    private function cacheKeyUserToken(string $userAccessToken): string
    {
        return 'introspect:users:' . $userAccessToken;
    }
    
    private function cacheKeyServiceToken(string $serviceCacheKey): string
    {
        return 'introspect:service:' . $serviceCacheKey;
    }
    
    private function cacheKeyAcl(?int $userId): string
    {
        return 'introspect:acl:user:' . ($userId ?? 'guest');
    }

}
