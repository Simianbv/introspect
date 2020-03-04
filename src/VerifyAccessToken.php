<?php

/**
 * @copyright (c) Simian B.V. 2019
 * @version       1.0.0
 */

namespace Simianbv\Introspect;

use Closure;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;
use Simianbv\Introspect\Exceptions\InvalidAccessTokenException;
use Simianbv\Introspect\Exceptions\InvalidEndpointException;
use Simianbv\Introspect\Exceptions\InvalidInputException;
use Simianbv\Introspect\Exceptions\NoAccessException;
use Simianbv\Introspect\Models\ApiUser;

/**
 * @description Middleware for verifying the Bearer OAuth2 access token as provided in the HTTP Authorization-header.
 * @class       VerifyAccessToken
 * @package     Simianbv\Introspect
 */
class VerifyAccessToken
{
    const INTROSPECT_ACCESS_TOKEN_KEY = '_access_token';


    /**
     * @var Client
     */
    private $client = null;

    /**
     * @var string
     */
    protected $cache_prefix = '';

    /**
     * @var int
     */
    protected $max_attempts = 2;
    /**
     * @var AclVerifier
     */
    private $aclVerifier;

    /**
     * VerifyAccessToken constructor.
     *
     * @param AclVerifier $aclVerifier
     */
    public function __construct(AclVerifier $aclVerifier)
    {
        $this->aclVerifier = $aclVerifier;
    }

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
     * @throws NoAccessException
     */
    public function handle($request, Closure $next, ...$scopes)
    {
        $authorizationHeader = $request->header('Authorization');

        if (strlen($authorizationHeader) == 0) {
            throw new InvalidInputException ("No Authorization header present");
        }

        $receivedUserAccessToken = preg_replace('/^Bearer (.*?)$/', '$1', $authorizationHeader);

        if (strlen($receivedUserAccessToken) <= 1) {
            throw new InvalidInputException ("No Bearer token in the Authorization header present");
        }

        try {
            $result = $this->introspect($receivedUserAccessToken);

            if (!$result['active']) {
                throw new InvalidAccessTokenException ("Invalid token, token is inactive.");
            }

            $this->validateScopes($result, $scopes);

            if (!$acl = Cache::tags(['acl'])->get('acl.user.' . Auth::id())) {
                $acl = $this->getAclFromAuthService($receivedUserAccessToken);
            }

            if (!$this->aclVerifier->verify($request, $acl)) {
                throw new NoAccessException("Authorization failed, user has no permissions to access this resource. Token given: " . $token);
            }
        } catch (RequestException $exception) {
            if ($exception->hasResponse()) {
                $result = json_decode(( string )$exception->getResponse()->getBody(), true);
                throw new InvalidAccessTokenException ($result['error'] ?? "Invalid token, unable to get a valid response from the introspection.", null, $exception);
            } else {
                throw new InvalidAccessTokenException ($exception, null, $exception);
            }
        }

        return $next ($request);
    }

    /**
     * If no ACL is found in cache, call out to the auth service directly and retrieve the ACL credentials for this
     * user, if all is correct, the cache should be set after this call as well.
     *
     * @param string $receivedUserAccessToken
     *
     * @return mixed|null
     */
    private function getAclFromAuthService(string $receivedUserAccessToken)
    {
        $body = [
            'headers' => [
                'Authorization' => 'Bearer ' . $receivedUserAccessToken,
            ],
        ];
        $response = $this->getClient()->get(config('introspect.introspect_acl_url'), $body);
        $acl = json_decode(( string )$response->getBody(), true);

        if (is_array($acl)) {
            return $acl;
        }
        return null;
    }

    /**
     * Perform the actual introspection, pass along the user's Access Token, validate the request using
     * the microservices' access token and validate the access token is valid.
     *
     * @param string $userAccessToken
     *
     * @return array
     * @throws InvalidEndpointException
     */
    protected function introspect(string $userAccessToken)
    {
        if ($cachedResponse = Cache::tags(['users'])->get($userAccessToken)) {
            $response = $cachedResponse;
        } else {
            $response = ['active' => false];
            $tries = 0;
            do {
                try {
                    $tries++;
                    $body = [
                        'form_params' => ['token_type_hint' => 'access_token', 'token' => $userAccessToken,],
                        'headers' => ['Authorization' => 'Bearer ' . $this->getServiceAccessToken(),],
                    ];
                    $response = $this->request(config('introspect.introspect_introspect_url'), $body);
                    if ($response['active']) {
                        Cache::tags(['users'])->put($userAccessToken, $response, now()->addMinutes(5));
                        $tries++;
                    }
                } catch (RequestException $exception) {
                    Cache::tags(['service'])->forget($this->getServiceCacheKey());
                    if ($tries == $this->maxAttempts()) {
                        throw $exception;
                    }
                }
            } while ($tries < $this->maxAttempts());
        }

        if ($response && $response['active']) {
            $user = new ApiUser($response);
            Log::debug("Setting user:");
            Log::debug(json_encode($user->getAttributes()));
            Auth::setUser($user);
        }

        return $response;
    }

    /**
     * Validate the scopes, if scopes are provided, check if the scopes given are accessible. If there are missing
     * scopes, raise a new exception and notify the missing scopes.
     *
     * @param array        $result
     * @param string|array $scopes
     *
     * @return void
     * @throws InvalidAccessTokenException
     */
    protected function validateScopes(array $result, $scopes): void
    {
        if ($scopes != null) {
            $scopes = !is_array($scopes) ? [$scopes] : $scopes;
            $scopesForToken = explode(" ", $result['scope']);
            if (count($misingScopes = array_diff($scopes, $scopesForToken)) > 0) {
                throw new InvalidAccessTokenException ("Missing the following required scopes: " . implode(" ,", $misingScopes));
            }
        }
    }

    /**
     * Get the Access Token required by this microservice, it attempts to search for a key in cache, if no key
     * is found, attempt to validate the microservice against our IDP.
     *
     * @return string
     * @throws InvalidEndpointException
     */
    protected function getServiceAccessToken(): string
    {
        $microServiceAccessToken = Cache::tags(['service'])->get($this->getServiceCacheKey());

        if (!$microServiceAccessToken) {
            $body = [
                'form_params' => [
                    'grant_type' => 'client_credentials',
                    'client_id' => config('introspect.introspect_client_id'),
                    'client_secret' => config('introspect.introspect_client_secret'),
                    'scope' => '',
                ],
            ];
            $result = $this->request(config('introspect.introspect_token_url'), $body);

            if (!$result || !isset($result['access_token'])) {
                throw new InvalidEndpointException ("No Access Token received, unable to verify the service.");
            }

            $microServiceAccessToken = $result['access_token'];
            Cache::tags(['service'])->put($this->getServiceCacheKey(), $microServiceAccessToken, intval($result['expires_in'] / 60));
        }

        return $microServiceAccessToken;
    }

    /**
     * Perform a POST request to the endpoint given by the $url. Post the body array and decode the
     * response ( we're assuming the response is JSON )
     *
     * @param string $url
     * @param array  $body
     *
     * @return array
     */
    protected function request(string $url, array $body): array
    {
        $guzzle = $this->getClient();
        $response = $guzzle->post($url, $body);
        return json_decode(( string )$response->getBody(), true);
    }

    /**
     * Return the cache key used by this microservice to store their access tokens,
     * if no prefix is set, falls back to the slug the APP_NAME environment string.
     *
     * @return string
     */
    public function getServiceCacheKey()
    {
        if ($this->cache_prefix == '') {
            $this->cache_prefix = config('introspect.introspect_cache_prefix', Str::slug(env('APP_NAME')));
        }

        return self::INTROSPECT_ACCESS_TOKEN_KEY . '_' . $this->cache_prefix;
    }

    /**
     * Return the Guzzle HTTP Client to use our requests with.
     *
     * @return Client
     */
    private function getClient(): Client
    {
        if ($this->client == null) {
            $this->client = new Client();
        }
        return $this->client;
    }

    /**
     * Returns the max attempts. This defines the maximum number of tries the service can call the auth service
     * to verify the request.
     *
     * @return int
     */
    protected function maxAttempts()
    {
        return $this->max_attempts;
    }

}
