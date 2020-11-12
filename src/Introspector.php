<?php
/**
 * PhpStorm
 * @user    merijn
 * @date    30/04/2020
 * @time    14:15
 * @version 1.0
 */

namespace Simianbv\Introspect;


use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Simianbv\Introspect\Exceptions\InvalidAccessTokenException;
use Simianbv\Introspect\Exceptions\InvalidEndpointException;
use Simianbv\Introspect\Exceptions\InvalidInputException;
use Simianbv\Introspect\Models\ApiUser;

/**
 * Class Introspector
 * @package Simianbv\Introspect
 */
class Introspector
{

    /**
     * @var string
     */
    const INTROSPECT_ACCESS_TOKEN_KEY = '_access_token';

    /**
     * @var AclVerifier
     */
    protected $verifier;

    /**
     * @var Request
     */
    private $request;

    /**
     * @var string
     */
    private $user_access_token;

    /**
     * @var Client
     */
    private $client;

    /**
     * @var string
     */
    protected $cache_prefix = '';

    /**
     * @var int
     */
    protected $max_attempts = 2;

    /**
     * Introspector constructor.
     *
     * @param Request     $request
     * @param AclVerifier $verifier
     * @param null        $userToken
     */
    public function __construct($userToken = null, Request $request = null)
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
     * @param      $scopes
     * @param null $receivedUserAccessToken
     *
     * @throws InvalidAccessTokenException
     * @throws InvalidInputException
     * @throws Exception
     */
    public function handle($receivedUserAccessToken = null, array $scopes = [])
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
            $result = $this->introspect($this->user_access_token);

            if (!$result['active']) {
                throw new InvalidAccessTokenException ("Invalid token, token is inactive.");
            }

            if (!empty($scopes)) {
                $this->validateScopes($result, $scopes);
            }

            $acl = $this->getAclFromAuthService($this->user_access_token);

            $this->verifier->verify($this->getRequest(), $acl);
        } catch (RequestException $exception) {
            if ($exception->hasResponse()) {
                $result = json_decode(( string )$exception->getResponse()->getBody(), true);
                Log::debug($result);
                $errorMessage = isset($result['error']) && is_string($result['error'])
                    ? $result['error']
                    : "Invalid token, unable to get a valid response from the introspection.";
                throw new InvalidAccessTokenException ($errorMessage, null, $exception);
            } else {
                throw new InvalidAccessTokenException ($exception, null, $exception);
            }
        } catch (Exception $exception) {
            throw new InvalidAccessTokenException("Unable to verify user token, cannot continue: " . $exception->getMessage(), null, $exception);
        }
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
                    $response = $this->performRequest(config('introspect.introspect_introspect_url'), $body);
                    if ($response['active']) {
                        Cache::tags(['users'])->put($userAccessToken, $response, now()->addMinutes(5));
                        $tries++;
                    }
                } catch (RequestException $exception) {
                    Cache::tags(['service'])->forget($this->getServiceCacheKey());
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
            $result = $this->performRequest(config('introspect.introspect_token_url'), $body);

            if (!$result || !isset($result['access_token'])) {
                throw new InvalidEndpointException ("No Access Token received, unable to verify the service.");
            }

            $microServiceAccessToken = $result['access_token'];
            Cache::tags(['service'])->put($this->getServiceCacheKey(), $microServiceAccessToken, intval($result['expires_in'] / 60));
        }

        return $microServiceAccessToken;
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
            $missingScopes = array_diff($scopes, $scopesForToken);

            if (count($missingScopes) > 0) {
                throw new InvalidAccessTokenException ("Missing the following required scopes: " . implode(" ,", $missingScopes));
            }
        }
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
        $acl = Cache::tags(['acl'])->get('acl.user.' . Auth::id());

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

    /**
     * Perform a POST request to the endpoint given by the $url. Post the body array and decode the
     * response ( we're assuming the response is JSON )
     *
     * @param string $url
     * @param array  $body
     *
     * @return array
     */
    protected function performRequest(string $url, array $body): array
    {
        $guzzle = $this->getClient();
        $response = $guzzle->post($url, $body);
        return json_decode(( string )$response->getBody(), true);
    }

    /**
     * Returns the max attempts. This defines the maximum number of tries the service can call the auth service
     * to verify the request.
     *
     * @return int
     */
    protected function getMaxAttempts()
    {
        return $this->max_attempts;
    }

    /**
     * Return the Guzzle HTTP Client to use our requests with.
     *
     * @return Client
     */
    private function getClient(): Client
    {
        return $this->client;
    }

    /**
     * Return the Illuminate Request object
     *
     * @return Request
     */
    private function getRequest()
    {
        return $this->request;
    }

}
