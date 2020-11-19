<?php

namespace Simianbv\Introspect\Models;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Auth\User as Model;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Sushi\Sushi;


/**
 * @class   ApiUser
 * @package Simianbv\Introspect\Models
 */
class ApiUser extends Model implements Authenticatable
{

    use Sushi;

    /**
     * ApiUser constructor.
     *
     * @param array $jwt
     */
    public function __construct (array $attributes = [])
    {
        parent::__construct($attributes);
    }

    /**
     * @return array|mixed|null
     * @throws \Exception
     */
    public function getRows ()
    {
        $employees = null;
        $employees = Cache::tags(['employees'])->get('all');

        Log::debug("Introspect\Models\ApiUser: Attempting to retrieve employees from cache");

        if (!$employees) {
            Log::debug("Introspect\Models\ApiUser: No employees found in cache");
            $employees = [];

            $header = $this->getAuthorizationHeader();

            $headers = [
                'Authorization'    => $header,
                "Content-Type"     => "application/json",
                "Accept"           => "application/json",
                "X-Requested-With" => "xmlHttpRequest",
            ];

            try {
                $response = Http::withHeaders($headers)
                    ->get(config('introspect.introspect_employees_endpoint'));

                if ($response->clientError() || $response->serverError()) {
                    $response->throw();
                }

                if ($response->successful()) {
                    Log::debug("Introspect\Models\ApiUser: Retrieved employees from cache, storing to cache");
                    $body = $response->json();
                    $employees = $body['data'];
                }
            } catch (\Exception $exception) {
                throw new \Exception("Unable to get the users from the auth service");
            }
        }

        return $employees;
    }

    /**
     * Attempts to return an authorization header.
     *
     * @return string
     */
    private function getAuthorizationHeader ()
    {
        if ($header = request()->header('Authorization')) {
            return $header;
        }

        if ($token = request('token') && $token !== null) {
            return 'Bearer ' . $token;
        }

        return null;
    }

    /**
     * Returns true if the JWT data has an attribute is_employee
     *
     * @return bool
     */
    public function isEmployee ()
    {
        return $this->getAttribute('is_employee') == 1;
    }


    /**
     * @return string|void
     */
    public function getAuthIdentifierName ()
    {
        return $this->given_name . ' ' . $this->family_name;
    }

    /**
     * @return mixed|void
     */
    public function getAuthIdentifier ()
    {
        return $this->id;
    }

    public function __toString ()
    {
        return (string)$this->getAuthIdentifier();
    }

    /**
     * @param $id
     *
     * @return void
     */
    protected function setAuthIdentifier ($id): void
    {
        $this->id = $id;
    }

    /**
     * @return string|void
     */
    public function getAuthPassword ()
    {
        // TODO: Implement getAuthPassword() method.
    }

    /**
     * @return string|void
     */
    public function getRememberToken ()
    {
        // TODO: Implement getAuthPassword() method.
    }

    /**
     * @param string $value
     */
    public function setRememberToken ($value)
    {
        // TODO: Implement setRememberToken() method.
    }

    /**
     * @return string|void
     */
    public function getRememberTokenName ()
    {
        // TODO: Implement getRememberTokenName() method.
    }
}
