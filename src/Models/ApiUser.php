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
        $employees = Cache::get('employees');

        if (!$employees) {
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
                    $body = $response->json();
                    $employees = $body['data'];
                }
            } catch (\Exception $exception) {
                Log::error("Unable to get the users from the auth service");
                Log::error($exception->getMessage());
                $employees = [];
            }
        }

        return $employees;
    }

    /**
     * Attempts to return an authorization header.
     *
     * @param string|null $token
     * @return string
     */
    private function getAuthorizationHeader ($token = null)
    {
        if ($token) {
            return 'Bearer ' . $token;
        }

        if ($header = request()->header('Authorization')) {
            return $header;
        }

        if ($token = request('token')) {
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
