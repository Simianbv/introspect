<?php

namespace Simianbv\Introspect\Models;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Auth\User as Model;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
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
    public function __construct(array $attributes = [])
    {
        parent::__construct($attributes);
    }

    /**
     * @return array|mixed|null
     */
    public function getRows()
    {
        $employees = null;
        $employees = Cache::tags(['employees'])->get('all');

        if (!$employees) {
            $employees = [];
            $authorizationHeader = request()->header('Authorization');
            $headers = [
                'Authorization' => $authorizationHeader,
                "Content-Type" => "application/json",
                "Accept" => "application/json",
                "X-Requested-With" => "xmlHttpRequest",
            ];

            $response = Http::withHeaders($headers)
                ->get(config('introspect.introspect_employees_endpoint'));

            if ($response->successful()) {
                $body = $response->json();
                $employees = $body['data'];
            }
        }

        return $employees;
    }

    /**
     * Returns true if the JWT data has an attribute is_employee
     *
     * @return bool
     */
    public function isEmployee()
    {
        return $this->getAttribute('is_employee') == 1;
    }


    /**
     * @return string|void
     */
    public function getAuthIdentifierName()
    {
        return $this->given_name . ' ' . $this->family_name;
    }

    /**
     * @return mixed|void
     */
    public function getAuthIdentifier()
    {
        return $this->id;
    }

    public function __toString()
    {
        return (string)$this->getAuthIdentifier();
    }

    /**
     * @param $id
     *
     * @return void
     */
    protected function setAuthIdentifier($id): void
    {
        $this->id = $id;
    }

    /**
     * @return string|void
     */
    public function getAuthPassword()
    {
        // TODO: Implement getAuthPassword() method.
    }

    /**
     * @return string|void
     */
    public function getRememberToken()
    {
        // TODO: Implement getAuthPassword() method.
    }

    /**
     * @param string $value
     */
    public function setRememberToken($value)
    {
        // TODO: Implement setRememberToken() method.
    }

    /**
     * @return string|void
     */
    public function getRememberTokenName()
    {
        // TODO: Implement getRememberTokenName() method.
    }
}
