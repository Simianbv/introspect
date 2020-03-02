<?php

namespace Simianbv\Introspect\Models;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * @class   ApiUser
 * @package Simianbv\Introspect\Models
 */
class ApiUser implements Authenticatable
{
    /**
     * @var mixed|null
     */
    protected $id = null;

    /**
     * @var string
     */
    protected $given_name = '';

    /**
     * @var string
     */
    protected $family_name = '';

    /**
     * @var string
     */
    protected $email = '';

    /**
     * @var bool
     */
    protected $is_employee = false;

    /**
     * @var string
     */
    protected $profile = '';

    /**
     * @var array
     */
    protected $fields = [];

    /**
     * ApiUser constructor.
     *
     * @param array $jwt
     */
    public function __construct(array $jwt)
    {
        foreach ($jwt as $k => $v) {
            $this->fields[$k] = $v;
            if (property_exists($this, $k)) {
                $this->$k = $v;
            }
        }

        if (isset($jwt['sub'])) {
            $this->setAuthIdentifier($jwt['sub']);
        }
    }

    /**
     * Returns true if the JWT data has an attribute is_employee
     *
     * @return bool
     */
    public function isEmployee()
    {
        return $this->is_employee === 1;
    }

    /**
     * Returns the profile image associated with the account.
     *
     * @return string
     */
    public function getProfile()
    {
        return $this->profile;
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
