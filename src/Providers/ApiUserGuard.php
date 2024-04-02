<?php


namespace Simianbv\Introspect\Providers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;

/**
 * @class   ApiUserGuard
 * @package Simianbv\Introspect\Providers
 */
class ApiUserGuard implements Guard
{
    /**
     * @var Authenticatable
     */
    private $user = null;

    /**
     * @inheritDoc
     */
    public function check()
    {
        return $this->user !== null;
    }

    /**
     * @inheritDoc
     */
    public function guest()
    {
        return $this->user === null;
    }

    /**
     * @inheritDoc
     */
    public function user()
    {
        return $this->user;
    }
    
    /**
     * @inheritDoc
     */
    public function hasUser()
    {
        return $this->user !== null;
    }

    /**
     * @inheritDoc
     */
    public function id()
    {
        return $this->user->getAuthIdentifier();
    }

    /**
     * @inheritDoc
     */
    public function validate(array $credentials = [])
    {
        // TODO: Implement validate() method.
    }

    /**
     * @inheritDoc
     */
    public function setUser(Authenticatable $user)
    {
        $this->user = $user;
    }

}
