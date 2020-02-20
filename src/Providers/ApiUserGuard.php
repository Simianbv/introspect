<?php


namespace Simianbv\Introspect\Providers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;


class ApiUserGuard implements Guard
{

    /**
     * @inheritDoc
     */
    public function check()
    {
        // TODO: Implement check() method.
    }

    /**
     * @inheritDoc
     */
    public function guest()
    {
        // TODO: Implement guest() method.
    }

    /**
     * @inheritDoc
     */
    public function user()
    {
        // TODO: Implement user() method.
    }

    /**
     * @inheritDoc
     */
    public function id()
    {
        // TODO: Implement id() method.
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
        // TODO: Implement setUser() method.
    }

}
