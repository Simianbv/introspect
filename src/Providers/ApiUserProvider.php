<?php

namespace Simianbv\Introspect\Providers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;

/**
 * @class   ApiUserProvider
 * @package App\Providers
 */
class ApiUserProvider implements UserProvider
{


    public function retrieveByCredentials(array $credentials)
    {
        $user = [];

        $user = $user ?: null;

        return $this->getApiUser($user);
    }

    public function retrieveById($identifier)
    {
        $user = session()->get($identifier);
        return $this->getApiUser($user);
    }

    public function validateCredentials(Authenticatable $user, array $credentials)
    {
    }

    protected function getApiUser($user)
    {
        if ($user !== null) {
            return new \App\ApiUser((array)$user);
        }
    }

    protected function getUserById($id)
    {
        $user = session()->get($id);
        return $user ?: null;
    }

    public function retrieveByToken($identifier, $token)
    {
    }

    public function updateRememberToken(Authenticatable $user, $token)
    {
    }
}
