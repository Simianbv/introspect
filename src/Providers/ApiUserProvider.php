<?php

namespace Simianbv\Introspect\Providers;

use Simianbv\Introspect\Models\ApiUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;

/**
 * @class   ApiUserProvider
 * @package App\Providers
 */
class ApiUserProvider implements UserProvider
{
    /**
     * @param array $credentials
     *
     * @return ApiUser
     */
    public function retrieveByCredentials(array $credentials)
    {
        $user = [];
        $user = $user ?: null;
        return $this->getApiUser($user);
    }

    /**
     * @param $identifier
     *
     * @return ApiUser
     */
    public function retrieveById($identifier)
    {
        $user = session()->get($identifier);
        return $this->getApiUser($user);
    }

    /**
     * @param Authenticatable $user
     * @param array           $credentials
     */
    public function validateCredentials(Authenticatable $user, array $credentials)
    {
    }

    protected function getApiUser($user)
    {
        if ($user !== null) {
            return new ApiUser((array)$user);
        }
    }

    /**
     * Get the user by ID
     *
     * @param $id
     *
     * @return |null
     */
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
