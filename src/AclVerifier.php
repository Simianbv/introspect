<?php
/**
 * PhpStorm
 * @user    merijn
 * @date    21/02/2020
 * @time    11:20
 * @version 1.0
 */

namespace Simianbv\Introspect;

use Exception;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Simianbv\Introspect\Contracts\RequiresAclValdation;
use Simianbv\Introspect\Exceptions\NoAccessException;

class AclVerifier
{

    /**
     * Verify the user has access to the given resource based on the Controller.
     *
     * @param Request $request
     * @param array   $acl
     *
     * @return bool
     * @throws NoAccessException
     */
    public function verify(Request $request, array $acl)
    {
        $token = null;
        try {
            if ($this->shouldControllerExcludeVerification($request)) {
                return true;
            }

            if ($this->isDeveloper($acl)) {
                return true;
            }

            $user = Auth::user();

            if ($user == null || !$user) {
                throw new AuthenticationException("No user found, cannot authorize this action");
            }

            if (!$user->isEmployee()) {
                throw new AuthenticationException("User is not an employee");
            }

            [$controller, $action] = explode('@', $request->route()->getActionName());

            $token = $this->generateAclToken($controller, $action);

            if (isset($acl['tokens']) && in_array($token, $acl['tokens'])) {
                return true;
            }

            throw new Exception('No permission tokens found to access this resource');
        } catch (Exception $exception) {
            throw new NoAccessException('Unable to verify token, you dont have permissions to access this resource.', null, $exception, $token);
        }
    }

    /**
     * Returns true if the $acl array contains a role with the name developer and the environment is not set t
     * to production.
     *
     * @param array $acl
     *
     * @return bool
     */
    private function isDeveloper(array $acl)
    {
        return isset($acl['roles']) && in_array('developer', $acl['roles']) && env('APP_ENV') !== 'production';
    }

    /**
     * Returns true if the controller has an exclusion interface and returns true on the exclusion part.
     *
     * @param Request $request
     *
     * @return bool
     */
    private function shouldControllerExcludeVerification(Request $request)
    {
        $implementations = class_implements($request->route()->getController());

        return (
            in_array(RequiresAclValdation::class, $implementations) &&
            $request->route()->getController()->excludeFromAclVerification() === true
        );
    }

    /**
     * Generate the token based on the name of the controller and the action.
     *
     * @param string $controller
     * @param string $action
     *
     * @return string
     */
    private function generateAclToken(string $controller, string $action)
    {
        $replace = ['App\\Http\\Controllers\\', "Api\\", 'Controller', '\\',];
        $replaceWith = ['', '', '', '.'];

        $controller = strtolower(str_replace($replace, $replaceWith, $controller));

        return $controller . '.' . $this->mapAction($action);
    }

    /**
     * Map the default resource actions to the permissions we defined as default permissions for each group.
     * basically, this maps the index, store, create, delete ( etc ) actions to our default set of 5 permissions of CRUD + access
     *
     * @param string $action
     *
     * @return string
     */
    private function mapAction($action)
    {
        switch ($action) {
            case 'create':
                return 'create';
            case 'read':
                return 'read';
            case 'update':
                return 'update';
            case 'delete':
                return 'delete';
            case 'index':
            case 'access':
            default:
                return 'access';
        }
    }
}
