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
use Illuminate\Support\Str;
use Simianbv\Introspect\Contracts\RequiresAclValdation;
use Simianbv\Introspect\Exceptions\NoAccessException;

class AclVerifier
{

    /**
     * Verify the user has access to the given resource based on the Controller.
     *
     * @param Request $request
     * @param array $acl
     *
     * @return bool
     * @throws NoAccessException
     */
    public function verify (Request $request, array $acl)
    {
        $token = '';
        try {
            if ($this->shouldControllerExcludeVerification($request)) {
                return true;
            }

            if ($this->isDeveloper($acl)) {
                return true;
            }

            $user = Auth::user();

            if ($user == null || !$user) {
                throw new AuthenticationException("No user found, cannot authorize this action.");
            }

            if (!$user->isEmployee()) {
                throw new AuthenticationException("The user we're trying to authenticate is not an employee.");
            }

            $token = $this->generateAclToken($request);

            if (isset($acl['tokens']) && in_array($token, $acl['tokens'])) {
                return true;
            }

            if (!isset($acl['tokens'])) {
                throw new Exception("No tokens were found in the ACL stack,
                 are you sure the user has a role and has granted permissions?");
            }

            if (!in_array($token, $acl['tokens'])) {
                throw new NoAccessException("The token given ('$token'), was
                not found in your ACL list, unable to grant access without the token.");
            }

            throw new Exception('No permission tokens found to access this resource');
        } catch (Exception $exception) {
            throw new NoAccessException(
                'The token to verify is ("' . $token . '").
                Unable to verify token, You do not have the necessary  token(s) to access this resource. The previous message is: ' . $exception->getMessage(),
                null,
                $exception,
                $token);
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
    private function isDeveloper (array $acl)
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
    private function shouldControllerExcludeVerification (Request $request)
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
     * @param Request $request
     * @return string
     */
    public function generateAclToken (Request $request = null)
    {
        if(!$request){
            $request = request();
        }
        [$controller, $action] = explode('@', $request->route()->getActionName());

        $replace = ['App\\Http\\', "Api\\", 'Controllers', 'Controller', '\\',];
        $replaceWith = ['', '', '', '', '.'];

        $tokenGroup = trim(rtrim(strtolower(str_replace($replace, $replaceWith, $controller)), '.'), '.');

        if ($tokenGroup == 'simianbv.jsonschema.http.schema') {
            return $this->getAclTokenByJsonSchema($request);
        }
        if ($tokenGroup == 'simianbv.search.http.filter') {
            return $this->getAclTokenBySearch($request);
        }

        return $tokenGroup . '.' . $this->mapAction($action);
    }

    /**
     * @param Request $request
     * @return string
     */
    private function getAclTokenByJsonSchema ($request)
    {
        $url = trim(rtrim($request->fullUrl(), '/'), '/');
        $args = explode('/', $url);
        $namespace = $args[count($args) - 2];
        $scope = Str::singular(str_replace('-', '', $args[count($args) - 1]));
        return $namespace . '.' . $scope . '.access';
    }

    /**
     * @param Request $request
     * @return string
     */
    private function getAclTokenBySearch ($request)
    {
        return 'filter.access';
    }


    /**
     * Map the default resource actions to the permissions we defined as default permissions for each group.
     * basically, this maps the index, store, create, delete ( etc ) actions to our default set of 5 permissions of CRUD + access
     *
     * @param string $action
     *
     * @return string
     */
    private function mapAction ($action)
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
