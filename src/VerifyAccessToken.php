<?php

/**
 * @copyright (c) Simian B.V. 2019
 * @version       1.0.0
 */

namespace Simianbv\Introspect;

use Closure;
use Illuminate\Http\Request;
use Simianbv\Introspect\Exceptions\InvalidAccessTokenException;
use Simianbv\Introspect\Exceptions\InvalidInputException;

/**
 * @description Middleware for verifying the Bearer OAuth2 access token as provided in the HTTP Authorization-header.
 * @class       VerifyAccessToken
 * @package     Simianbv\Introspect
 */
class VerifyAccessToken
{
    /**
     * @var Introspector
     */
    protected $introspector;


    /**
     * VerifyAccessToken constructor.
     *
     * @param Introspector $introspector
     */
    public function __construct(Introspector $introspector)
    {
        $this->introspector = $introspector;
    }

    /**
     * Handle an incoming request.
     *
     * @param Request $request
     * @param Closure $next
     * @param array   $scopes
     *
     * @return mixed
     * @throws InvalidAccessTokenException
     * @throws InvalidInputException
     */
    public function handle($request, Closure $next, ...$scopes)
    {
        if (!$this->controllerIsExcluded($request)) {
            $this->introspector->handle(null, $scopes);
        }

        return $next ($request);
    }

    /**
     * Check if the controller can be excluded from ACL validation and introspection.
     *
     * @param Request $request
     *
     * @return bool
     */
    private function controllerIsExcluded(Request $request)
    {
        $controller = $request->route()->getController();

        if (method_exists($controller, 'isExcludedFromAclVerification')) {
            return $controller->isExcludedFromAclVerification();
        }

        return false;
    }
}
