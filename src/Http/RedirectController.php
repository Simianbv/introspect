<?php
/**
 * @copyright (c) Simian B.V. 2019
 * @version       1.0.0
 */

namespace Simianbv\Introspect\Http;

use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Foundation\Bus\DispatchesJobs;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Routing\Controller;
use Illuminate\Http\Request;

/**
 * @class   ApiController
 * @package Simianbv\JsonSchema\Http
 */
class RedirectController extends Controller
{
    use AuthorizesRequests, DispatchesJobs, ValidatesRequests;

    /**
     * Redirection endpoint for initiating the OAuth2 Implicit Grant flow.
     * The retrieved access token can be used to call the APIs as protected with the provided middleware.
     *
     * Note: this module does not provide any logic for extracting the access tokens from the url.
     *
     * @param Request $request
     * @return Redirect
     */
    public function index (Request $request)
    {
        $query = http_build_query(
            [
                'client_id'     => config('introspect.introspect_client_id'),
                'redirect_uri'  => config('introspect.introspect_redirect_url'),
                'response_type' => 'token',
                'scope'         => 'place-orders',
            ]
        );

        return redirect(config('introspect.introspect_authorization_url') . '?' . $query);
    }
}
