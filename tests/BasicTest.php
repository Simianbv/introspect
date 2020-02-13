<?php
/**
 * @copyright (c) Simian B.V. 2019
 * @version       1.0.0
 */

namespace Simianbv\Introspect\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7;
use GuzzleHttp\Psr7\Response;
use Illuminate\Http\Request;
use Orchestra\Testbench\TestCase;
use Simianbv\Introspect\Exceptions\InvalidAccessTokenException;
use Simianbv\Introspect\VerifyAccessToken;

/**
 * @class   BasicTest
 * @package Simianbv\Introspect\Tests
 */
class BasicTest extends TestCase
{

    /**
     * @param $app
     */
    protected function getEnvironmentSetUp($app)
    {
        $app ['config']->set('introspect.introspect_token_url', 'https://token_endpoint');
        $app ['config']->set('introspect.introspect_introspect_url', 'https://introspect_endpoint');
    }

    /**
     * @return Response
     */
    protected function getClientCredentialsTokenEndPoint()
    {
        return new Response (
            200, [], Psr7\stream_for(
                   '{
            "access_token":"2YotnFZFEjr1zCsicMWpAA",
            "token_type":"example",
            "expires_in":3600,
            "example_parameter":"example_value"
        }'
               )
        );
    }

    /**
     * @throws InvalidAccessTokenException
     * @throws \Simianbv\Introspect\Exceptions\InvalidEndpointException
     * @throws \Simianbv\Introspect\Exceptions\InvalidInputException
     */
    public function testMissingRequiredScopes()
    {
        $this->expectException(InvalidAccessTokenException::class);

        $middleware = new VerifyAccessToken ();

        $mock = new MockHandler(
            [
                $this->getClientCredentialsTokenEndPoint(),
                new Response(
                    200, [], Psr7\stream_for(
                           '{
                "active": true,
                "client_id": "l238j323ds-23ij4",
                "username": "jdoe",
                "scope": "read write dolphin",
                "sub": "Z5O3upPC88QrAjx00dis",
                "aud": "https://protected.example.net/resource",
                "iss": "https://server.example.com/",
                "exp": 1419356238,
                "iat": 1419350238,
                "extension_field": "twenty-seven"
            }'
                       )
                ),
            ]
        );

        $middleware->setClient(new Client(['handler' => HandlerStack::create($mock),]));

        $request = Request::create('http://example.com/admin', 'GET');
        $request->headers->set('Authorization', 'Bearer test123');

        $response = $middleware->handle(
            $request, function () {
            return true;
        }, "missing_scope"
        );
    }

    /**
     * @throws InvalidAccessTokenException
     * @throws \Simianbv\Introspect\Exceptions\InvalidEndpointException
     * @throws \Simianbv\Introspect\Exceptions\InvalidInputException
     */
    public function testRequiredScopePresent()
    {
        $middleware = new VerifyAccessToken ();
        $mock = new MockHandler (
            [

                $this->getClientCredentialsTokenEndPoint(),

                new Response(
                    200, [], Psr7\stream_for(
                           '{
                    "active": true,
                    "client_id": "l238j323ds-23ij4",
                    "username": "jdoe",
                    "scope": "read write dolphin",
                    "sub": "Z5O3upPC88QrAjx00dis",
                    "aud": "https://protected.example.net/resource",
                    "iss": "https://server.example.com/",
                    "exp": 1419356238,
                    "iat": 1419350238,
                    "extension_field": "twenty-seven"
                }'
                       )
                ),
            ]
        );

        $middleware->setClient(new Client(['handler' => HandlerStack::create($mock),]));

        $request = Request::create('http://example.com/admin', 'GET');
        $request->headers->set('Authorization', 'Bearer test123');

        $response = $middleware->handle(
            $request, function () {
            return true;
        }, "dolphin"
        );

        $this->assertTrue($response);
    }

    /**
     * @throws InvalidAccessTokenException
     * @throws \Simianbv\Introspect\Exceptions\InvalidEndpointException
     * @throws \Simianbv\Introspect\Exceptions\InvalidInputException
     */
    public function testTokenIsActive()
    {
        $middleware = new VerifyAccessToken();

        $mock = new MockHandler (
            [

                $this->getClientCredentialsTokenEndPoint(),

                new Response(
                    200, [], Psr7\stream_for(
                           '{
                        "active": true,
                        "client_id": "l238j323ds-23ij4",
                        "username": "jdoe",
                        "sub": "Z5O3upPC88QrAjx00dis",
                        "aud": "https://protected.example.net/resource",
                        "iss": "https://server.example.com/",
                        "exp": 1419356238,
                        "iat": 1419350238,
                        "extension_field": "twenty-seven"
                    }'
                       )
                ),
            ]
        );

        $middleware->setClient(
            new Client (
                [
                    'handler' => HandlerStack::create($mock),
                ]
            )
        );

        $request = Request::create('http://example.com/admin', 'GET');
        $request->headers->set('Authorization', 'Bearer test123');

        $response = $middleware->handle(
            $request, function () {
            return true;
        }
        );

        $this->assertTrue($response);
    }

}


