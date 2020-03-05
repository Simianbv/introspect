# Installation

Install the package on your resource server

~~~
composer require simianbv\introspect
~~~

and add the Service Provider in your `config/app.php`

~~~.php
'providers' => [
     // [..]
    \Simianbv\Introspect\ServiceProvider::class
     // [..]
];
~~~

and add the MiddleWare in your `App/Http/Kernel.php`

~~~.php
protected $routeMiddleware = [
    // [..]
    'introspect' => \Simianbv\Introspect\VerifyAccessToken::class,
    // [..]   
];
~~~  

publish the configuration

~~~
php artisan vendor:publish
~~~

Finally in your `.env` file, define the following properties

~~~.properties
# Url of the authorization server
INTROSPECT_URL="https://authorization.server.dom"
# Client Identifier as defined in https://tools.ietf.org/html/rfc6749#section-2.2
INTROSPECT_CLIENT_ID="123"
# The client secret
INTROSPECT_CLIENT_SECRET="abcdefg"
# Endpoint for requesting the access token
INTROSPECT_TOKEN_URL="${INTROSPECT_URL}/oauth/token"
# The OAuth2 Introspection endpoint https://tools.ietf.org/html/rfc7662
INTROSPECT_INTROSPECT_URL="${INTROSPECT_URL}/oauth/introspect"
# Optional configuration for requesting an OAuth2 access tokens using the implicit grant flow 
INTROSPECT_AUTHORIZATION_URL="${INTROSPECT_URL}/oauth/authorize"
INTROSPECT_REDIRECT_URL=https://my.machine.dom
# the cache prefix to create a unique key per microservice, defaults to the APP_NAME
INTROSPECT_CACHE_PREFIX=HR
# the endpoints for calling in customer/employee or user data
INTROSPECT_USERS_ENDPOINT="${INTROSPECT_URL}/api/users"
INTROSPECT_EMPLOYEES_ENDPOINT="${INTROSPECT_URL}/api/employees"
INTROSPECT_CUSTOMERS_ENDPOINT="${INTROSPECT_URL}/api/customers"
~~~

Now, use the middleware.

~~~.php
Route::group(['middleware'=>'introspect:required-scope1,required-scope2'], function () {
	Route::get('/endpoint1', 'UserController@index');
	Route::resource('/resource', 'OrderController');
});
~~~

