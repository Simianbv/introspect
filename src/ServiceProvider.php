<?php

/**
 * @copyright (c) Simian B.V. 2019
 * @version       1.0.0
 */

namespace Simianbv\Introspect;

use Illuminate\Support\ServiceProvider as ServiceProviderAlias;

/**
 * @description Laravel ServiceProvider for registering the routes and publishing the configuration.
 * @class       ServiceProvider
 * @package     Simianbv\Introspect
 */
class ServiceProvider extends ServiceProviderAlias
{
    /**
     * @return void
     */
    public function boot()
    {
        $base = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR;
        $this->publishes([$base . 'config' . DIRECTORY_SEPARATOR . 'introspect.php' => config_path('introspect.php'),]);
        $this->loadRoutesFrom($base . 'routes' . DIRECTORY_SEPARATOR . 'routes.php');
    }

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
    }

}
