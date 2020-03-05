<?php

/**
 * @copyright (c) Simian B.V. 2019
 * @version       1.0.0
 */

namespace Simianbv\Introspect\Contracts;

/**
 * @Interface RequiresAclVerification
 * @package   Simianbv\Introspect\Contracts
 */
interface RequiresAclVerification
{

    /**
     * Should return a boolean true if you want to exclude this controller from verifying ACL Access.
     *
     * @return bool
     */
    public function requiresAclVerification(): bool;

    /**
     * Should return a boolean false if you dont need this controller to be verified.
     *
     * @return bool
     */
    public function isExcludedFromAclVerification(): bool;


}
