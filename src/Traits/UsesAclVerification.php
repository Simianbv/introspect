<?php

/**
 * @copyright (c) Simian B.V. 2019
 * @version       1.0.0
 */

namespace Simianbv\Introspect\Traits;

/**
 * @trait   UsesAclVerification
 * @package Simianbv\Introspect\Traits
 */
trait UsesAclVerification
{

    /**
     * @var bool
     */
    protected $acl_verification = true;

    /**
     * @return bool
     */
    public function requiresAclVerification()
    {
        return $this->acl_verification === true;
    }

    /**
     * @return bool
     */
    public function isExcludedFromAclVerification()
    {
        return $this->acl_verification === false;
    }


}
