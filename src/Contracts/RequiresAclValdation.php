<?php

namespace Simianbv\Introspect\Contracts;

/**
 * @Interface RequiresAclValdation
 * @package   Simianbv\Introspect\Contracts
 */
interface RequiresAclValdation
{

    /**
     * Should return a boolean true if you want to exclude this controller from verifying ACL Access.
     *
     * @return bool
     */
    public function excludeFromAclVerification(): bool;
}
