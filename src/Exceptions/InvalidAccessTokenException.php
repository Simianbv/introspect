<?php

namespace Simianbv\Introspect\Exceptions;

use Exception;
use Throwable;

/**
 * @class   InvalidAccessTokenException
 * @package Simianbv\Introspect\Exceptions
 */
class InvalidAccessTokenException extends Exception
{
    private ?string $permissionToken;
    private array $missingScopes;

    public function __construct (
        $message = "",
        $code = 0,
        Throwable $previous = null,
        string $permissionToken = null,
        array $missingScopes = [])
    {
        parent::__construct($message, $code, $previous);
        $this->permissionToken = $permissionToken;
        $this->missingScopes = $missingScopes;
    }

    public function getPermissionToken (): ?string
    {
        return $this->permissionToken;
    }

    public function setPermissionToken (string $permissionToken): void
    {
        $this->permissionToken = $permissionToken;
    }

    public function getMissingScopes (): array
    {
        return $this->missingScopes;
    }

    public function setMissingScopes (array $missingScopes): void
    {
        $this->missingScopes = $missingScopes;
    }
}
