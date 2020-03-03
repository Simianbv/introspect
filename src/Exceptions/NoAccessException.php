<?php

namespace Simianbv\Introspect\Exceptions;

use Exception;
use Throwable;

/**
 * @class   NoAccessException
 * @package Simianbv\Introspect\Exceptions
 */
class NoAccessException extends Exception
{
    /**
     * @var string
     */
    private $token = '';

    /**
     * NoAccessException constructor.
     *
     * @param string         $message
     * @param int            $code
     * @param Throwable|null $previous
     * @param string         $token
     */
    public function __construct($message = "", $code = 0, Throwable $previous = null, string $token = '')
    {
        parent::__construct($message, $code, $previous);
        if ($token !== '') {
            $this->token = $token;
        }
    }

    /**
     * @return string
     */
    public function getToken()
    {
        return $this->token;
    }
}
