<?php

namespace PlacetoPay\GnuPG\Messages;

use PlacetoPay\GnuPG\Entities\ArmoredKey;
use PlacetoPay\GnuPG\Runners\CommandResult;

class ArmoredKeyResponse extends ArmoredKey
{
    protected $success = false;
    protected $result;

    public function __construct(bool $success, CommandResult $result)
    {
        parent::__construct($result->output());
        $this->success = $success;
        $this->result = $result;
    }

    public static function fromResult(CommandResult $result)
    {
        return new self($result->isSuccessful(), $result);
    }

    public function commandResult(): ?CommandResult
    {
        return $this->result;
    }
}
