<?php

namespace PlacetoPay\GnuPG\Messages;

use PlacetoPay\GnuPG\Runners\CommandResult;

class GenerateKeyResponse
{
    protected $success = false;
    protected $fingerprint = '';

    protected $result;

    public function __construct(bool $success, string $fingerprint, CommandResult $result)
    {
        $this->success = $success;
        $this->fingerprint = $fingerprint;
        $this->result = $result;
    }

    public static function fromResult(CommandResult $result)
    {
        $matches = [];
        $fingerprint = '';
        if (preg_match('/KEY_CREATED\s(\w+)\s(\w+)/', $result->output(), $matches)) {
            $fingerprint = $matches[2];
        }
        return new static((bool)$fingerprint, $fingerprint, $result);
    }

    public function isGenerated(): bool
    {
        return $this->success;
    }

    public function fingerprint(): string
    {
        return $this->fingerprint;
    }

    public function commandResult(): ?CommandResult
    {
        return $this->result;
    }
}
