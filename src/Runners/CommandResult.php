<?php

namespace PlacetoPay\GnuPG\Runners;

class CommandResult
{
    protected $command;
    protected $returnCode = -1;
    protected $output = '';
    protected $error = '';

    public function __construct($returnCode, string $output, string $error, Command $command)
    {
        $this->returnCode = $returnCode;
        $this->output = $output;
        $this->error = $error;
        $this->command = $command;
    }

    public function output(): string
    {
        return $this->output;
    }

    public function error()
    {
        return $this->error;
    }

    public function isSuccessful()
    {
        return $this->returnCode === 0;
    }

    public function command(): Command
    {
        return $this->command;
    }
}
