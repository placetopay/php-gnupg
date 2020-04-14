<?php

namespace PlacetoPay\GnuPG\Entities;

class ArmoredKey
{
    protected $content = '';

    public function __construct(string $content = '')
    {
        $this->content = $content;
    }

    public function content(): string
    {
        return $this->content;
    }
}
