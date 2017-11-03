<?php

class TestCase extends PHPUnit_Framework_TestCase
{

    public function gnuPG()
    {
        return new PlacetoPay\GnuPG\GnuPG([
            'gpgExecutable' => null,
            'ringPath' => __DIR__ . '/../tests/gnupg-test'
        ]);
    }

}