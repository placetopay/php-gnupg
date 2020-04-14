<?php

namespace Tests;

use PHPUnit\Framework\TestCase;
use PlacetoPay\GnuPG\GnuPG;

abstract class BaseTestCase extends TestCase
{
    protected static $generatedKey;
    protected static $generatedFingerprint;
    protected static $generatedPassPhrase = 'superSecretPhrase';
    protected static $importedKey = '464B9930963B3E57';

    /**
     * @return GnuPG
     */
    protected function gnuPG()
    {
        return new GnuPG([
            'gpgExecutable' => getenv('GPG1_PATH') ?: null,
            'ringPath' => __DIR__ . '/assets/ringpath',
            'ignoreTimeConflict' => true,
        ]);
    }
}
