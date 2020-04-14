<?php

namespace Tests\Feature;

use PlacetoPay\GnuPG\Entities\PGPKey;
use Tests\BaseTestCase;

class KeyGenerationTest extends BaseTestCase
{
    /**
     * @test
     */
    public function it_generates_a_key_correctly()
    {
        $gpg = $this->gnuPG();
        $result = $gpg->genKey(new PGPKey([
            'name' => 'TestCase',
            'comment' => 'Used for unit test',
            'email' => 'testing@testing.com',
            'expirationDate' => '5y',
        ]), self::$generatedPassPhrase);

        $this->assertTrue($result->isGenerated(), $result->commandResult()->error());
        $this->assertIsString($result->fingerprint());

        $keyData = $gpg->listKeys(PGPKey::KIND_SECRET, $result->fingerprint());

        $this->assertGreaterThan(0, $keyData->count());
        $this->assertEquals($result->fingerprint(), $keyData->keys()[0]->fingerprint());
        $this->assertEquals('testing@testing.com', $keyData->keys()[0]->email());
        
        // Subtract one day dont know why, but GPG calculates it like this
        $dateInFiveYears = (new \DateTime())->add(\DateInterval::createFromDateString('+5 years -1 day'))->format('Y-m-d');
        $this->assertEquals($dateInFiveYears, $keyData->keys()[0]->expirationDate());
    }

    /**
     * @test
     */
    public function it_list_keys_correctly()
    {
        $gpg = $this->gnuPG();
        $keyData = $gpg->listSecretKeys();
        $keyData = $gpg->listPublicKeys();

        $this->assertNotNull($keyData);
    }

    /**
     * @test
     */
    public function it_exports_correctly_a_public_key()
    {
        $gpg = $this->gnuPG();
        $keyData = $gpg->listKeys();
        $this->assertGreaterThan(0, $keyData->count());
        $key = $keyData->keys()[0];
        
        $result = $gpg->export($key->fingerprint());
        $this->assertStringContainsString('BEGIN PGP PUBLIC KEY BLOCK', $result->content());
    }
}
