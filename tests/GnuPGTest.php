<?php

use PHPUnit\Framework\TestCase;
use PlacetoPay\GnuPG\GnuPG;

class GnuPGTest extends TestCase
{
    protected static $generatedKey;
    protected static $generatedFingerprint;
    protected static $generatedPassPhrase = 'superSecretPhrase';
    protected static $importedKey = '464B9930963B3E57';

    /**
     * @covers GnuPG::genKey()
     */
    public function testCreateKey()
    {
        $gpg = $this->gnuPG();
        $fingerprint = $gpg->genKey('TestCase', 'Used for unit test', 'testing@testing.com', self::$generatedPassPhrase, '5y');
        if ($fingerprint === false)
            $this->fail($gpg->error());

        $this->assertInternalType('string', $fingerprint, 'Expecting the fingerprint after key creation');
        self::$generatedFingerprint = $fingerprint;

        $keyData = $gpg->listKeys(GnuPG::KEY_KIND_SECRET, $fingerprint);
        if (($keyData === false) || empty($keyData))
            $this->fail($gpg->error());

        $this->assertEquals($fingerprint, $keyData[0]['Fingerprint'], 'Can not be vailidated the fingerprint');
        $this->assertContains('testing@testing.com', $keyData[0]['UserID'], 'Can not be recovered the created key');
        self::$generatedKey = $keyData[0]['KeyID'];
    }

    /**
     * @covers GnuPG::import()
     */
    public function testImportKey()
    {
        $keyToImport = <<<EOL
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: SKS 1.1.6
Comment: Hostname: pgp.mit.edu

mQGiBDvyljQRBAD10bo8xVTncADmqwcFb/BeetdirEDmR2Rkr55tLtDOxTWNar/pgecNCtAs
DUwGPFOVRk4wIZLejW3SJMP4Y/FfxDURK2iRuI5FvrBQaC6vY4pmU6WIet7t4mBqYV1jtaKZ
lfIwVxUiGCN+OoQVVYhYIxBOGPUltQ7JLoRrAc8dOwCg/49b9EZxTVeJcpTN862Vl8wvCqME
AJNKXDQ56iLRAJ2rjGcG9cbDWs9UtZboHBsREwIxZoYDVrZNYTFyKYudGKDPiVOse3u8NUYk
fY9l8PLLgF3R7yezYiufctttOMftF/9t1i+edaog2TlOHW/RKAg+Y5I42VLXzXAq2R6e9zTU
K7pVwhsNC8iyQRv+16+IsJFhDCESBADuRry4iArU+Zo8ezvkbfhV0wb17g3RcW1odInwkIX7
gpkLwGkZPkAe8h4p4w9MpbclAIQ2eUDhrccV7mszHUszfpmVleXIExJk5hJEyqsXvHMTxvuf
0LDvkmXy9DUaqrb8zMMAwnD4NMFp7TjsYdWZWMe5Hampmgl9hY4ZPZt2CLQiRW5yaXF1ZSBH
YXJj7WEgTS4gPGVnYXJjaWFAZWdtLmFzPohFBBARAgAGBQI8M8g2AAoJEEZLmTCWOz5XElMA
l3eNwT+hUAG58auuCsiQiZxahJoAniCJr/GddGJ4YjOQ3L7HdyIjNlq2tCNFbnJpcXVlIEdh
cmPtYSBNLiA8ZWdhcmNpYUBmc20ubmV0PohGBBARAgAGBQI8H4SIAAoJEEZLmTCWOz5XYRoA
niTCPlCABUFx4Anf2epksAvP1SxkAJ9MG7v9gWvMMTRN6yNNwxEQC39CGLQkRW5yaXF1ZSBH
YXJj7WEgTS4gPGVnbV9AaG90bWFpbC5jb20+iEYEEBECAAYFAjv3EIMACgkQRkuZMJY7PldZ
vgCgzYw+AMrLOPGJG5/wKKHlwb1Rm90AmgO+Lr/j4CqDSMbXKMvHX7LKgtQctCVFbnJpcXVl
IEdhcmPtYSBNLiA8ZWdhcmNhbUB5YWhvby5jb20+iEYEEBECAAYFAjv3EKQACgkQRkuZMJY7
PldjugCdH82PkiVDnzIzdbVxgpwPhW8/rGwAoJJ6WWs3Se2q0aDkIoODguRYSER6tCdFbnJp
cXVlIEdhcmPtYSBNLiA8ZWdhcmNpYUAxMDBwaWVzLmNvbT6IRgQQEQIABgUCO/KXaQAKCRBG
S5kwljs+V/AHAJ4pmDH00ZJ1vuLK1/bLZkyGRFm4pwCgvH7TXHhlGiqWRg6VbItLVnjKlOW0
J0VucmlxdWUgR2FyY+1hIE0uIDxlZ2FyY2lhQGNhc2hmb24ubmV0PohGBBARAgAGBQI78pei
AAoJEEZLmTCWOz5XAy8AmwW8tXeew5irbGb9k62V5thTNS1EAJ48Zkrl1NL15/+bLQk+2/qS
jxCHBLQnRW5yaXF1ZSBHYXJj7WEgTS4gPGVnYXJjaWFAdHV0b3BpYS5jb20+iEYEEBECAAYF
Ajv3EGYACgkQRkuZMJY7PlfCEQCfRaEqAQOTKnm74XYI3xP7fP/xL4kAnAlEsAnMQbVT9GOt
SMmTnd000OG6tChFbnJpcXVlIEdhcmPtYSBNLiA8ZWdhcmNpYUBjZW50cnVhbC5jb20+iEYE
EBECAAYFAjvyl4QACgkQRkuZMJY7PlcHcwCfQ7y77k+Bf8kGplmjwvCCsBkXuiQAoKRhlRR4
Jg23PypqjaYi7nMm1FlItClFbnJpcXVlIEdhcmPtYSBNLiA8ZWdhcmNpYUBlLWdhdHRhY2Eu
Y29tPohYBBARAgAYBQI78pY0CAsDCQgHAgEKAhkBBRsDAAAAAAoJEEZLmTCWOz5XWxoAn01x
KfPMZesH/W3XzDG4KrJ/Pqm4AJ4yu9x2eb3UB3Q0ZEfC0zsWl6KbcbQpRW5yaXF1ZSBHYXJj
7WEgTS4gPGVnYXJjaWFAcHJlbnNhbmV0LmNvbT6IRgQQEQIABgUCO/cREAAKCRBGS5kwljs+
V9xBAJ9WWeO/XOlAaOX3sO7hw+mvy7jXXACeOxN/KdZfXVFRGETmX3gRTdp6HCG0KkVucmlx
dWUgR2FyY+1hIE0uIDxlZ2FyY2lhQHBsYWNldG9wYXkuY29tPohGBBARAgAGBQI78pbdAAoJ
EEZLmTCWOz5Xk7kAoK87kPUSto6ZQgySHAXSHpx3gPt+AKC9UlbtIL5IycrRbFp0sXLiiCYo
IbkCDQQ78pY0EAgA9kJXtwh/CBdyorrWqULzBej5UxE5T7bxbrlLOCDaAadWoxTpj0BV89AH
xstDqZSt90xkhkn4DIO9ZekX1KHTUPj1WV/cdlJPPT2N286Z4VeSWc39uK50T8X8dryDxUcw
Yc58yWb/Ffm7/ZFexwGq01uejaClcjrUGvC/RgBYK+X0iP1YTknbzSC0neSRBzZrM2w4DUUd
D3yIsxx8Wy2O9vPJI8BD8KVbGI2Ou1WMuF040zT9fBdXQ6MdGGzeMyEstSr/POGxKUAYEY18
hKcKctaGxAMZyAcpesqVDNmWn6vQClCbAkbTCD1mpF1Bn5x8vYlLIhkmuquiXsNV6TILOwAC
AggAsmQ38c+HIFhOj4ri6Xg9fyyUK4IcGrpveaEJ+JifhG/Pw3xkfT1Q58y/ZilWMI1iutgh
LUxJAWL4zuaMTzSe2j9S1S+u5BTR/w57KIMeR7jRDZanGEH4CimGHyKHKDuxyZy8/pxulBPm
YazAdQ8UsAV50cWev/Sruq99fT3K7DkH7k1k3/cy/JS+VWvxfWqkHaW11bRNFVby/ZqeZv2H
InJEehkva/4CD61IBebLugPmJycDiuEsti25aMZfB+flXz9sG63i7c4uGm+CPfth1SOGnoD9
xhzKzRHrKQCHdakigU2yKZMzYsU5Xp1UR5Rjp6bWMIugmiyaebDL/bvEmIhMBBgRAgAMBQI7
8pY0BRsMAAAAAAoJEEZLmTCWOz5XthAAniDK6jYZUiwMj+SaImw+B/FkckCPAKD7edYNSYFd
RTEgpqwnZi4d4yH3Rg==
=RmsZ
-----END PGP PUBLIC KEY BLOCK-----
EOL;

        $gpg = $this->gnuPG();
        $imported = $gpg->import($keyToImport);
        if (($imported === false) || empty($imported))
            $this->fail($gpg->error());
        $this->assertEquals(self::$importedKey, $imported[0]['KeyID'], 'Expecting that the imported key');
    }

    /**
     * @depends testCreateKey
     * @depends testImportKey
     * @covers GnuPG::signKey()
     */
    public function testSignKey()
    {
        $gpg = $this->gnuPG();
        $signed = $gpg->signKey(self::$generatedFingerprint, self::$generatedPassPhrase, self::$importedKey, GnuPG::CERT_LEVEL_FULL);
        if ($signed === false)
            $this->fail($gpg->error());
    }

    /**
     * @depends testCreateKey
     * @covers GnuPG::encrypt()
     * @covers GnuPG::encryptFile()
     * @covers GnuPG::decrypt()
     * @covers GnuPG::decryptFile()
     */
    public function testEncryptDecrypt()
    {
        $receiverPassPhrase = 'ReceiverPass';
        $message = 'This is a testing message';

        $gpg = $this->gnuPG();

        // creates the receiver key, normally you just import the key and encrypt to that key
        // but for the test we create a new key
        $receiverFingerprint = $gpg->genKey('Receiver TestCase', 'Used for unit test', 'third@party.com', $receiverPassPhrase, 30);
        if ($receiverFingerprint === false)
            $this->fail($gpg->error());
        $this->assertInternalType('string', $receiverFingerprint, 'Expecting the fingerprint after key creation');

        // now get the keyId, since we have the fingerprint (you never get the fingerprint)
        // you also can encrypt with the fingerprint, but we do this extra step just to show the regular usage
        $keys = $gpg->listKeys(GnuPG::KEY_KIND_PUBLIC, $receiverFingerprint);
        if (($keys === false) || empty($keys))
            $this->fail($gpg->error());
        $receiverKey = $keys[0]['KeyID'];

        $encrypted = $gpg->encrypt(self::$generatedKey, self::$generatedPassPhrase, $receiverKey, $message);
        if ($encrypted === false)
            $this->fail($gpg->error());
        $this->assertNotEquals($message, $encrypted, 'Encryption error the encrypted message can not be the same that original message');

        $decrypted = $gpg->decrypt($receiverKey, $receiverPassPhrase, $encrypted);
        if ($encrypted === false)
            $this->fail($gpg->error());
        $this->assertEquals($message, $decrypted, 'Error on decryption the expected message differs');

        $inputFile = tempnam(__DIR__, 'it');
        $outputFile = tempnam(__DIR__, 'ot');
        file_put_contents($inputFile, $message);

        $encrypted = $gpg->encryptFile(self::$generatedKey, self::$generatedPassPhrase, $receiverKey, $inputFile, $outputFile);
        $this->assertNotFalse($encrypted, $gpg->error());
        $this->assertNotEquals($message, file_get_contents($outputFile), 'Encryption error the encrypted message can not be the same that original message');

        $decrypted = $gpg->decryptFile($receiverKey, $receiverPassPhrase, $outputFile, $inputFile);
        $this->assertNotFalse($decrypted, $gpg->error());
        $this->assertEquals($message, file_get_contents($inputFile), 'Error on decryption the expected message differs');
        unlink($inputFile);
        unlink($outputFile);

        // deletes the receiver created key
        $gpg->deleteKey($receiverFingerprint, GnuPG::KEY_KIND_SECRET);
        $gpg->deleteKey($receiverKey, GnuPG::KEY_KIND_PUBLIC);
    }

    /**
     * @depends testCreateKey
     * @depends testImportKey
     * @covers GnuPG::listKeys()
     */
    public function testListKeys()
    {
        $gpg = $this->gnuPG();

        $keys = $gpg->listKeys(GnuPG::KEY_KIND_SECRET);
        $this->assertEquals(1, count($keys), 'Invalid the list of secret keys');

        $keys = $gpg->listKeys(GnuPG::KEY_KIND_PUBLIC);
        $this->assertEquals(2, count($keys), 'Invalid the list of public keys');
    }

    /**
     * @depends testEncryptDecrypt
     * @depends testImportKey
     * @covers GnuPG::deleteKey()
     */
    public function testDeleteKeys()
    {
        // delete the created secret key
        $gpg = $this->gnuPG();
        $deleted = $gpg->deleteKey(self::$generatedFingerprint, GnuPG::KEY_KIND_SECRET);
        if ($deleted === false)
            $this->fail($gpg->error());
        $this->assertTrue($deleted, $deleted);

        // delete the created public key
        $deleted = $gpg->deleteKey(self::$generatedKey, GnuPG::KEY_KIND_PUBLIC);
        if ($deleted === false)
            $this->fail($gpg->error());
        $this->assertTrue($deleted, $deleted);

        // delete the imported key
        $deleted = $gpg->deleteKey(self::$importedKey, GnuPG::KEY_KIND_PUBLIC);
        if ($deleted === false)
            $this->fail($gpg->error());
        $this->assertTrue($deleted, $deleted);
    }

    /**
     * @return GnuPG
     */
    protected function gnuPG()
    {
        return new GnuPG([
            'gpgExecutable' => null,
            'ringPath' => __DIR__ . '/gnupg-test'
        ]);
    }
}