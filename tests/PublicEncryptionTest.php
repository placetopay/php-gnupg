<?php


class PublicEncryptionTest extends TestCase
{

    public function testItEncryptsWithAPublicKey()
    {
        $gnuPG = $this->gnuPG();

        $signKeyId = 'BE7AB3555E1EB58B';
        $password = 'EmitterPass';
        $receiverKeyId = '8B143B2548F9875B';

        $message = 'This is a testing message';

        $encrypted = $gnuPG->encrypt($signKeyId, $password, $receiverKeyId, $message);

        if (!$encrypted) {
            $this->fail($gnuPG->error());
        } else {
            $this->assertNotEquals($message, $encrypted);
        }

        $decrypted = $gnuPG->decrypt($receiverKeyId, 'ReceiverPass', $encrypted);

        if (!$decrypted) {
            $this->fail($gnuPG->error());
        } else {
            $this->assertEquals($message, $decrypted);
        }

        $this->assertEquals($message, $decrypted);
    }

}