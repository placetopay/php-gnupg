<?php

namespace PlacetoPay\GnuPG;

use PlacetoPay\GnuPG\Entities\PGPKey;
use PlacetoPay\GnuPG\Exception\InvalidArgumentException;
use PlacetoPay\GnuPG\Messages\ArmoredKeyResponse;
use PlacetoPay\GnuPG\Messages\GenerateKeyResponse;
use PlacetoPay\GnuPG\Messages\ListKeysResponse;
use PlacetoPay\GnuPG\Runners\Command;

/**
 * Class to interact with the gnuPG.
 */
class GnuPG
{
    // Certification / Thrust Level
    /**
     * Means you make no particular claim as to how carefully you verified the key.
     */
    const CERT_LEVEL_NONE = 0;

    /**
     * Means you believe the key is owned by the person who claims to own it but you could not, or did not verify the key at all.
     */
    const CERT_LEVEL_PRESUMPTION = 1;

    /**
     * Means you did casual verification of the key.
     */
    const CERT_LEVEL_CASUAL = 2;

    /**
     * Means you did extensive verification of the key.
     */
    const CERT_LEVEL_FULL = 3;

    /**
     * the path to gpg executable (default: /usr/local/bin/gpg).
     * @var string
     */
    private $gpgExecutable;

    /**
     * The path to directory where personal gnupg files (keyrings, etc) are stored (default: ~/.gnupg).
     * @var string
     */
    private $ringPath;

    /**
     * @var array
     */
    private $additional = [];

    /**
     * Create the gnuPG object.
     *
     * Set the program path for the GNUPG and the home directory of the keyring.
     * If this parameters are not specified, according to the OS the function derive the values.
     * @param array $settings
     */
    public function __construct($settings = [])
    {
        $gpgExecutable = isset($settings['gpgExecutable']) ? $settings['gpgExecutable'] : null;
        $ringPath = isset($settings['ringPath']) ? $settings['ringPath'] : null;

        $ignoreTimeConflict = isset($settings['ignoreTimeConflict']) ? $settings['ignoreTimeConflict'] : null;
        if ($ignoreTimeConflict) {
            $this->additional[] = '--ignore-time-conflict';
        }

        if (empty($gpgExecutable)) {
            if (strstr(PHP_OS, 'WIN')) {
                $gpgExecutable = 'C:\gnupg\gpg';
            } elseif (@file_exists('/usr/local/bin/gpg1')) {
                $gpgExecutable = '/usr/local/bin/gpg1';
            } else {
                $gpgExecutable = '/usr/local/bin/gpg1';
            }
        }

        // if is empty the home directory then assume based in the OS
        if (empty($ringPath)) {
            if (strstr(PHP_OS, 'WIN')) {
                $ringPath = 'C:\gnupg';
            } else {
                $ringPath = '~/.gnupg';
            }
        }

        if (!is_executable($gpgExecutable)) {
            throw new InvalidArgumentException('The GnuPG executable file does not exist or can not be executed.', 1010);
        }
        if (!is_dir($ringPath)) {
            throw new InvalidArgumentException('The ring path is not a directory or does not exists.', 1020);
        }

        $this->gpgExecutable = $gpgExecutable;
        $this->ringPath = $ringPath;
    }

    public function ringPath(): string
    {
        return $this->ringPath;
    }

    public function gpgExecutable(): string
    {
        return $this->gpgExecutable;
    }

    protected function buildGnuPGCommand(): string
    {
        return $this->gpgExecutable . ' --homedir ' . $this->ringPath . ($this->additional ? ' ' . implode(' ', $this->additional) : '');
    }

    public function genKey(PGPKey $key, string $passphrase): GenerateKeyResponse
    {
        // validates the keytype
        if (($key->type() != 'DSA') && ($key->type() != 'RSA')) {
            throw new InvalidArgumentException('Invalid Key-Type, the allowed are DSA and RSA.', 1070);
        }

        // validate the expiration date
        if (!preg_match('/^(([0-9]+[dwmy]?)|([0-9]{4}-[0-9]{2}-[0-9]{2}))$/', $key->expirationDate())) {
            throw new InvalidArgumentException('Invalid Expire Date, the allowed values are <iso-date>|(<number>[d|w|m|y]).', 1072);
        }

        // execute the GPG command
        $result = Command::create($this->buildGnuPGCommand(), [
            '--batch' => null,
            '--status-fd' => '1',
            '--gen-key' => null,
        ])->run($key->asGenerationInput($passphrase));

        return GenerateKeyResponse::fromResult($result);
    }

    public function listKeys(string $kind = '', string $criteria = ''): ListKeysResponse
    {
        $arguments = [
            '--with-colons' => null,
            '--with-fingerprint' => null,
        ];

        switch ($kind) {
            case '':
                $arguments['--list-keys'] = null;
                break;
            case PGPKey::KIND_SECRET:
                $arguments['--list-secret-keys'] = $criteria ?: null;
                break;
            case PGPKey::KIND_PUBLIC:
                $arguments['--list-public-keys'] = $criteria ?: null;
                break;
        }

        $result = Command::create($this->buildGnuPGCommand(), $arguments)->run();

        return ListKeysResponse::fromResult($result);
    }

    public function listSecretKeys(string $criteria = '')
    {
        return $this->listKeys(PGPKey::KIND_SECRET, $criteria);
    }

    public function listPublicKeys(string $criteria = '')
    {
        return $this->listKeys(PGPKey::KIND_PUBLIC, $criteria);
    }

    public function export(string $keyId = ''): ArmoredKeyResponse
    {
        $result = Command::create($this->buildGnuPGCommand(), [
            '--armor' => null,
            '--export' => $keyId ?: null,
        ])->run();

        return ArmoredKeyResponse::fromResult($result);
    }

    /**
     * Import/merge keys.
     *
     * This adds the given keys to the keyring. New keys are appended to your
     * keyring and already existing keys are updated. Note that GnuPG does not
     * import keys that are not self-signed.
     *
     * @param string $keyBlock The PGP block with the key(s).
     * @return false|array  false on error, the array with [KeyID, UserID] elements of imported keys on success.
     */
    public function import($keyBlock)
    {
        // Verify for the Key block contents
        if (empty($keyBlock)) {
            throw new InvalidArgumentException('No valid key block was specified.', 1060);
        }

        // initialize the output
        $contents = '';

        // execute the GPG command
        if ($this->forkProcess($this->buildGnuPGCommand([
            '--status-fd' => '1',
            '--import' => null,
        ]),
            $keyBlock, $contents)) {
            // initialize the array data
            $imported_keys = [];

            // parse the imported keys
            $contents = explode("\n", $contents);
            foreach ($contents as $data) {
                $matches = false;
                if (preg_match('/\[GNUPG:\]\sIMPORTED\s(\w+)\s(.+)/', $data, $matches)) {
                    array_push($imported_keys, [
                        'KeyID' => $matches[1],
                        'UserID' => $matches[2],]);
                }
            }
            return $imported_keys;
        } else {
            return false;
        }
    }

    /**
     * Encrypt and sign data.
     *
     * @param string $keyId the key id used to encrypt
     * @param string $passPhrase the pass phrase to open the key used to encrypt
     * @param string $recipientKeyId the recipient key id
     * @param string $text data to encrypt
     * @param bool $sign indicates if must sign the content
     * @return false|string  false on error, the encrypted data on success
     */
    public function encrypt($keyId, $passPhrase, $recipientKeyId, $text, $sign = true)
    {
        if (empty($keyId)) {
            throw new InvalidArgumentException('You must specify the KeyID used to encrypt.', 1080);
        }
        if (empty($recipientKeyId)) {
            throw new InvalidArgumentException('You must specify the RecipientKeyID who will receive the message.', 1081);
        }

        // initialize the output
        $contents = '';

        // execute the GPG command
        $options = [
            '--batch' => null,
            '--yes' => null,
            '--armor' => null,
            '--passphrase-fd' => '0',
            '--local-user' => $keyId,
            '--default-key' => $keyId,
            '--recipient' => $recipientKeyId,
            '--encrypt' => null,
        ];
        if ($sign) {
            $options = array_merge([
                '--sign' => null,
                '--force-v3-sigs' => null,
            ], $options);
        }
        $result = $this->forkProcess($this->buildGnuPGCommand($options),
            $passPhrase . "\n" . $text, $contents);

        // execute the GPG command
        if ($result) {
            return trim($contents);
        } else {
            return false;
        }
    }

    /**
     * Encrypt and sign a file.
     *
     * @param string $keyId the key id used to encrypt
     * @param string $passPhrase the pass phrase to open the key used to encrypt
     * @param string $recipientKeyId the recipient key id
     * @param string $inputFile file to encrypt
     * @param string $outputFile file encrypted
     * @param bool $sign indicates if must sign the content
     * @return false|string  false on error, the encrypted data on success
     */
    public function encryptFile($keyId, $passPhrase, $recipientKeyId, $inputFile, $outputFile, $sign = true)
    {
        if (empty($keyId)) {
            throw new InvalidArgumentException('You must specify the KeyID used to encrypt.', 1090);
        }
        if (empty($recipientKeyId)) {
            throw new InvalidArgumentException('You must specify the RecipientKeyID who will receive the message.', 1091);
        }
        if (!is_readable($inputFile)) {
            throw new InvalidArgumentException('The file to be encrypted must exist.', 1092);
        }

        // initialize the output
        $contents = '';

        // execute the GPG command
        $options = [
            '--batch' => null,
            '--yes' => null,
            '--armor' => null,
            '--passphrase-fd' => '0',
            '--local-user' => $keyId,
            '--default-key' => $keyId,
            '--recipient' => $recipientKeyId,
            '--output' => $outputFile,
            '--encrypt' => $inputFile,
        ];
        if ($sign) {
            $options = array_merge([
                '--sign' => null,
                '--force-v3-sigs' => null,
            ], $options);
        }
        if ($this->forkProcess($this->buildGnuPGCommand($options),
            $passPhrase . "\n", $contents)) {
            return $contents;
        } else {
            return false;
        }
    }

    /**
     * Decrypt the data.
     *
     * If the decrypted file is signed, the signature is also verified.
     *
     * @param string $keyId the key id to decrypt
     * @param string $passPhrase the passphrase to open the key used to decrypt
     * @param string $text data to decrypt
     * @return mixed  false on error, the clear (decrypted) data on success
     */
    public function decrypt($keyId, $passPhrase, $text)
    {
        if (empty($keyId)) {
            throw new InvalidArgumentException('You must specify the KeyID used to decrypt.', 1100);
        }

        // the text to decrypt from another platforms can has a bad sequence
        // this line removes the bad data and converts to line returns
        $text = preg_replace("/\x0D\x0D\x0A/s", "\n", $text);

        // we generate an array and add a new line after the PGP header
        $text = explode("\n", $text);
        if (count($text) > 1) {
            $text[1] .= "\n";
        }
        $text = implode("\n", $text);

        // initialize the output
        $contents = '';

        // execute the GPG command
        if ($this->forkProcess($this->buildGnuPGCommand([
            '--batch' => null,
            '--yes' => null,
            '--passphrase-fd' => '0',
            '--local-user' => $keyId,
            '--default-key' => $keyId,
            '--decrypt' => null,
        ]),
            $passPhrase . "\n" . $text, $contents)) {
            return $contents;
        } else {
            return false;
        }
    }

    /**
     * Decrypt a file.
     *
     * If the decrypted file is signed, the signature is also verified.
     *
     * @param string $keyId the key id to decrypt
     * @param string $passPhrase the pass phrase to open the key used to decrypt
     * @param string $inputFile file to decrypt
     * @param string $outputFile file decrypted
     * @return mixed  false on error, the clear (decrypted) data on success
     */
    public function decryptFile($keyId, $passPhrase, $inputFile, $outputFile)
    {
        if (empty($keyId)) {
            throw new InvalidArgumentException('You must specify the KeyID used to decrypt.', 1110);
        }
        if (!is_readable($inputFile)) {
            throw new InvalidArgumentException('The file to be decrypted must exist.', 1111);
        }

        // initialize the output
        $contents = '';

        // execute the GPG command
        if ($this->forkProcess($this->buildGnuPGCommand([
            '--batch' => null,
            '--yes' => null,
            '--passphrase-fd' => '0',
            '--local-user' => $keyId,
            '--default-key' => $keyId,
            '--output' => $outputFile,
            '--decrypt' => $inputFile,
        ]),
            $passPhrase . "\n", $contents)) {
            return $contents;
        } else {
            return false;
        }
    }

    /**
     * Remove key from the public keyring.
     *
     * If secret is specified it try to remove the key from from the secret
     * and public keyring.
     * The returned error codes are:
     * 1 = no such key
     * 2 = must delete secret key first
     * 3 = ambiguous specification
     *
     * @param string $keyId the key id to be removed, if this is the secret key you must specify the fingerprint
     * @param string $keyKind the kind of the keys, can be secret or public
     * @return bool|string  true on success, otherwise false or the delete error code
     */
    public function deleteKey($keyId, $keyKind = self::KEY_KIND_PUBLIC)
    {
        if (empty($keyId)) {
            throw new InvalidArgumentException('You must specify the KeyID to delete.', 1120);
        }

        // validate the KeyKind
        $keyKind = strtolower(substr($keyKind, 0, 3));
        if (($keyKind != 'pub') && ($keyKind != 'sec')) {
            throw new InvalidArgumentException('The Key kind must be public or secret.', 1121);
        }

        // initialize the output
        $contents = '';

        // execute the GPG command
        if ($this->forkProcess($this->buildGnuPGCommand([
            '--batch' => null,
            '--yes' => null,
            '--status-fd' => '1',
            (($keyKind == 'pub') ? '--delete-key' : '--delete-secret-keys') => $keyId,
        ]),
            false, $contents)) {
            return true;
        } else {
            $matches = [];
            if (preg_match('/\[GNUPG:\]\DELETE_PROBLEM\s(\w+)/', $contents, $matches)) {
                return $matches[1];
            } else {
                return false;
            }
        }
    }

    /**
     * Sign the recipient key with the private key.
     *
     * @param string $keyId the key id used to sign
     * @param string $passPhrase the pass phrase to open the key used to sign
     * @param string $recipientKeyId the recipient key id to be signed
     * @param int $certificationLevel the level of thrust for the recipient key
     *    0 : means you make no particular claim as to how carefully you verified the key
     *    1 : means you believe the key is owned by the person who claims to own it but you could not, or did not verify the key at all
     *    2 : means you did casual verification of the key
     *    3 : means you did extensive verification of the key
     * @return bool|string true on success, otherwise false or the sign error code
     */
    public function signKey($keyId, $passPhrase, $recipientKeyId, $certificationLevel = self::CERT_LEVEL_NONE)
    {
        if (empty($keyId)) {
            throw new InvalidArgumentException('You must specify the KeyID used to sign.', 1130);
        }
        if (empty($recipientKeyId)) {
            throw new InvalidArgumentException('You must specify the RecipientKeyID to be signed.', 1131);
        }

        // initialize the output
        $contents = '';

        // execute the GPG command
        if ($this->forkProcess($this->buildGnuPGCommand([
            '--batch' => null,
            '--yes' => null,
            '--expert' => null,
            '--no-ask-cert-level' => null,
            '--passphrase-fd' => '0',
            '--status-fd' => '1',
            '--local-user' => $keyId,
            '--default-key' => $keyId,
            '--default-cert-level' => strval($certificationLevel),
            '--sign-key' => $recipientKeyId,
        ]),
            $passPhrase . "\n", $contents)) {
            return $contents;
        } else {
            return false;
        }
    }
}
