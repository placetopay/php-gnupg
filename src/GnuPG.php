<?php

namespace PlacetoPay\GnuPG;


use PlacetoPay\GnuPG\Exception\InvalidArgumentException;

/**
 * Class to interact with the gnuPG.
 */
class GnuPG
{
    // Certification / Thrust Level
    /**
     * Means you make no particular claim as to how carefully you verified the key
     */
    const CERT_LEVEL_NONE = 0;

    /**
     * Means you believe the key is owned by the person who claims to own it but you could not, or did not verify the key at all
     */
    const CERT_LEVEL_PRESUMPTION = 1;

    /**
     * Means you did casual verification of the key
     */
    const CERT_LEVEL_CASUAL = 2;

    /**
     * Means you did extensive verification of the key
     */
    const CERT_LEVEL_FULL = 3;

    /**
     * Public key
     */
    const KEY_KIND_PUBLIC = 'public';

    /**
     * Secret key
     */
    const KEY_KIND_SECRET = 'secret';

    /**
     * Key type RSA
     */
    const KEY_TYPE_RSA = 'RSA';

    /**
     * Key type DSA
     */
    const KEY_TYPE_DSA = 'DSA';

    /**
     * the path to gpg executable (default: /usr/local/bin/gpg)
     * @var string
     */
    private $gpgExecutable;

    /**
     * The path to directory where personal gnupg files (keyrings, etc) are stored (default: ~/.gnupg)
     * @var string
     */
    private $ringPath;

    /**
     * Error and status messages
     * @var string
     */
    protected $error;

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
            } elseif (@file_exists('/usr/local/bin/gpg')) {
                $gpgExecutable = '/usr/local/bin/gpg';
            } else {
                $gpgExecutable = '/usr/local/bin/gpg2';
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

        if (!is_executable($gpgExecutable))
            throw new InvalidArgumentException('The GnuPG executable file does not exist or can not be executed.', 1010);
        if (!is_dir($ringPath))
            throw new InvalidArgumentException('The ring path is not a directory or does not exists.', 1020);

        $this->gpgExecutable = $gpgExecutable;
        $this->ringPath = $ringPath;
    }

    /**
     * @return string
     */
    public function ringPath()
    {
        return $this->ringPath;
    }

    /**
     * @return string
     */
    public function gpgExecutable()
    {
        return $this->gpgExecutable;
    }

    /**
     * @return string
     */
    public function error()
    {
        return $this->error;
    }

    /**
     * Build the GnuPG command based on the arguments
     * @param array $arguments
     * @return string
     */
    protected function buildGnuPGCommand($arguments = [])
    {
        $command = escapeshellcmd($this->gpgExecutable) .
            ' --homedir ' . escapeshellarg($this->ringPath);

        if (!empty($this->additional))
            $command .= ' ' . implode(' ', $this->additional);

        foreach ($arguments as $key => $value) {
            if (!isset($value))
                $command .= ' ' . $key;
            else
                $command .= ' ' . $key . ' ' . escapeshellarg($value);
        }

        return $command;
    }

    /**
     * Call a subprogram redirecting the standard pipes
     * @param string $command
     * @param bool $input
     * @param string $output
     * @return bool
     */
    private function forkProcess($command, $input = false, &$output)
    {
        // define the redirection pipes
        $descriptorSpec = [
            0 => ['pipe', 'r'],  // stdin is a pipe that the child will read from
            1 => ['pipe', 'w'],  // stdout is a pipe that the child will write to
            2 => ['pipe', 'w']   // stderr is a pipe that the child will write to
        ];
        $pipes = null;

        // calls the process
        $process = proc_open($command, $descriptorSpec, $pipes);
        if (is_resource($process)) {
            // writes the input
            if (!empty($input)) fwrite($pipes[0], $input);
            fclose($pipes[0]);

            // reads the output
            while (!feof($pipes[1])) {
                $data = fread($pipes[1], 1024);
                if (strlen($data) == 0) break;
                $output .= $data;
            }
            fclose($pipes[1]);

            // reads the error message
            $result = '';
            while (!feof($pipes[2])) {
                $data = fread($pipes[2], 1024);
                if (strlen($data) == 0) break;
                $result .= $data;
            }
            fclose($pipes[2]);

            // close the process
            $status = proc_close($process);

            // returns the contents
            $this->error = $result;
            return (($status == 0) || ($status == -1));
        } else {
            $this->error = 'Unable to fork the command';
            return false;
        }
    }

    /**
     * Get the keys from the KeyRing.
     *
     * The returned array get the following elements:
     * [RecordType, CalculatedTrust, KeyLength, Algorithm,
     *  KeyID, CreationDate, ExpirationDate, LocalID,
     *  Ownertrust, UserID]
     *
     * @param  string $keyKind the kind of the keys, can be secret or public
     * @param  string $searchCriteria the filter or criteria to search
     * @return false|array  false on error, the array with the keys in the keyring in success
     */
    public function listKeys($keyKind = self::KEY_KIND_PUBLIC, $searchCriteria = '')
    {
        // validate the KeyKind
        $keyKind = strtolower(substr($keyKind, 0, 3));
        if (($keyKind != 'pub') && ($keyKind != 'sec'))
            throw new InvalidArgumentException('The Key kind must be public or secret.', 1050);

        // initialize the output
        $contents = '';

        // execute the GPG command
        if ($this->forkProcess($this->buildGnuPGCommand([
            '--with-colons' => null,
            '--with-fingerprint' => null,
            (($keyKind == 'pub') ? '--list-public-keys' : '--list-secret-keys') => (empty($searchCriteria) ? null : $searchCriteria)
        ]),
            false, $contents)) {

            // initialize the array data
            $returned_keys = array();
            $keyPos = -1;

            // the keys are \n separated
            $contents = explode("\n", $contents);

            // find each key
            foreach ($contents as $data) {
                // read the fields to get the : separated, the sub record is dismiss
                $fields = explode(':', $data);
                if (count($fields) <= 3) continue;

                // verify the that the record is valid
                if (($fields[0] == 'pub') || ($fields[0] == 'sec')) {
                    array_push($returned_keys, array(
                            'RecordType' => $fields[0],
                            'CalculatedTrust' => $fields[1],
                            'KeyLength' => $fields[2],
                            'Algorithm' => $fields[3],
                            'KeyID' => $fields[4],
                            'CreationDate' => $fields[5],
                            'ExpirationDate' => $fields[6],
                            'LocalID' => $fields[7],
                            'Ownertrust' => $fields[8],
                            'UserID' => $fields[9],
                            'Fingerprint' => ''
                        )
                    );
                    $keyPos++;
                } elseif ($keyPos != -1) {
                    switch ($fields[0]) {
                        case 'uid':
                            if (empty($returned_keys[$keyPos]['UserID']))
                                $returned_keys[$keyPos]['UserID'] = $fields[9];
                            break;
                        case 'fpr':
                            if (empty($returned_keys[$keyPos]['UserID']))
                                $returned_keys[$keyPos]['Fingerprint'] = $fields[9];
                            break;
                    }
                }
            }
            return $returned_keys;
        } else
            return false;
    }

    /**
     * Export a key.
     *
     * Export all keys from all keyrings, or if at least one name is given, those of the given name.
     *
     * @param $keyId
     * @return false|string  false on error, the key block with the exported keys
     */
    public function export($keyId = null)
    {
        $keyId = empty($keyId) ? '' : $keyId;

        // initialize the output
        $contents = '';

        // execute the GPG command
        if ($this->forkProcess($this->buildGnuPGCommand([
            '--armor' => null,
            '--export' => $keyId
        ]),
            false, $contents))
            return (empty($contents) ? false : $contents);
        else
            return false;
    }

    /**
     * Import/merge keys.
     *
     * This adds the given keys to the keyring. New keys are appended to your
     * keyring and already existing keys are updated. Note that GnuPG does not
     * import keys that are not self-signed.
     *
     * @param  string $keyBlock The PGP block with the key(s).
     * @return false|array  false on error, the array with [KeyID, UserID] elements of imported keys on success.
     */
    public function import($keyBlock)
    {
        // Verify for the Key block contents
        if (empty($keyBlock))
            throw new InvalidArgumentException('No valid key block was specified.', 1060);

        // initialize the output
        $contents = '';

        // execute the GPG command
        if ($this->forkProcess($this->buildGnuPGCommand([
            '--status-fd' => '1',
            '--import' => null
        ]),
            $keyBlock, $contents)) {
            // initialize the array data
            $imported_keys = array();

            // parse the imported keys
            $contents = explode("\n", $contents);
            foreach ($contents as $data) {
                $matches = false;
                if (preg_match('/\[GNUPG:\]\sIMPORTED\s(\w+)\s(.+)/', $data, $matches))
                    array_push($imported_keys, array(
                        'KeyID' => $matches[1],
                        'UserID' => $matches[2]));
            }
            return $imported_keys;
        } else
            return false;
    }

    /**
     * Generate a new key pair.
     *
     * @param  string $realName The real name of the user or key.
     * @param  string $comment Any explanatory commentary.
     * @param  string $email The e-mail for the user.
     * @param  string $passPhrase Pass phrase for the secret key, default is not to use any passphrase.
     * @param  int|string $expireDate Set the expiration date for the key (and the subkey).  It may either be entered in ISO date format (2000-08-15) or as number of days, weeks, month or years (<number>[d|w|m|y]). Without a letter days are assumed.
     * @param  string $keyType Set the type of the key, the allowed values are DSA and RSA, default is DSA.
     * @param  int $keyLength Length of the key in bits, default is 1024.
     * @param  string $subKeyType This generates a secondary key, currently only one subkey can be handled ELG-E.
     * @param  int $subKeyLength Length of the subkey in bits, default is 1024.
     * @return boolean|array  false on error, the fingerprint of the created key pair in success
     */
    public function genKey($realName, $comment, $email, $passPhrase = '', $expireDate = 0, $keyType = 'DSA', $keyLength = 1024, $subKeyType = 'ELG-E', $subKeyLength = 1024)
    {
        // validates the keytype
        if (($keyType != 'DSA') && ($keyType != 'RSA'))
            throw new InvalidArgumentException('Invalid Key-Type, the allowed are DSA and RSA.', 1070);

        // validates the subkey
        if ((!empty($subKeyType)) && ($subKeyType != 'ELG-E'))
            throw new InvalidArgumentException('Invalid Subkey-Type, the allowed is ELG-E.', 1071);

        // validate the expiration date
        if (!preg_match('/^(([0-9]+[dwmy]?)|([0-9]{4}-[0-9]{2}-[0-9]{2}))$/', $expireDate))
            throw new InvalidArgumentException('Invalid Expire Date, the allowed values are <iso-date>|(<number>[d|w|m|y]).', 1072);

        // generates the batch configuration script
        $batch_script = "Key-Type: $keyType\n" .
            "Key-Length: $keyLength\n";
        if (($keyType == 'DSA') && ($subKeyType == 'ELG-E'))
            $batch_script .= "Subkey-Type: $subKeyType\n" .
                "Subkey-Length: $subKeyLength\n";
        $batch_script .= "Name-Real: $realName\n" .
            "Name-Comment: $comment\n" .
            "Name-Email: $email\n" .
            "Expire-Date: $expireDate\n" .
            "Passphrase: $passPhrase\n" .
            "%commit\n" .
            "%echo done with success\n";

        // initialize the output
        $contents = '';

        // execute the GPG command
        if ($this->forkProcess($this->buildGnuPGCommand([
            '--batch' => null,
            '--status-fd' => '1',
            '--gen-key' => null
        ]),
            $batch_script, $contents)) {
            $matches = false;
            if (preg_match('/\[GNUPG:\]\sKEY_CREATED\s(\w+)\s(\w+)/', $contents, $matches))
                return $matches[2];
            else
                return true;
        } else
            return false;
    }

    /**
     * Encrypt and sign data.
     *
     * @param  string $keyId the key id used to encrypt
     * @param  string $passPhrase the pass phrase to open the key used to encrypt
     * @param  string $recipientKeyId the recipient key id
     * @param  string $text data to encrypt
     * @param  bool $sign indicates if must sign the content
     * @return false|string  false on error, the encrypted data on success
     */
    public function encrypt($keyId, $passPhrase, $recipientKeyId, $text, $sign = true)
    {
        if (empty($keyId))
            throw new InvalidArgumentException('You must specify the KeyID used to encrypt.', 1080);
        if (empty($recipientKeyId))
            throw new InvalidArgumentException('You must specify the RecipientKeyID who will receive the message.', 1081);

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
            '--encrypt' => null
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
        if ($result)
            return trim($contents);
        else
            return false;
    }

    /**
     * Encrypt and sign a file.
     *
     * @param  string $keyId the key id used to encrypt
     * @param  string $passPhrase the pass phrase to open the key used to encrypt
     * @param  string $recipientKeyId the recipient key id
     * @param  string $inputFile file to encrypt
     * @param  string $outputFile file encrypted
     * @param  bool $sign indicates if must sign the content
     * @return false|string  false on error, the encrypted data on success
     */
    public function encryptFile($keyId, $passPhrase, $recipientKeyId, $inputFile, $outputFile, $sign = true)
    {
        if (empty($keyId))
            throw new InvalidArgumentException('You must specify the KeyID used to encrypt.', 1090);
        if (empty($recipientKeyId))
            throw new InvalidArgumentException('You must specify the RecipientKeyID who will receive the message.', 1091);
        if (!is_readable($inputFile))
            throw new InvalidArgumentException('The file to be encrypted must exist.', 1092);

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
            '--encrypt' => $inputFile
        ];
        if ($sign) {
            $options = array_merge([
                '--sign' => null,
                '--force-v3-sigs' => null,
            ], $options);
        }
        if ($this->forkProcess($this->buildGnuPGCommand($options),
            $passPhrase . "\n", $contents))
            return $contents;
        else
            return false;
    }

    /**
     * Decrypt the data.
     *
     * If the decrypted file is signed, the signature is also verified.
     *
     * @param  string $keyId the key id to decrypt
     * @param  string $passPhrase the passphrase to open the key used to decrypt
     * @param  string $text data to decrypt
     * @return mixed  false on error, the clear (decrypted) data on success
     */
    public function decrypt($keyId, $passPhrase, $text)
    {
        if (empty($keyId))
            throw new InvalidArgumentException('You must specify the KeyID used to decrypt.', 1100);

        // the text to decrypt from another platforms can has a bad sequence
        // this line removes the bad data and converts to line returns
        $text = preg_replace("/\x0D\x0D\x0A/s", "\n", $text);

        // we generate an array and add a new line after the PGP header
        $text = explode("\n", $text);
        if (count($text) > 1) $text[1] .= "\n";
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
            '--decrypt' => null
        ]),
            $passPhrase . "\n" . $text, $contents))
            return $contents;
        else
            return false;
    }

    /**
     * Decrypt a file.
     *
     * If the decrypted file is signed, the signature is also verified.
     *
     * @param  string $keyId the key id to decrypt
     * @param  string $passPhrase the pass phrase to open the key used to decrypt
     * @param  string $inputFile file to decrypt
     * @param  string $outputFile file decrypted
     * @return mixed  false on error, the clear (decrypted) data on success
     */
    public function decryptFile($keyId, $passPhrase, $inputFile, $outputFile)
    {
        if (empty($keyId))
            throw new InvalidArgumentException('You must specify the KeyID used to decrypt.', 1110);
        if (!is_readable($inputFile))
            throw new InvalidArgumentException('The file to be decrypted must exist.', 1111);

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
            '--decrypt' => $inputFile
        ]),
            $passPhrase . "\n", $contents))
            return $contents;
        else
            return false;
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
     * @param  string $keyId the key id to be removed, if this is the secret key you must specify the fingerprint
     * @param  string $keyKind the kind of the keys, can be secret or public
     * @return boolean|string  true on success, otherwise false or the delete error code
     */
    public function deleteKey($keyId, $keyKind = self::KEY_KIND_PUBLIC)
    {
        if (empty($keyId))
            throw new InvalidArgumentException('You must specify the KeyID to delete.', 1120);

        // validate the KeyKind
        $keyKind = strtolower(substr($keyKind, 0, 3));
        if (($keyKind != 'pub') && ($keyKind != 'sec'))
            throw new InvalidArgumentException('The Key kind must be public or secret.', 1121);

        // initialize the output
        $contents = '';

        // execute the GPG command
        if ($this->forkProcess($this->buildGnuPGCommand([
            '--batch' => null,
            '--yes' => null,
            '--status-fd' => '1',
            (($keyKind == 'pub') ? '--delete-key' : '--delete-secret-keys') => $keyId
        ]),
            false, $contents))
            return true;
        else {
            $matches = array();
            if (preg_match('/\[GNUPG:\]\DELETE_PROBLEM\s(\w+)/', $contents, $matches))
                return $matches[1];
            else
                return false;
        }
    }

    /**
     * Sign the recipient key with the private key.
     *
     * @param  string $keyId the key id used to sign
     * @param  string $passPhrase the pass phrase to open the key used to sign
     * @param  string $recipientKeyId the recipient key id to be signed
     * @param  int $certificationLevel the level of thrust for the recipient key
     *    0 : means you make no particular claim as to how carefully you verified the key
     *    1 : means you believe the key is owned by the person who claims to own it but you could not, or did not verify the key at all
     *    2 : means you did casual verification of the key
     *    3 : means you did extensive verification of the key
     * @return boolean|string true on success, otherwise false or the sign error code
     */
    public function signKey($keyId, $passPhrase, $recipientKeyId, $certificationLevel = self::CERT_LEVEL_NONE)
    {
        if (empty($keyId))
            throw new InvalidArgumentException('You must specify the KeyID used to sign.', 1130);
        if (empty($recipientKeyId))
            throw new InvalidArgumentException('You must specify the RecipientKeyID to be signed.', 1131);

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
            '--sign-key' => $recipientKeyId
        ]),
            $passPhrase . "\n", $contents))
            return $contents;
        else
            return false;
    }
}
