<?php

namespace PlacetoPay\GnuPG;

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

        $this->gpgExecutable = $gpgExecutable;
        $this->ringPath = $ringPath;

        if (empty($gpgExecutable)) {
            if (strstr(PHP_OS, 'WIN')) {
                $this->gpgExecutable = 'C:\gnupg\gpg';
            } elseif (@file_exists('/usr/local/bin/gpg')) {
                $this->gpgExecutable = '/usr/local/bin/gpg';
            } else {
                $this->gpgExecutable = '/usr/local/bin/gpg2';
            }
        }

        // if is empty the home directory then assume based in the OS
        if (empty($ringPath)) {
            if (strstr(PHP_OS, 'WIN')) {
                $this->ringPath = 'C:\gnupg';
            } else {
                $this->ringPath = '~/.gnupg';
            }
        }
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
     * @param $command
     * @param bool $input
     * @param $output
     * @return bool
     */
    private function forkProcess($command, $input = false, &$output)
    {
        // define the redirection pipes
        $descriptorspec = array(
            0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
            1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
            2 => array("pipe", "w")   // stderr is a pipe that the child will write to
        );
        $pipes = null;

        // calls the process
        $process = proc_open($command, $descriptorspec, $pipes);
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
     * @param  string $KeyKind the kind of the keys, can be secret or public
     * @param  string $SearchCriteria the filter or criteria to search
     * @return false|array  false on error, the array with the keys in the keyring in success
     */
    public function listKeys($KeyKind = 'public', $SearchCriteria = '')
    {
        // validate the KeyKind
        $KeyKind = strtolower(substr($KeyKind, 0, 3));
        if (($KeyKind != 'pub') && ($KeyKind != 'sec')) {
            $this->error = 'The Key kind must be public or secret';
            return false;
        }

        // initialize the output
        $contents = '';

        // execute the GPG command
        if ($this->forkProcess($this->buildGnuPGCommand([
            '--with-colons' => null,
            '--with-fingerprint' => null,
            (($KeyKind == 'pub') ? '--list-public-keys' : '--list-secret-keys') => (empty($SearchCriteria) ? null : $SearchCriteria)
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
     * @param $KeyID
     * @return false|string  false on error, the key block with the exported keys
     */
    public function export($KeyID = null)
    {
        $KeyID = empty($KeyID) ? '' : $KeyID;

        // initialize the output
        $contents = '';

        // execute the GPG command
        if ($this->forkProcess($this->buildGnuPGCommand([
            '--armor' => null,
            '--export' => $KeyID
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
     * @param  string $KeyBlock The PGP block with the key(s).
     * @return false|array  false on error, the array with [KeyID, UserID] elements of imported keys on success.
     */
    public function import($KeyBlock)
    {
        // Verify for the Key block contents
        if (empty($KeyBlock)) {
            $this->error = 'No valid key block was specified.';
            return false;
        }

        // initialize the output
        $contents = '';

        // execute the GPG command
        if ($this->forkProcess($this->buildGnuPGCommand([
            '--status-fd' => '1',
            '--import' => null
        ]),
            $KeyBlock, $contents)) {
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
     * @param  string $RealName The real name of the user or key.
     * @param  string $Comment Any explanatory commentary.
     * @param  string $Email The e-mail for the user.
     * @param  string $Passphrase Passphrase for the secret key, default is not to use any passphrase.
     * @param  int|string $ExpireDate Set the expiration date for the key (and the subkey).  It may either be entered in ISO date format (2000-08-15) or as number of days, weeks, month or years (<number>[d|w|m|y]). Without a letter days are assumed.
     * @param  string $KeyType Set the type of the key, the allowed values are DSA and RSA, default is DSA.
     * @param  int $KeyLength Length of the key in bits, default is 1024.
     * @param  string $SubkeyType This generates a secondary key, currently only one subkey can be handled ELG-E.
     * @param  int $SubkeyLength Length of the subkey in bits, default is 1024.
     * @return boolean|array  false on error, the fingerprint of the created key pair in success
     */
    public function genKey($RealName, $Comment, $Email, $Passphrase = '', $ExpireDate = 0, $KeyType = 'DSA', $KeyLength = 1024, $SubkeyType = 'ELG-E', $SubkeyLength = 1024)
    {
        // validates the keytype
        if (($KeyType != 'DSA') && ($KeyType != 'RSA')) {
            $this->error = 'Invalid Key-Type, the allowed are DSA and RSA';
            return false;
        }

        // validates the subkey
        if ((!empty($SubkeyType)) && ($SubkeyType != 'ELG-E')) {
            $this->error = 'Invalid Subkey-Type, the allowed is ELG-E';
            return false;
        }

        // validate the expiration date
        if (!preg_match('/^(([0-9]+[dwmy]?)|([0-9]{4}-[0-9]{2}-[0-9]{2}))$/', $ExpireDate)) {
            $this->error = 'Invalid Expire Date, the allowed values are <iso-date>|(<number>[d|w|m|y])';
            return false;
        }

        // generates the batch configuration script
        $batch_script = "Key-Type: $KeyType\n" .
            "Key-Length: $KeyLength\n";
        if (($KeyType == 'DSA') && ($SubkeyType == 'ELG-E'))
            $batch_script .= "Subkey-Type: $SubkeyType\n" .
                "Subkey-Length: $SubkeyLength\n";
        $batch_script .= "Name-Real: $RealName\n" .
            "Name-Comment: $Comment\n" .
            "Name-Email: $Email\n" .
            "Expire-Date: $ExpireDate\n" .
            "Passphrase: $Passphrase\n" .
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
     * @param  string $KeyID the key id used to encrypt
     * @param  string $Passphrase the passphrase to open the key used to encrypt
     * @param  string $RecipientKeyID the recipient key id
     * @param  string $Text data to encrypt
     * @return false|string  false on error, the encrypted data on success
     */
    public function encrypt($KeyID, $Passphrase, $RecipientKeyID, $Text)
    {
        // initialize the output
        $contents = '';

        $result = $this->forkProcess($this->buildGnuPGCommand([
            '--batch' => null,
            '--yes' => null,
            '--armor' => null,
            '--sign' => null,
            '--force-v3-sigs' => null,
            '--passphrase-fd' => '0',
            '--local-user' => $KeyID,
            '--default-key' => $KeyID,
            '--recipient' => $RecipientKeyID,
            '--encrypt' => null
        ]),
            $Passphrase . "\n" . $Text, $contents);

        // execute the GPG command
        if ($result)
            return trim($contents);
        else
            return false;
    }

    /**
     * Encrypt and sign a file.
     *
     * @param  string $KeyID the key id used to encrypt
     * @param  string $Passphrase the passphrase to open the key used to encrypt
     * @param  string $RecipientKeyID the recipient key id
     * @param  string $InputFile file to encrypt
     * @param  string $OutputFile file encrypted
     * @return false|string  false on error, the encrypted data on success
     */
    public function encryptFile($KeyID, $Passphrase, $RecipientKeyID, $InputFile, $OutputFile)
    {
        // initialize the output
        $contents = '';

        // execute the GPG command
        if ($this->forkProcess($this->buildGnuPGCommand([
            '--batch' => null,
            '--yes' => null,
            '--armor' => null,
            '--sign' => null,
            '--force-v3-sigs' => null,
            '--passphrase-fd' => '0',
            '--local-user' => $KeyID,
            '--default-key' => $KeyID,
            '--recipient' => $RecipientKeyID,
            '--output' => $OutputFile,
            '--encrypt' => $InputFile
        ]),
            $Passphrase . "\n", $contents))
            return $contents;
        else
            return false;
    }

    /**
     * Decrypt the data.
     *
     * If the decrypted file is signed, the signature is also verified.
     *
     * @param  string $KeyID the key id to decrypt
     * @param  string $Passphrase the passphrase to open the key used to decrypt
     * @param  string $Text data to decrypt
     * @return mixed  false on error, the clear (decrypted) data on success
     */
    public function decrypt($KeyID, $Passphrase, $Text)
    {
        // the text to decrypt from another platforms can has a bad sequence
        // this line removes the bad data and converts to line returns
        $Text = preg_replace("/\x0D\x0D\x0A/s", "\n", $Text);

        // we generate an array and add a new line after the PGP header
        $Text = explode("\n", $Text);
        if (count($Text) > 1) $Text[1] .= "\n";
        $Text = implode("\n", $Text);

        // initialize the output
        $contents = '';

        // execute the GPG command
        if ($this->forkProcess($this->buildGnuPGCommand([
            '--batch' => null,
            '--yes' => null,
            '--passphrase-fd' => '0',
            '--local-user' => $KeyID,
            '--default-key' => $KeyID,
            '--decrypt' => null
        ]),
            $Passphrase . "\n" . $Text, $contents))
            return $contents;
        else
            return false;
    }

    /**
     * Decrypt a file.
     *
     * If the decrypted file is signed, the signature is also verified.
     *
     * @param  string $KeyID the key id to decrypt
     * @param  string $Passphrase the passphrase to open the key used to decrypt
     * @param  string $InputFile file to decrypt
     * @param  string $OutputFile file decrypted
     * @return mixed  false on error, the clear (decrypted) data on success
     */
    public function decryptFile($KeyID, $Passphrase, $InputFile, $OutputFile)
    {
        // initialize the output
        $contents = '';

        // execute the GPG command
        if ($this->forkProcess($this->buildGnuPGCommand([
            '--batch' => null,
            '--yes' => null,
            '--passphrase-fd' => '0',
            '--local-user' => $KeyID,
            '--default-key' => $KeyID,
            '--output' => $OutputFile,
            '--decrypt' => $InputFile
        ]),
            $Passphrase . "\n", $contents))
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
     * @param  string $KeyID the key id to be removed, if this is the secret key you must specify the fingerprint
     * @param  string $KeyKind the kind of the keys, can be secret or public
     * @return boolean|string  true on success, otherwise false or the delete error code
     */
    public function deleteKey($KeyID, $KeyKind = 'public')
    {
        if (empty($KeyID)) {
            $this->error = 'You must specify the KeyID to delete';
            return false;
        }

        // validate the KeyKind
        $KeyKind = strtolower(substr($KeyKind, 0, 3));
        if (($KeyKind != 'pub') && ($KeyKind != 'sec')) {
            $this->error = 'The Key kind must be public or secret';
            return false;
        }

        // initialize the output
        $contents = '';

        // execute the GPG command
        if ($this->forkProcess($this->buildGnuPGCommand([
            '--batch' => null,
            '--yes' => null,
            '--status-fd' => '1',
            (($KeyKind == 'pub') ? '--delete-key' : '--delete-secret-keys') => $KeyID
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
     * @param  string $KeyID the key id used to sign
     * @param  string $Passphrase the passphrase to open the key used to sign
     * @param  string $RecipientKeyID the recipient key id to be signed
     * @param  int $CertificationLevel the level of thrust for the recipient key
     *    0 : means you make no particular claim as to how carefully you verified the key
     *    1 : means you believe the key is owned by the person who claims to own it but you could not, or did not verify the key at all
     *    2 : means you did casual verification of the key
     *    3 : means you did extensive verification of the key
     * @return boolean|string true on success, otherwise false or the sign error code
     */
    public function signKey($KeyID, $Passphrase, $RecipientKeyID, $CertificationLevel = self::CERT_LEVEL_NONE)
    {
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
            '--local-user' => $KeyID,
            '--default-key' => $KeyID,
            '--default-cert-level' => strval($CertificationLevel),
            '--sign-key' => $RecipientKeyID
        ]),
            $Passphrase . "\n", $contents))
            return $contents;
        else
            return false;
    }
}
