<?php

namespace PlacetoPay\GnuPG\Messages;

use PlacetoPay\GnuPG\Entities\PGPKey;
use PlacetoPay\GnuPG\Runners\CommandResult;

class ListKeysResponse
{
    protected $success = false;
    /**
     * @var PGPKey[]
     */
    protected $keys;
    protected $result;

    public function __construct(bool $success, array $keys, CommandResult $result)
    {
        $this->success = $success;
        $this->keys = $keys;
        $this->result = $result;
    }

    public static function fromResult(CommandResult $result)
    {
        // initialize the array data
        $returned_keys = [];
        $keyPos = -1;

        // the keys are \n separated
        $contents = explode("\n", $result->output());

        // find each key
        foreach ($contents as $data) {
            $fields = explode(':', $data);

            if (count($fields) <= 3) {
                continue;
            }

            // verify the that the record is valid
            if (($fields[0] == 'pub') || ($fields[0] == 'sec')) {
                $keyPos++;
                $returned_keys[$keyPos] = [
                    'kind' => $fields[0],
                    'trust' => $fields[1],
                    'length' => $fields[2],
                    'type' => $fields[3] == 17 ? PGPKey::KEY_TYPE_DSA : PGPKey::KEY_TYPE_RSA,
                    'identifier' => $fields[4],
                    'creationDate' => $fields[5],
                    'expirationDate' => $fields[6],
                    'owner' => $fields[9],
                    'fingerprint' => '',
                ];
            } elseif ($keyPos != -1) {
                switch ($fields[0]) {
                    case 'fpr':
                        $returned_keys[$keyPos]['fingerprint'] = $fields[9];
                        break;
                }
            }
        }

        return new static($result->isSuccessful(), array_map(function ($keyData) {
            return PGPKey::fromColonRow($keyData);
        }, $returned_keys), $result);
    }

    /**
     * @return PGPKey[]
     */
    public function keys(): array
    {
        return $this->keys;
    }

    public function count()
    {
        return count($this->keys);
    }

    public function commandResult(): ?CommandResult
    {
        return $this->result;
    }
}
