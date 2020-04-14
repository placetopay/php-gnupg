<?php

namespace PlacetoPay\GnuPG\Entities;

class PGPKey
{
    /**
     * Kinds of keys.
     */
    const KIND_PUBLIC = 'pub';
    const KIND_SECRET = 'sec';

    /**
     * Types of security.
     */
    const KEY_TYPE_RSA = 'RSA';
    const KEY_TYPE_DSA = 'DSA';

    protected $kind;
    protected $trust;
    protected $length;
    protected $type;
    protected $identifier;
    protected $creationDate;
    protected $expirationDate;
    protected $fingerprint;

    protected $name = '';
    protected $comment = '';
    protected $email = '';

    public function __construct(array $data = [])
    {
        $this->kind = $data['kind'] ?? 'pub';
        $this->trust = $data['trust'] ?? null;
        $this->length = $data['length'] ?? 1024;
        $this->type = $data['type'] ?? self::KEY_TYPE_DSA;

        $this->identifier = $data['identifier'] ?? null;
        $this->creationDate = $data['creationDate'] ?? null;
        $this->expirationDate = $data['expirationDate'] ?? 0;
        $this->fingerprint = $data['fingerprint'] ?? null;

        $this->name = $data['name'] ?? '';
        $this->comment = $data['comment'] ?? '';
        $this->email = $data['email'] ?? '';
    }

    public function type(): string
    {
        return $this->type;
    }

    public function length(): int
    {
        return $this->length;
    }
    
    public function fingerprint(): string
    {
        return $this->fingerprint;
    }

    public function name(): string
    {
        return $this->name;
    }

    public function comment(): string
    {
        return $this->comment;
    }

    public function email(): string
    {
        return $this->email;
    }

    public function expirationDate()
    {
        return $this->expirationDate;
    }

    public function asGenerationInput($passphrase): string
    {
        $script = [];
        
        // generates the batch configuration script
        $script[] = "Key-Type: {$this->type()}";
        $script[] = "Key-Length: {$this->length()}";

        if (($this->type() == 'DSA')) {
            $script[] = "Subkey-Type: ELG-E";
            $script[] = "Subkey-Length: {$this->length()}";
        }

        $script[] = "Name-Real: {$this->name()}";
        $script[] = "Name-Comment: {$this->comment()}";
        $script[] = "Name-Email: {$this->email()}";
        $script[] = "Expire-Date: {$this->expirationDate()}";
        $script[] = "Passphrase: $passphrase";
        $script[] = "%commit";
        $script[] = "%echo done with success";
        
        return implode("\n", $script);
    }

    public static function parseOwner(string $owner): array
    {
        if (preg_match('/([\w \.\-\_À-ÿ]+)\s*(?:\(([\w \.\-\_]+)?\))?\s*<([\w@\.\-\_]+)>/', $owner, $matches)) {
            return [
                'name' => trim($matches[1]),
                'comment' => trim($matches[2]),
                'email' => trim($matches[3]),
            ];
        }

        return [
            'name' => '',
            'comment' => '',
            'email' => '',
        ];
    }

    public static function fromColonRow(array $data)
    {
        if ($data['owner'] ?? null) {
            $data = array_replace(self::parseOwner($data['owner']), $data);
        }

        return new static($data);
    }
}
