# Placetopay PHP - GnuPG

This library requires the GPG binary in order to work

## Installation

```
composer require placetopay/php-gnupg
```

### Usage

```
$gnupg = new \PlacetoPay\GnuPG\GnuPG([
    'gpgExecutable' => '/usr/local/bin/gpg', // The full path to the GPG executable
    'ringPath' => '~/.gnupg' // Path to the folder containing the keyring
]);
```

### Restrictions

gpg (GnuPG) version < 1.9