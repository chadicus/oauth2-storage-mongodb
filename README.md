## OAuth2\Storage\MongoDB

Uses the [Mongo](https://www.mongodb.com/) Document Database for storing and retrieving objects in OAuth.

This implementation requires the [MongoDB Extension](http://us3.php.net/manual/en/set.mongodb.php).

## Installation
Add the storage package to your composer file.
```sh
composer require chadicus/oauth2-storage-mongodb
```

## Getting Started

```php
use OAuth2\Storage\MongoDB;

$database = (new \MongoDB\Client('mongodb://localhost:27017'))->selectDatabase('oauth2');

$storage = new MongoDB($database);

$storage->setClientDetails('librarian', 'secret', '/receive-code');
$storage->setClientDetails('student', 's3cr3t');
```

## Usage
The Mongo storage engine implements all the standard Storage Interfaces supported in this library. See [interfaces](http://bshaffer.github.io/oauth2-server-php-docs/storage/custom) for more information.
