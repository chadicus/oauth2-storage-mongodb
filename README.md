MongoDB Storage for OAuth2 Server
=================================

[![Build Status](https://travis-ci.org/chadicus/oauth2-storage-mongodb.svg?branch=master)](https://travis-ci.org/chadicus/oauth2-storage-mongodb)
[![Code Quality](https://scrutinizer-ci.com/g/chadicus/oauth2-storage-mongodb/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/chadicus/oauth2-storage-mongodb/?branch=master)
[![Coverage Status](https://coveralls.io/repos/github/chadicus/oauth2-storage-mongodb/badge.svg?branch=master)](https://coveralls.io/github/chadicus/oauth2-storage-mongodb?branch=master)

[![Latest Stable Version](https://poser.pugx.org/chadicus/oauth2-storage-mongodb/v/stable)](https://packagist.org/packages/chadicus/oauth2-storage-mongodb)
[![Latest Unstable Version](https://poser.pugx.org/chadicus/oauth2-storage-mongodb/v/unstable)](https://packagist.org/packages/chadicus/oauth2-storage-mongodb)
[![License](https://poser.pugx.org/chadicus/oauth2-storage-mongodb/license)](https://packagist.org/packages/chadicus/oauth2-storage-mongodb)

[![Total Downloads](https://poser.pugx.org/chadicus/oauth2-storage-mongodb/downloads)](https://packagist.org/packages/chadicus/oauth2-storage-mongodb)
[![Monthly Downloads](https://poser.pugx.org/chadicus/oauth2-storage-mongodb/d/monthly)](https://packagist.org/packages/chadicus/oauth2-storage-mongodb)
[![Daily Downloads](https://poser.pugx.org/chadicus/oauth2-storage-mongodb/d/daily)](https://packagist.org/packages/chadicus/oauth2-storage-mongodb)

This library uses the [Mongo](https://www.mongodb.com/) document database for storing and retrieving objects in an [OAuth2 Server](http://bshaffer.github.io/oauth2-server-php-docs/) application.

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
The MongoDB storage engine implements all the standard Storage Interfaces supported in this library. See [interfaces](http://bshaffer.github.io/oauth2-server-php-docs/storage/custom) for more information.
