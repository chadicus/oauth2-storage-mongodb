<?php

namespace OAuth2Test\Storage;

use OAuth2\Storage\MongoDB;
use MongoDB\BSON\UTCDateTime;
use MongoDB\Model\BSONDocument;

/**
 * @coversDefaultClass \OAuth2\Storage\MongoDB
 * @covers ::__construct
 * @covers ::<private>
 */
final class MongoDBTest extends \PHPUnit_Framework_TestCase
{
    /**
     * Verify basic behavior of getAuthorizationCode().
     *
     * @test
     * @covers ::getAuthorizationCode
     *
     * @return void
     */
    public function getAuthorizationCode()
    {
        $code = md5(microtime(true));
        $expires = new UTCDateTime((int)(microtime(true) * 1000));
        $document = new BSONDocument(
            [
                '_id' => $code,
                'client_id' => 'a client id',
                'user_id' => 'a user id',
                'expires' => $expires,
                'redirect_uri' => 'a redirect uri',
                'scope' => 'a scope',
            ]
        );

        $collectionMock = $this->getMockBuilder('\\MongoDB\\Collection')->disableOriginalConstructor()->getMock();
        $collectionMock->expects($this->once())->method('findOne')->will($this->returnValue($document));

        $databaseMock = $this->getMockBuilder('\\MongoDB\\Database')->disableOriginalConstructor()->getMock();
        $databaseMock->expects($this->once())->method('selectCollection')->with(
            $this->equalTo('oauth_authorization_codes')
        )->will($this->returnValue($collectionMock));

        $storage = new MongoDB($databaseMock, ['code_table' => 'oauth_authorization_codes']);

        $this->assertSame(
            [
                'client_id' => 'a client id',
                'user_id' => 'a user id',
                'expires' => $expires->toDateTime()->getTimestamp(),
                'redirect_uri' => 'a redirect uri',
                'scope' => 'a scope',
            ],
            $storage->getAuthorizationCode($code)
        );
    }

    /**
     * Verify behavior of getAuthorizationCode() with custom mongo client typeMap.
     *
     * @test
     * @covers ::getAuthorizationCode
     *
     * @return void
     */
    public function getAuthorizationCodeArrayResult()
    {
        $code = md5(microtime(true));
        $expires = new UTCDateTime((int)(microtime(true) * 1000));
        $result = [
            '_id' => $code,
            'client_id' => 'a client id',
            'user_id' => 'a user id',
            'expires' => $expires,
            'redirect_uri' => 'a redirect uri',
            'scope' => 'a scope',
        ];

        $collectionMock = $this->getMockBuilder('\\MongoDB\\Collection')->disableOriginalConstructor()->getMock();
        $collectionMock->expects($this->once())->method('findOne')->will($this->returnValue($result));

        $databaseMock = $this->getMockBuilder('\\MongoDB\\Database')->disableOriginalConstructor()->getMock();
        $databaseMock->expects($this->once())->method('selectCollection')->with(
            $this->equalTo('oauth_authorization_codes')
        )->will($this->returnValue($collectionMock));

        $storage = new MongoDB($databaseMock, ['code_table' => 'oauth_authorization_codes']);

        $this->assertSame(
            [
                'client_id' => 'a client id',
                'user_id' => 'a user id',
                'expires' => $expires->toDateTime()->getTimestamp(),
                'redirect_uri' => 'a redirect uri',
                'scope' => 'a scope',
            ],
            $storage->getAuthorizationCode($code)
        );
    }

    /**
     * Verify behavior of getAuthorizationCode() when findOne returns null.
     *
     * @test
     * @covers ::getAuthorizationCode
     *
     * @return void
     */
    public function getAuthorizationCodeNullResult()
    {
        $collectionMock = $this->getMockBuilder('\\MongoDB\\Collection')->disableOriginalConstructor()->getMock();
        $collectionMock->expects($this->once())->method('findOne')->will($this->returnValue(null));

        $databaseMock = $this->getMockBuilder('\\MongoDB\\Database')->disableOriginalConstructor()->getMock();
        $databaseMock->expects($this->once())->method('selectCollection')->with(
            $this->equalTo('oauth_authorization_codes')
        )->will($this->returnValue($collectionMock));

        $code = md5(microtime(true));
        $storage = new MongoDB($databaseMock, ['code_table' => 'oauth_authorization_codes']);
        $this->assertNull($storage->getAuthorizationCode($code));
    }

    /**
     * Verify basic behavior of setAuthorizationCode().
     *
     * @test
     * @covers ::setAuthorizationCode
     *
     * @return void
     */
    public function setAuthorizationCode()
    {
        $code = md5(microtime(true));
        $expires = strtotime('+1 hour');

        $collectionMock = $this->getMockBuilder('\\MongoDB\\Collection')->disableOriginalConstructor()->getMock();
        $collectionMock->expects($this->once())->method('insertOne')->with(
            $this->equalTo(
                [
                    '_id' => $code,
                    'client_id' => 'a client id',
                    'user_id' => 'a user id',
                    'redirect_uri' => 'a redirect uri',
                    'expires' => new UTCDateTime($expires * 1000),
                    'scope' => 'a scope',
                ]
            )
        );

        $databaseMock = $this->getMockBuilder('\\MongoDB\\Database')->disableOriginalConstructor()->getMock();
        $databaseMock->expects($this->once())->method('selectCollection')->with(
            $this->equalTo('oauth_authorization_codes')
        )->will($this->returnValue($collectionMock));

        $storage = new MongoDB($databaseMock, ['code_table' => 'oauth_authorization_codes']);
        $storage->setAuthorizationCode($code, 'a client id', 'a user id', 'a redirect uri', $expires, 'a scope');
    }

    /**
     * Verify basic behavior of expireAuthorizationCode().
     *
     * @test
     * @covers ::expireAuthorizationCode
     *
     * @return void
     */
    public function expireAuthorizationCode()
    {
        $code = md5(microtime(true));
        $collectionMock = $this->getMockBuilder('\\MongoDB\\Collection')->disableOriginalConstructor()->getMock();
        $collectionMock->expects($this->once())->method('deleteOne')->with(
            $this->equalTo(['_id' => $code])
        );

        $databaseMock = $this->getMockBuilder('\\MongoDB\\Database')->disableOriginalConstructor()->getMock();
        $databaseMock->expects($this->once())->method('selectCollection')->with(
            $this->equalTo('oauth_authorization_codes')
        )->will($this->returnValue($collectionMock));

        $storage = new MongoDB($databaseMock, ['code_table' => 'oauth_authorization_codes']);
        $storage->expireAuthorizationCode($code);
    }

    /**
     * Verify basic behavior of getAccessToken().
     *
     * @test
     * @covers ::getAccessToken
     *
     * @return void
     */
    public function getAccessToken()
    {
        $token = md5(microtime(true));
        $expires = new UTCDateTime((int)(microtime(true) * 1000));
        $document = new BSONDocument(
            [
                '_id' => $token,
                'client_id' => 'a client id',
                'user_id' => 'a user id',
                'expires' => $expires,
                'scope' => 'a scope',
            ]
        );

        $collectionMock = $this->getMockBuilder('\\MongoDB\\Collection')->disableOriginalConstructor()->getMock();
        $collectionMock->expects($this->once())->method('findOne')->will($this->returnValue($document));

        $databaseMock = $this->getMockBuilder('\\MongoDB\\Database')->disableOriginalConstructor()->getMock();
        $databaseMock->expects($this->once())->method('selectCollection')->with(
            $this->equalTo('oauth_access_tokens')
        )->will($this->returnValue($collectionMock));

        $storage = new MongoDB($databaseMock);

        $this->assertSame(
            [
                'expires' => $expires->toDateTime()->getTimestamp(),
                'client_id' => 'a client id',
                'user_id' => 'a user id',
                'scope' => 'a scope',
            ],
            $storage->getAccessToken($token)
        );
    }

    /**
     * Verify behavior of getAccessToken() with null result.
     *
     * @test
     * @covers ::getAccessToken
     *
     * @return void
     */
    public function getAccessTokenNullResult()
    {
        $collectionMock = $this->getMockBuilder('\\MongoDB\\Collection')->disableOriginalConstructor()->getMock();
        $collectionMock->expects($this->once())->method('findOne')->will($this->returnValue(null));

        $databaseMock = $this->getMockBuilder('\\MongoDB\\Database')->disableOriginalConstructor()->getMock();
        $databaseMock->expects($this->once())->method('selectCollection')->with(
            $this->equalTo('oauth_access_tokens')
        )->will($this->returnValue($collectionMock));

        $token = md5(microtime(true));
        $storage = new MongoDB($databaseMock);
        $this->assertNull($storage->getAccessToken($token));
    }

    /**
     * Verify basic behavior of setAccessToken().
     *
     * @test
     * @covers ::setAccessToken
     *
     * @return void
     */
    public function setAccessToken()
    {
        $token = md5(microtime(true));
        $expires = strtotime('+1 hour');

        $collectionMock = $this->getMockBuilder('\\MongoDB\\Collection')->disableOriginalConstructor()->getMock();
        $collectionMock->expects($this->once())->method('insertOne')->with(
            $this->equalTo(
                [
                    '_id' => $token,
                    'client_id' => 'a client id',
                    'user_id' => 'a user id',
                    'expires' => new UTCDateTime($expires * 1000),
                    'scope' => 'a scope',
                ]
            )
        );

        $databaseMock = $this->getMockBuilder('\\MongoDB\\Database')->disableOriginalConstructor()->getMock();
        $databaseMock->expects($this->once())->method('selectCollection')->with(
            $this->equalTo('oauth_access_tokens')
        )->will($this->returnValue($collectionMock));

        $storage = new MongoDB($databaseMock);
        $storage->setAccessToken($token, 'a client id', 'a user id', $expires, 'a scope');
    }

    /**
     * Verify basic behavior of getClientDetails().
     *
     * @test
     * @covers ::getClientDetails
     *
     * @return void
     */
    public function getClientDetails()
    {
        $document = new BSONDocument(
            [
                '_id' => 'a client id',
                'redirect_uri' => ['redirectUriOne', 'redirectUriTwo'],
                'user_id' => 'a user id',
                'scope' => ['aScope', 'anotherScope'],
                'grant_types' => ['grant type 1', 'grant type 2'],
            ]
        );

        $collectionMock = $this->getMockBuilder('\\MongoDB\\Collection')->disableOriginalConstructor()->getMock();
        $collectionMock->expects($this->once())->method('findOne')->will($this->returnValue($document));

        $databaseMock = $this->getMockBuilder('\\MongoDB\\Database')->disableOriginalConstructor()->getMock();
        $databaseMock->expects($this->once())->method('selectCollection')->with(
            $this->equalTo('oauth_clients')
        )->will($this->returnValue($collectionMock));

        $storage = new MongoDB($databaseMock);

        $this->assertSame(
            [
                'redirect_uri' => 'redirectUriOne redirectUriTwo',
                'client_id' => 'a client id',
                'grant_types' => ['grant type 1', 'grant type 2'],
                'user_id' => 'a user id',
                'scope' => 'aScope anotherScope',
            ],
            $storage->getClientDetails('a client id')
        );
    }

    /**
     * Verify behavior of getClientDetails() with null result.
     *
     * @test
     * @covers ::getClientDetails
     *
     * @return void
     */
    public function getClientDetailsNullResult()
    {
        $collectionMock = $this->getMockBuilder('\\MongoDB\\Collection')->disableOriginalConstructor()->getMock();
        $collectionMock->expects($this->once())->method('findOne')->will($this->returnValue(null));

        $databaseMock = $this->getMockBuilder('\\MongoDB\\Database')->disableOriginalConstructor()->getMock();
        $databaseMock->expects($this->once())->method('selectCollection')->with(
            $this->equalTo('oauth_clients')
        )->will($this->returnValue($collectionMock));

        $storage = new MongoDB($databaseMock);
        $this->assertFalse($storage->getClientDetails('a client id'));
    }

    /**
     * Verify basic behavior of getClientScope().
     *
     * @test
     * @covers ::getClientScope
     *
     * @return void
     */
    public function getClientScope()
    {
        $document = new BSONDocument(
            [
                '_id' => 'a client id',
                'redirect_uri' => ['redirectUriOne', 'redirectUriTwo'],
                'user_id' => 'a user id',
                'scope' => ['aScope', 'anotherScope'],
                'grant_types' => ['grant type 1', 'grant type 2'],
            ]
        );

        $collectionMock = $this->getMockBuilder('\\MongoDB\\Collection')->disableOriginalConstructor()->getMock();
        $collectionMock->expects($this->once())->method('findOne')->with(
            $this->equalTo(['_id' => 'a client id'])
        )->will($this->returnValue($document));

        $databaseMock = $this->getMockBuilder('\\MongoDB\\Database')->disableOriginalConstructor()->getMock();
        $databaseMock->expects($this->once())->method('selectCollection')->with(
            $this->equalTo('oauth_clients')
        )->will($this->returnValue($collectionMock));

        $storage = new MongoDB($databaseMock);

        $this->assertSame('aScope anotherScope', $storage->getClientScope('a client id'));
    }

    /**
     * Verify behavior of getClientScope() when scope is empty.
     *
     * @test
     * @covers ::getClientScope
     *
     * @return void
     */
    public function getClientScopeEmptyScope()
    {
        $document = new BSONDocument(
            [
                '_id' => 'a client id',
                'redirect_uri' => ['redirectUriOne', 'redirectUriTwo'],
                'user_id' => 'a user id',
                'scope' => null,
                'grant_types' => ['grant type 1', 'grant type 2'],
            ]
        );

        $collectionMock = $this->getMockBuilder('\\MongoDB\\Collection')->disableOriginalConstructor()->getMock();
        $collectionMock->expects($this->once())->method('findOne')->with(
            $this->equalTo(['_id' => 'a client id'])
        )->will($this->returnValue($document));

        $databaseMock = $this->getMockBuilder('\\MongoDB\\Database')->disableOriginalConstructor()->getMock();
        $databaseMock->expects($this->once())->method('selectCollection')->with(
            $this->equalTo('oauth_clients')
        )->will($this->returnValue($collectionMock));

        $storage = new MongoDB($databaseMock);

        $this->assertSame('', $storage->getClientScope('a client id'));
    }

    /**
     * Verify behavior of getClientScope() when client is not found.
     *
     * @test
     * @covers ::getClientScope
     *
     * @return void
     */
    public function getClientScopeClientNotFound()
    {
        $collectionMock = $this->getMockBuilder('\\MongoDB\\Collection')->disableOriginalConstructor()->getMock();
        $collectionMock->expects($this->once())->method('findOne')->with(
            $this->equalTo(['_id' => 'a client id'])
        )->will($this->returnValue(null));

        $databaseMock = $this->getMockBuilder('\\MongoDB\\Database')->disableOriginalConstructor()->getMock();
        $databaseMock->expects($this->once())->method('selectCollection')->with(
            $this->equalTo('oauth_clients')
        )->will($this->returnValue($collectionMock));

        $storage = new MongoDB($databaseMock);

        $this->assertSame('', $storage->getClientScope('a client id'));
    }

    /**
     * Verify basic behavior of checkRestrictedGrantType().
     *
     * @test
     * @covers ::checkRestrictedGrantType
     *
     * @return void
     */
    public function checkRestrictedGrantType()
    {
        $document = new BSONDocument(
            [
                '_id' => 'a client id',
                'redirect_uri' => ['redirectUriOne', 'redirectUriTwo'],
                'user_id' => 'a user id',
                'scope' => ['aScope', 'anotherScope'],
                'grant_types' => ['grant type 1', 'grant type 2'],
            ]
        );

        $collectionMock = $this->getMockBuilder('\\MongoDB\\Collection')->disableOriginalConstructor()->getMock();
        $collectionMock->expects($this->once())->method('findOne')->with(
            $this->equalTo(['_id' => 'a client id'])
        )->will($this->returnValue($document));

        $databaseMock = $this->getMockBuilder('\\MongoDB\\Database')->disableOriginalConstructor()->getMock();
        $databaseMock->expects($this->once())->method('selectCollection')->with(
            $this->equalTo('oauth_clients')
        )->will($this->returnValue($collectionMock));

        $storage = new MongoDB($databaseMock);

        $this->assertTrue($storage->checkRestrictedGrantType('a client id', 'grant type 2'));
    }

    /**
     * Verify basic behavior of checkClientCredentials().
     *
     * @test
     * @covers ::checkClientCredentials
     *
     * @return void
     */
    public function checkClientCredentials()
    {
        $document = new BSONDocument(
            [
                '_id' => 'a client id',
                'redirect_uri' => ['redirectUriOne', 'redirectUriTwo'],
                'user_id' => 'a user id',
                'scope' => ['aScope', 'anotherScope'],
                'grant_types' => ['grant type 1', 'grant type 2'],
                'client_secret' => MongoDB::encryptCredentials('a client id', ' a secret'),
            ]
        );

        $collectionMock = $this->getMockBuilder('\\MongoDB\\Collection')->disableOriginalConstructor()->getMock();
        $collectionMock->expects($this->once())->method('findOne')->with(
            $this->equalTo(['_id' => 'a client id'])
        )->will($this->returnValue($document));

        $databaseMock = $this->getMockBuilder('\\MongoDB\\Database')->disableOriginalConstructor()->getMock();
        $databaseMock->expects($this->once())->method('selectCollection')->with(
            $this->equalTo('oauth_clients')
        )->will($this->returnValue($collectionMock));

        $storage = new MongoDB($databaseMock);

        $this->assertTrue($storage->checkClientCredentials('a client id', ' a secret'));
    }

    /**
     * Verify behavior of checkClientCredentials() when client is not found.
     *
     * @test
     * @covers ::checkClientCredentials
     *
     * @return void
     */
    public function checkClientCredentialsClientNotFound()
    {
        $collectionMock = $this->getMockBuilder('\\MongoDB\\Collection')->disableOriginalConstructor()->getMock();
        $collectionMock->expects($this->once())->method('findOne')->with(
            $this->equalTo(['_id' => 'a client id'])
        )->will($this->returnValue(null));

        $databaseMock = $this->getMockBuilder('\\MongoDB\\Database')->disableOriginalConstructor()->getMock();
        $databaseMock->expects($this->once())->method('selectCollection')->with(
            $this->equalTo('oauth_clients')
        )->will($this->returnValue($collectionMock));

        $storage = new MongoDB($databaseMock);

        $this->assertFalse($storage->checkClientCredentials('a client id', ' a secret'));
    }

    /**
     * Verify basic behavior of isPublicClient().
     *
     * @test
     * @covers ::isPublicClient
     *
     * @return void
     */
    public function isPublicClient()
    {
        $document = new BSONDocument(
            [
                '_id' => 'a client id',
                'redirect_uri' => ['redirectUriOne', 'redirectUriTwo'],
                'user_id' => 'a user id',
                'scope' => ['aScope', 'anotherScope'],
                'grant_types' => ['grant type 1', 'grant type 2'],
                'client_secret' => null,
            ]
        );

        $collectionMock = $this->getMockBuilder('\\MongoDB\\Collection')->disableOriginalConstructor()->getMock();
        $collectionMock->expects($this->once())->method('findOne')->with(
            $this->equalTo(['_id' => 'a client id'])
        )->will($this->returnValue($document));

        $databaseMock = $this->getMockBuilder('\\MongoDB\\Database')->disableOriginalConstructor()->getMock();
        $databaseMock->expects($this->once())->method('selectCollection')->with(
            $this->equalTo('oauth_clients')
        )->will($this->returnValue($collectionMock));

        $storage = new MongoDB($databaseMock);

        $this->assertTrue($storage->isPublicClient('a client id'));
    }

    /**
     * Verify behavior of isPublicClient() when client is not found.
     *
     * @test
     * @covers ::isPublicClient
     *
     * @return void
     */
    public function isPublicClientClientNotFound()
    {
        $collectionMock = $this->getMockBuilder('\\MongoDB\\Collection')->disableOriginalConstructor()->getMock();
        $collectionMock->expects($this->once())->method('findOne')->with(
            $this->equalTo(['_id' => 'a client id'])
        )->will($this->returnValue(null));

        $databaseMock = $this->getMockBuilder('\\MongoDB\\Database')->disableOriginalConstructor()->getMock();
        $databaseMock->expects($this->once())->method('selectCollection')->with(
            $this->equalTo('oauth_clients')
        )->will($this->returnValue($collectionMock));

        $storage = new MongoDB($databaseMock);

        $this->assertFalse($storage->isPublicClient('a client id'));
    }

    /**
     * Verify basic behavior of getUserDetails().
     *
     * @test
     * @covers ::getUserDetails
     *
     * @return void
     */
    public function getUserDetails()
    {
        $document = new BSONDocument(
            [
                '_id' => 'a user id',
                'scope' => ['aScope', 'anotherScope'],
                'extra' => 'extra data from mongo',
            ]
        );

        $collectionMock = $this->getMockBuilder('\\MongoDB\\Collection')->disableOriginalConstructor()->getMock();
        $collectionMock->expects($this->once())->method('findOne')->with(
            $this->equalTo(['_id' => 'a user id'])
        )->will($this->returnValue($document));

        $databaseMock = $this->getMockBuilder('\\MongoDB\\Database')->disableOriginalConstructor()->getMock();
        $databaseMock->expects($this->once())->method('selectCollection')->with(
            $this->equalTo('oauth_users')
        )->will($this->returnValue($collectionMock));

        $storage = new MongoDB($databaseMock);

        $this->assertSame(
            [
                'user_id' => 'a user id',
                'scope' => 'aScope anotherScope',
            ],
            $storage->getUserDetails('a user id')
        );
    }

    /**
     * Verify behavior of getUserDetails() when no user is found.
     *
     * @test
     * @covers ::getUserDetails
     *
     * @return void
     */
    public function getUserDetailsUsernotFound()
    {
        $collectionMock = $this->getMockBuilder('\\MongoDB\\Collection')->disableOriginalConstructor()->getMock();
        $collectionMock->expects($this->once())->method('findOne')->with(
            $this->equalTo(['_id' => 'a user id'])
        )->will($this->returnValue(null));

        $databaseMock = $this->getMockBuilder('\\MongoDB\\Database')->disableOriginalConstructor()->getMock();
        $databaseMock->expects($this->once())->method('selectCollection')->with(
            $this->equalTo('oauth_users')
        )->will($this->returnValue($collectionMock));

        $storage = new MongoDB($databaseMock);

        $this->assertFalse($storage->getUserDetails('a user id'));
    }

    /**
     * Verify basic behavior of checkUserCredentials().
     *
     * @test
     * @covers ::checkUserCredentials
     *
     * @return void
     */
    public function checkUserCredentials()
    {
        $document = new BSONDocument(
            [
                '_id' => 'a username',
                'password' => MongoDB::encryptCredentials('a username', ' a password'),
            ]
        );

        $collectionMock = $this->getMockBuilder('\\MongoDB\\Collection')->disableOriginalConstructor()->getMock();
        $collectionMock->expects($this->once())->method('findOne')->with(
            $this->equalTo(['_id' => 'a username'])
        )->will($this->returnValue($document));

        $databaseMock = $this->getMockBuilder('\\MongoDB\\Database')->disableOriginalConstructor()->getMock();
        $databaseMock->expects($this->once())->method('selectCollection')->with(
            $this->equalTo('oauth_users')
        )->will($this->returnValue($collectionMock));

        $storage = new MongoDB($databaseMock);

        $this->assertTrue($storage->checkUserCredentials('a username', ' a password'));
    }

    /**
     * Verify behavior of checkUserCredentials() when no user is found.
     *
     * @test
     * @covers ::checkUserCredentials
     *
     * @return void
     */
    public function checkUserCredentialsUserNotFound()
    {
        $collectionMock = $this->getMockBuilder('\\MongoDB\\Collection')->disableOriginalConstructor()->getMock();
        $collectionMock->expects($this->once())->method('findOne')->with(
            $this->equalTo(['_id' => 'a username'])
        )->will($this->returnValue(null));

        $databaseMock = $this->getMockBuilder('\\MongoDB\\Database')->disableOriginalConstructor()->getMock();
        $databaseMock->expects($this->once())->method('selectCollection')->with(
            $this->equalTo('oauth_users')
        )->will($this->returnValue($collectionMock));

        $storage = new MongoDB($databaseMock);

        $this->assertFalse($storage->checkUserCredentials('a username', ' a password'));
    }
}
