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
}
