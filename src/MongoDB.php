<?php

namespace OAuth2\Storage;

use MongoDB\BSON\UTCDateTime;
use MongoDB\Database;

/**
 * Simple MongoDB storage for all storage types
 *
 * NOTE: This class is meant to get users started
 * quickly. If your application requires further
 * customization, extend this class or create your own.
 *
 * NOTE: Passwords are stored in plaintext, which is never
 * a good idea.  Be sure to override this for your application
 *
 * @author Julien Chaumond <chaumond@gmail.com>
 */
final class MongoDB implements
    AuthorizationCodeInterface,
    AccessTokenInterface,
    ClientCredentialsInterface,
    UserCredentialsInterface,
    RefreshTokenInterface,
    JwtBearerInterface
{
    /**
     * MongoDB\Database instance.
     *
     * @var Database
     */
    private $database;

    /**
     * Settings for this storage instance.
     *
     * @var array
     */
    private $config;

    /**
     * The salt for the encryption.  The $2y$ part specifies that this is blowfish encryption.
     *
     * @var string
     */
    const SALT = '$2y$07$5b9a5c43cdf9c3fa1dcfb4de4f379858';

    /**
     * Construct a new instance of the MongoDB storage.
     *
     * @param Database $database A mongo database instance.
     * @param array    $config   Settings for this mongodb storage.
     */
    public function __construct(Database $database, array $config = [])
    {
        $this->database = $database;
        $this->config = array_merge(
            [
                'code_table' => 'oauth_authorization_codes',
                'access_token_table' => 'oauth_access_tokens',
                'client_table' => 'oauth_clients',
                'user_table' => 'oauth_users',
                'refresh_token_table' => 'oauth_refresh_tokens',
                'jti_table' => 'oauth_jti',
                'jwt_table' => 'oauth_jwt',
            ],
            $config
        );
    }

    /**
     * Fetch authorization code data (probably the most common grant type).
     *
     * Retrieve the stored data for the given authorization code.
     *
     * Required for OAuth2::GRANT_TYPE_AUTH_CODE.
     *
     * @param string $code The authorization code to be check with.
     *
     * @return An associative array as below, and NULL if the code is invalid.
     * @code
     * return array(
     *     "client_id"    => CLIENT_ID,      // REQUIRED Stored client identifier
     *     "user_id"      => USER_ID,        // REQUIRED Stored user identifier
     *     "expires"      => EXPIRES,        // REQUIRED Stored expiration in unix timestamp
     *     "redirect_uri" => REDIRECT_URI,   // REQUIRED Stored redirect URI
     *     "scope"        => SCOPE,          // OPTIONAL Stored scope values in space-separated string
     * );
     * @endcode
     *
     * @see http://tools.ietf.org/html/rfc6749#section-4.1
     *
     * @ingroup oauth2_section_4
     */
    public function getAuthorizationCode($code)
    {
        $document = $this->getCollection('code_table')->findOne(['_id' => $code]);
        if ($document === null) {
            return null;
        }

        return [
            'client_id' => $document['client_id'],
            'user_id' => $document['user_id'],
            'expires' => $document['expires']->toDateTime()->getTimestamp(),
            'redirect_uri' => $document['redirect_uri'],
            'scope' => $document['scope'],
        ];
    }

    /**
     * Take the provided authorization code values and store them somewhere.
     *
     * This function should be the storage counterpart to getAuthCode().
     *
     * If storage fails for some reason, we're not currently checking for
     * any sort of success/failure, so you should bail out of the script
     * and provide a descriptive fail message.
     *
     * Required for OAuth2::GRANT_TYPE_AUTH_CODE.
     *
     * @param string  $code        Authorization code to be stored.
     * @param mixed   $clientId    Client identifier to be stored.
     * @param mixed   $userId      User identifier to be stored.
     * @param string  $redirectUri Redirect URI(s) to be stored in a space-separated string.
     * @param integer $expires     Expiration to be stored as a Unix timestamp.
     * @param string  $scope       OPTIONAL Scopes to be stored in space-separated string.
     *
     * @return void
     *
     * @ingroup oauth2_section_4
     */
    public function setAuthorizationCode($code, $clientId, $userId, $redirectUri, $expires, $scope = null)
    {
        $this->getCollection('code_table')->insertOne(
            [
                '_id' => $code,
                'client_id' => $clientId,
                'user_id' => $userId,
                'redirect_uri' => $redirectUri,
                'expires' => new UTCDateTime($expires * 1000),
                'scope' => $scope,
            ]
        );
    }

    /**
     * once an Authorization Code is used, it must be exipired
     *
     * @param string $code The authorization code to expire.
     *
     * @see http://tools.ietf.org/html/rfc6749#section-4.1.2
     *
     *    The client MUST NOT use the authorization code
     *    more than once.  If an authorization code is used more than
     *    once, the authorization server MUST deny the request and SHOULD
     *    revoke (when possible) all tokens previously issued based on
     *    that authorization code
     *
     * @return void
     */
    public function expireAuthorizationCode($code)
    {
        $this->getCollection('code_table')->deleteOne(['_id' => $code]);
    }

    /**
     * Look up the supplied oauth_token from storage.
     *
     * We need to retrieve access token data as we create and verify tokens.
     *
     * @param string $token The oauth_token to be check with.
     *
     * @return array An associative array as below, and return NULL if the supplied oauth_token
     * is invalid:
     * - expires: Stored expiration in unix timestamp.
     * - client_id: (optional) Stored client identifier.
     * - user_id: (optional) Stored user identifier.
     * - scope: (optional) Stored scope values in space-separated string.
     *
     * @ingroup oauth2_section_7
     */
    public function getAccessToken($token)
    {
        $document = $this->getCollection('access_token_table')->findOne(['_id' => $token]);
        if ($document === null) {
            return null;
        }

        return [
            'expires' => $document['expires']->toDateTime()->getTimestamp(),
            'client_id' => $document['client_id'],
            'user_id' => $document['user_id'],
            'scope' => $document['scope'],
        ];
    }

    /**
     * Store the supplied access token values to storage.
     *
     * We need to store access token data as we create and verify tokens.
     *
     * @param string  $token    The oauth_token to be stored.
     * @param string  $clientId Client identifier to be stored.
     * @param string  $userId   User identifier to be stored.
     * @param integer $expires  Expiration to be stored as a Unix timestamp.
     * @param string  $scope    OPTIONAL Scopes to be stored in space-separated string.
     *
     * @return void
     *
     * @ingroup oauth2_section_4
     */
    public function setAccessToken($token, $clientId, $userId, $expires, $scope = null)
    {
        $this->getCollection('access_token_table')->insertOne(
            [
                '_id' => $token,
                'client_id' => $clientId,
                'user_id' => $userId,
                'expires' => new UTCDateTime($expires * 1000),
                'scope' => $scope,
            ]
        );
    }

    /**
     * Get client details corresponding client_id.
     *
     * OAuth says we should store request URIs for each registered client.
     * Implement this function to grab the stored URI for a given client id.
     *
     * @param string $clientId Client identifier to be check with.
     *
     * @return array|false
     *               Client details. The only mandatory key in the array is "redirect_uri".
     *               This function MUST return FALSE if the given client does not exist or is
     *               invalid. "redirect_uri" can be space-delimited to allow for multiple valid uris.
     *               <code>
     *               return array(
     *               "redirect_uri" => REDIRECT_URI,      // REQUIRED redirect_uri registered for the client
     *               "client_id"    => CLIENT_ID,         // OPTIONAL the client id
     *               "grant_types"  => GRANT_TYPES,       // OPTIONAL an array of restricted grant types
     *               "user_id"      => USER_ID,           // OPTIONAL the user identifier associated with this client
     *               "scope"        => SCOPE,             // OPTIONAL the scopes allowed for this client
     *               );
     *               </code>
     *
     * @ingroup oauth2_section_4
     */
    public function getClientDetails($clientId)
    {
        $document = $this->getCollection('client_table')->findOne(['_id' => $clientId]);
        if ($document === null) {
            return false;
        }

        return [
            'redirect_uri' => implode(' ', $document['redirect_uri']),
            'client_id' => $clientId,
            'grant_types' => $document['grant_types'],
            'user_id' => $document['user_id'],
            'scope' => empty($document['scope']) ? null : implode(' ', $document['scope']),
        ];
    }

    /**
     * Get the scope associated with this client.
     *
     * @param string $clientId Client identifier to be check with.
     *
     * @return string The space-delineated scope list for the specified client_id.
     */
    public function getClientScope($clientId)
    {
        $client = $this->getClientDetails($clientId);
        if ($client === false) {
            return '';
        }

        return empty($client['scope']) ? '' : $client['scope'];
    }

    /**
     * Check restricted grant types of corresponding client identifier.
     *
     * @param string $clientId  Client identifier to be check with.
     * @param string $grantType Grant type to be check with.
     *
     * @return boolean Returns TRUE if the grant type is supported by this client identifier, and otherwise FALSE.
     *
     * @ingroup oauth2_section_4
     */
    public function checkRestrictedGrantType($clientId, $grantType)
    {
        $client = $this->getClientDetails($clientId);
        return $client === false ? false : in_array($grantType, $client['grant_types']);
    }

    /**
     * Make sure that the client credentials is valid.
     *
     * @param string $clientId     Client identifier to be check with.
     * @param string $clientSecret OPTIONAL If a secret is required, check that they've given the right one.
     *
     * @return boolean Returns TRUE if the client credentials are valid, and MUST return FALSE if it isn't.
     *
     * @see http://tools.ietf.org/html/rfc6749#section-3.1
     *
     * @ingroup oauth2_section_3
     */
    public function checkClientCredentials($clientId, $clientSecret = null)
    {
        $document = $this->getCollection('client_table')->findOne(['_id' => $clientId]);
        if ($document === null) {
            return false;
        }

        return self::encryptCredentials($clientId, $clientSecret) === $document['client_secret'];
    }

    /**
     * Determine if the client is a "public" client, and therefore does not require passing credentials for certain
     * grant types.
     *
     * @param string $clientId Client identifier to be check with.
     *
     * @return boolean Returns TRUE if the client is public, and FALSE if it isn't.
     *
     * @see http://tools.ietf.org/html/rfc6749#section-2.3
     * @see https://github.com/bshaffer/oauth2-server-php/issues/257
     *
     * @ingroup oauth2_section_2
     */
    public function isPublicClient($clientId)
    {
        $document = $this->getCollection('client_table')->findOne(['_id' => $clientId]);
        if ($document === null) {
            return false;
        }

        return empty($document['client_secret']);
    }

    /**
     * Grant access tokens for basic user credentials.
     *
     * Check the supplied username and password for validity.
     *
     * You can also use the $client_id param to do any checks required based
     * on a client, if you need that.
     *
     * Required for OAuth2::GRANT_TYPE_USER_CREDENTIALS.
     *
     * @param string $username Username to be check with.
     * @param string $password Password to be check with.
     *
     * @return boolean Returns TRUE if the username and password are valid, and FALSE if it isn't.
     * Moreover, if the username and password are valid, and you want to
     *
     * @see http://tools.ietf.org/html/rfc6749#section-4.3
     *
     * @ingroup oauth2_section_4
     */
    public function checkUserCredentials($username, $password)
    {
        $document = $this->getCollection('user_table')->findOne(['_id' => $username]);
        if ($document === null) {
            return false;
        }

        return self::encryptCredentials($username, $password) === $document['password'];
    }

    /**
     * Get the details for a specific user.
     *
     * @param string $username The user identifier for which the details will be returned.
     *
     * @return array The associated "user_id" and optional "scope" values.
     * This function MUST return FALSE if the requested user does not exist or is
     * invalid. "scope" is a space-separated list of restricted scopes.
     * @code
     * return array(
     *     "user_id"  => USER_ID,    // REQUIRED user_id to be stored with the authorization code or access token
     *     "scope"    => SCOPE       // OPTIONAL space-separated list of restricted scopes
     * );
     * @endcode
     */
    public function getUserDetails($username)
    {
        $document = $this->getCollection('user_table')->findOne(['_id' => $username]);
        if ($document === null) {
            return false;
        }

        return [
            'user_id' => $username,
            'scope' => empty($document['scope']) ? null : implode(' ', $document['scope']),
        ];
    }

    /**
     * Grant refresh access tokens.
     *
     * Retrieve the stored data for the given refresh token.
     *
     * Required for OAuth2::GRANT_TYPE_REFRESH_TOKEN.
     *
     * @param string $token Refresh token to be check with.
     *
     * @return array An associative array as below, and NULL if the refresh_token is invalid.
     * - refresh_token: Refresh token identifier.
     * - client_id: Client identifier.
     * - user_id: User identifier.
     * - expires: Expiration unix timestamp, or 0 if the token doesn't expire.
     * - scope: (optional) Scope values in space-separated string.
     *
     * @see http://tools.ietf.org/html/rfc6749#section-6
     *
     * @ingroup oauth2_section_6
     */
    public function getRefreshToken($token)
    {
        $document = $this->getCollection('refresh_token_table')->findOne(['_id' => $token]);
        if ($document === null) {
            return null;
        }

        return [
            'refresh_token' => $token,
            'client_id' => $document['client_id'],
            'user_id' => $document['user_id'],
            'expires' => $document['expires']->toDateTime()->getTimestamp(),
            'scope' => empty($document['scope']) ? null : implode(' ', $document['scope']),
        ];
    }

    /**
     * Take the provided refresh token values and store them somewhere.
     *
     * This function should be the storage counterpart to getRefreshToken().
     *
     * If storage fails for some reason, we're not currently checking for
     * any sort of success/failure, so you should bail out of the script
     * and provide a descriptive fail message.
     *
     * Required for OAuth2::GRANT_TYPE_REFRESH_TOKEN.
     *
     * @param string  $token    Refresh token to be stored.
     * @param string  $clientId Client identifier to be stored.
     * @param string  $userId   User identifier to be stored.
     * @param integer $expires  Expiration timestamp to be stored. 0 if the token doesn't expire.
     * @param string  $scope    OPTIONAL Scopes to be stored in space-separated string.
     *
     * @return void
     *
     * @ingroup oauth2_section_6
     */
    public function setRefreshToken($token, $clientId, $userId, $expires, $scope = null)
    {
        $this->getCollection('refresh_token_table')->insertOne(
            [
                '_id' => $token,
                'client_id' => $clientId,
                'user_id' => $userId,
                'expires' => new UTCDateTime($expires * 1000),
                'scope' => explode(' ', $scope),
            ]
        );
    }

    /**
     * Expire a used refresh token.
     *
     * This is not explicitly required in the spec, but is almost implied.
     * After granting a new refresh token, the old one is no longer useful and
     * so should be forcibly expired in the data store so it can't be used again.
     *
     * If storage fails for some reason, we're not currently checking for
     * any sort of success/failure, so you should bail out of the script
     * and provide a descriptive fail message.
     *
     * @param string $token Refresh token to be expired.
     *
     * @return void
     *
     * @ingroup oauth2_section_6
     */
    public function unsetRefreshToken($token)
    {
        $this->getCollection('refresh_token_table')->deleteOne(['_id' => $token]);
    }

    /**
     * Get the public key associated with a client_id
     *
     * @param string $clientId Client identifier to be checked with.
     * @param string $subject  The subject to be checked with.
     *
     * @return string Return the public key for the client_id if it exists, and MUST return FALSE if it doesn't.
     */
    public function getClientKey($clientId, $subject)
    {
        $document = $this->getCollection('jwt_table')->findOne(['client_id' => $clientId, 'subject' => $subject]);
        if ($document === null) {
            return false;
        }

        return $document['public_key'];
    }

    /**
     * Get a jti (JSON token identifier) by matching against the client_id, subject, audience and expiration.
     *
     * @param string  $clientId Client identifier to match.
     * @param string  $subject  The subject to match.
     * @param string  $audience The audience to match.
     * @param integer $expires  The expiration of the jti.
     * @param string  $jti      The jti to match.
     *
     * @return array An associative array as below, and return NULL if the jti does not exist.
     * - issuer: Stored client identifier.
     * - subject: Stored subject.
     * - audience: Stored audience.
     * - expires: Stored expires in unix timestamp.
     * - jti: The stored jti.
     */
    public function getJti($clientId, $subject, $audience, $expires, $jti)
    {
        $query = [
            'client_id' => $clientId,
            'subject' => $subject,
            'audience' => $audience,
            'expires' => new UTCDateTime($expires * 1000),
            'jti' => $jti,
        ];
        $document = $this->getCollection('jti_table')->findOne($query);
        if ($document === null) {
            return null;
        }

        return [
            'issuer' => $clientId,
            'subject' => $subject,
            'audience' => $audience,
            'expires' => $expires,
            'jti' => $jti,
        ];
    }

    /**
     * Store a used jti so that we can check against it to prevent replay attacks.
     *
     * @param string  $clientId Client identifier to insert.
     * @param string  $subject  The subject to insert.
     * @param string  $audience The audience to insert.
     * @param integer $expires  The expiration of the jti.
     * @param string  $jti      The jti to insert.
     *
     * @return void
     */
    public function setJti($clientId, $subject, $audience, $expires, $jti)
    {
        $this->getCollection('jti_table')->insertOne(
            [
                'client_id' => $clientId,
                'subject' => $subject,
                'audience' => $audience,
                'expires' => new UTCDateTime($expires * 1000),
                'jti' => $jti,
            ]
        );
    }

    /**
     * Helper method to obtain a mongo collection.
     *
     * @param string $key The index of the config containing the collection name.
     *
     * @return \MongoDB\Collection
     */
    private function getCollection($key)
    {
        return $this->database->selectCollection($this->config[$key]);
    }

    /**
     * Encrypts the credentials and returns the result.
     *
     * @param string $identifier The identifier/username.
     * @param string $secret     The secret/password.
     *
     * @return string The encrypted credentials.
     *
     * @throws \UnexpectedValueException Thrown if unable to encrypt the credentials.
     */
    public static function encryptCredentials($identifier, $secret)
    {
        return crypt("{$identifier}{$secret}", self::SALT);
    }
}
