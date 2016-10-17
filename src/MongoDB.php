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
    ClientCredentialsInterface
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

        return crypt($clientId . $clientSecret, self::SALT) === $document['client_secret'];
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
}
