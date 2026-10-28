<?php

declare(strict_types=1);

namespace Widthx\Auth;

use GuzzleHttp\Exception\GuzzleException;
use League\OAuth2\Client\OptionProvider\HttpBasicAuthOptionProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Token\AccessTokenInterface;
use Widthx\Auth\Exception\AuthorizationException;
use Widthx\Auth\Exception\InvalidTokenException;

/**
 * Relying-party side, as a thin wrapper around league/oauth2-client (authorization URL, state,
 * PKCE S256, code exchange, refresh). Widthx adds what the OAuth2 library does not do for OIDC:
 * discovery, nonce, ID-token signature/claims validation (firebase/php-jwt + JWKS) and RP logout.
 */
final class OidcClient
{
    /** Extra authorization parameters an app may pass through. Everything else is ignored. */
    private const PASSTHROUGH = ['prompt', 'max_age', 'login_hint', 'ui_locales'];

    private ?GenericProvider $provider = null;

    public function __construct(
        private readonly Config $config,
        private readonly Http $http,
        private readonly Discovery $discovery,
        private readonly JwtVerifier $jwt,
    ) {
    }

    private function provider(): GenericProvider
    {
        return $this->provider ??= new GenericProvider(
            [
                'clientId' => $this->config->clientId,
                'clientSecret' => $this->config->clientSecret,
                'redirectUri' => $this->config->redirectUri,
                'urlAuthorize' => $this->discovery->endpoint('authorization_endpoint'),
                'urlAccessToken' => $this->discovery->endpoint('token_endpoint'),
                'urlResourceOwnerDetails' => $this->discovery->endpoint('userinfo_endpoint'),
                'scopes' => $this->config->scopes,
                'scopeSeparator' => ' ',
                'pkceMethod' => GenericProvider::PKCE_METHOD_S256,
            ],
            [
                'httpClient' => $this->http->client(),
                // Widthx clients authenticate with client_secret_basic (league defaults to client_secret_post).
                ...($this->config->clientSecret !== null ? ['optionProvider' => new HttpBasicAuthOptionProvider()] : []),
            ],
        );
    }

    /**
     * Builds the authorization URL. Persist the returned PendingAuthorization server-side.
     *
     * @param array<string, string> $extra
     * @return array{0: string, 1: PendingAuthorization}
     */
    public function createAuthorization(string $returnTo = '/', array $extra = []): array
    {
        $nonce = self::random();
        $options = ['nonce' => $nonce, 'approval_prompt' => null];
        if ($this->config->audience !== []) {
            $options['audience'] = implode(' ', $this->config->audience);
        }
        foreach (self::PASSTHROUGH as $key) {
            if (isset($extra[$key]) && $extra[$key] !== '') {
                $options[$key] = $extra[$key];
            }
        }
        $provider = $this->provider();
        $url = $provider->getAuthorizationUrl($options); // generates state + PKCE verifier
        $pending = new PendingAuthorization(
            state: $provider->getState(),
            nonce: $nonce,
            codeVerifier: (string) $provider->getPkceCode(),
            returnTo: self::safeReturnTo($returnTo),
            createdAt: time(),
        );
        return [$url, $pending];
    }

    /**
     * Validates the redirect back from the IdP and exchanges the code.
     *
     * @param array<string, mixed> $query the callback query parameters ($_GET / $request->query())
     */
    public function handleCallback(array $query, ?PendingAuthorization $pending, int $maxAgeSeconds = 600): TokenSet
    {
        $param = static fn (string $name): string => is_string($query[$name] ?? null) ? $query[$name] : '';
        if ($param('error') !== '') {
            throw new AuthorizationException(self::code($param('error')));
        }
        if ($pending === null || !$pending->isComplete() || $pending->createdAt < time() - $maxAgeSeconds) {
            throw new AuthorizationException('login_expired', 'no pending authorization (expired or already used)');
        }
        if (!hash_equals($pending->state, $param('state'))) {
            throw new AuthorizationException('state_mismatch');
        }
        $code = $param('code');
        if ($code === '') {
            throw new AuthorizationException('invalid_request', 'missing code');
        }
        $provider = $this->provider();
        $provider->setPkceCode($pending->codeVerifier);
        $tokens = $this->toTokenSet($this->grant('authorization_code', ['code' => $code]));
        if ($tokens->idToken === null) {
            throw new AuthorizationException('invalid_id_token', 'no id_token returned');
        }
        $nonce = $tokens->idTokenClaims['nonce'] ?? null;
        if (!is_string($nonce) || !hash_equals($pending->nonce, $nonce)) {
            throw new AuthorizationException('invalid_id_token', 'nonce mismatch');
        }
        return $tokens;
    }

    /**
     * Refresh tokens rotate: always persist the returned refresh token. Pass the subject of the
     * current session as `$expectedSubject` so a refreshed ID token for another user is rejected
     * (OIDC Core 12.2; the issuer is already pinned by the verifier).
     */
    public function refresh(string $refreshToken, ?string $expectedSubject = null): TokenSet
    {
        $tokens = $this->toTokenSet($this->grant('refresh_token', ['refresh_token' => $refreshToken]));
        if ($expectedSubject !== null && $tokens->idToken !== null && $tokens->subject() !== $expectedSubject) {
            throw new AuthorizationException('invalid_id_token', 'sub changed on refresh');
        }
        return $tokens;
    }

    /** RP-initiated logout URL (ends the Widthx IdP session after user confirmation). */
    public function endSessionUrl(string $idTokenHint, ?string $state = null): string
    {
        $params = ['id_token_hint' => $idTokenHint];
        if ($this->config->postLogoutRedirectUri !== null) {
            $params['post_logout_redirect_uri'] = $this->config->postLogoutRedirectUri;
        }
        if ($state !== null) {
            $params['state'] = $state;
        }
        return $this->discovery->endpoint('end_session_endpoint') . '?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    /** @param array<string, string> $params */
    private function grant(string $grant, array $params): AccessTokenInterface
    {
        try {
            return $this->provider()->getAccessToken($grant, $params);
        } catch (IdentityProviderException $e) {
            $body = $e->getResponseBody();
            $error = is_array($body) && isset($body['error']) ? (string) $body['error'] : 'token_error';
            throw new AuthorizationException(self::code($error));
        } catch (\UnexpectedValueException $e) {
            throw new AuthorizationException('token_error', $e->getMessage());
        } catch (GuzzleException $e) {
            throw new AuthorizationException('token_error', 'token endpoint request failed', $e);
        }
    }

    private function toTokenSet(AccessTokenInterface $token): TokenSet
    {
        $values = $token->getValues();
        $idToken = isset($values['id_token']) && is_string($values['id_token']) ? $values['id_token'] : null;
        $claims = [];
        if ($idToken !== null) {
            try {
                $claims = $this->jwt->verify($idToken, $this->config->clientId, acceptedTypes: ['JWT', 'id_token+jwt']);
            } catch (InvalidTokenException $e) {
                throw new AuthorizationException('invalid_id_token', $e->getMessage());
            }
            if (array_key_exists('events', $claims)) {
                throw new AuthorizationException('invalid_id_token', 'not an ID token');
            }
            // OIDC Core 3.1.3.7: azp is required when there are several audiences, and must be us.
            $azp = $claims['azp'] ?? null;
            $multipleAudiences = is_array($claims['aud']) && count($claims['aud']) > 1;
            if (($multipleAudiences || $azp !== null) && $azp !== $this->config->clientId) {
                throw new AuthorizationException('invalid_id_token', 'azp mismatch');
            }
        }
        return new TokenSet(
            accessToken: $token->getToken(),
            idToken: $idToken,
            refreshToken: $token->getRefreshToken(),
            expiresAt: $token->getExpires(),
            idTokenClaims: $claims,
        );
    }

    /** Only same-site relative paths are accepted as post-login destinations (open-redirect guard). */
    public static function safeReturnTo(string $returnTo): string
    {
        if ($returnTo === '' || $returnTo[0] !== '/' || str_starts_with($returnTo, '//') || str_contains($returnTo, '\\')
            || preg_match('/[\x00-\x1f]/', $returnTo)) {
            return '/';
        }
        return $returnTo;
    }

    private static function code(string $error): string
    {
        return preg_replace('/[^a-z_]/', '', strtolower($error)) ?: 'unknown_error';
    }

    private static function random(int $bytes = 32): string
    {
        return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    }
}
