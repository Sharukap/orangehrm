<?php

/**
 * OrangeHRM is a comprehensive Human Resource Management (HRM) System that captures
 * all the essential functionalities required for any enterprise.
 * Copyright (C) 2006 OrangeHRM Inc., http://www.orangehrm.com
 *
 * OrangeHRM is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 *
 * OrangeHRM is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with OrangeHRM.
 * If not, see <https://www.gnu.org/licenses/>.
 */

namespace OrangeHRM\OpenidAuthentication\OpenID;

use Jumbojett\OpenIDConnectClientException;
use OrangeHRM\Core\Traits\Auth\AuthUserTrait;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpClientExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

class OpenIDConnectClient extends \Jumbojett\OpenIDConnectClient
{
    use AuthUserTrait;

    private const REQUEST_TIMEOUT = 60;

    private const WELL_KNOWN_PATH = '/.well-known/openid-configuration';

    protected ?string $generatedAuthUrl = null;

    private ?HttpClientInterface $httpClient = null;

    private int $lastResponseCode = 0;

    private ?string $lastResponseContentType = null;

    private ?string $capturedWellKnownConfig = null;

    /**
     * @return HttpClientInterface
     */
    public function getHttpClient(): HttpClientInterface
    {
        return $this->httpClient ??= SafeHttpClientFactory::create();
    }

    /**
     * @param HttpClientInterface $httpClient
     */
    public function setHttpClient(HttpClientInterface $httpClient): void
    {
        $this->httpClient = $httpClient;
    }

    /**
     * The raw OIDC discovery document fetched during this request, if any, so it can be cached
     * and reused to skip discovery on later logins.
     *
     * @return string|null
     */
    public function getCapturedWellKnownConfig(): ?string
    {
        return $this->capturedWellKnownConfig;
    }

    /**
     * Every outbound request (discovery, token, userinfo) flows through here. Jumbojett's raw
     * cURL implementation is replaced with a delegation to an SSRF-guarded Symfony HTTP client:
     * the target is rejected before connecting if it resolves to a blocked address, the connected
     * IP is re-checked (DNS-rebinding defence) and redirects are not followed. Only the http/https
     * scheme is permitted.
     *
     * @inheritDoc
     * @throws OpenIDConnectClientException
     */
    protected function fetchURL(string $url, ?string $post_body = null, array $headers = [])
    {
        $scheme = strtolower((string)parse_url($url, PHP_URL_SCHEME));
        if (!in_array($scheme, ['http', 'https'], true)) {
            throw new OpenIDConnectClientException('Refusing to fetch OIDC URL with disallowed scheme');
        }

        $method = 'GET';
        $options = [
            'max_redirects' => 0,
            'timeout' => self::REQUEST_TIMEOUT,
        ];

        if ($post_body !== null) {
            $method = 'POST';
            $options['body'] = $post_body;
            // Mirror Jumbojett: form-encoded by default, JSON when the body is a JSON object.
            $headers[] = is_object(json_decode($post_body, false))
                ? 'Content-Type: application/json'
                : 'Content-Type: application/x-www-form-urlencoded';
        }

        $headers[] = 'User-Agent: ' . $this->getUserAgent();
        $options['headers'] = $headers;

        try {
            $response = $this->getHttpClient()->request($method, $url, $options);
            // Accessing the response triggers the transfer; the guarded client throws here if the
            // host (or a redirect/rebind target) resolves to a blocked address.
            $this->lastResponseCode = $response->getStatusCode();
            $contentTypeHeader = $response->getHeaders(false)['content-type'] ?? [];
            $this->lastResponseContentType = $contentTypeHeader[0] ?? null;
            $output = $response->getContent(false);
        } catch (HttpClientExceptionInterface $e) {
            throw new OpenIDConnectClientException('OIDC HTTP request failed: ' . $e->getMessage());
        }

        // Capture the discovery document so it can be cached for later logins.
        $path = (string)parse_url($url, PHP_URL_PATH);
        if (
            substr($path, -strlen(self::WELL_KNOWN_PATH)) === self::WELL_KNOWN_PATH
            && is_object(json_decode($output, false))
        ) {
            $this->capturedWellKnownConfig = $output;
        }

        return $output;
    }

    /**
     * @inheritDoc
     */
    public function getResponseCode(): int
    {
        return $this->lastResponseCode;
    }

    /**
     * @inheritDoc
     */
    public function getResponseContentType()
    {
        return $this->lastResponseContentType;
    }

    /**
     * @inheritDoc
     */
    public function redirect(string $url)
    {
        $this->generatedAuthUrl = $url;
    }

    /**
     * @inheritDoc
     */
    public function getGeneratedAuthUrl(): string
    {
        return $this->generatedAuthUrl;
    }

    /**
     * @inheritDoc
     */
    public function commitSession(): void
    {
    }

    /**
     * @inheritDoc
     */
    protected function setSessionKey(string $key, $value)
    {
        $this->getAuthUser()->setAttribute($key, $value);
    }

    /**
     * @inheritDoc
     */
    protected function getSessionKey(string $key)
    {
        return $this->getAuthUser()->getAttribute($key);
    }

    /**
     * @inheritDoc
     */
    protected function unsetSessionKey(string $key)
    {
        $this->getAuthUser()->removeAttribute($key);
    }
}
