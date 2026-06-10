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
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\HttpClient\NoPrivateNetworkHttpClient;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpClientExceptionInterface;

class OpenIDConnectClient extends \Jumbojett\OpenIDConnectClient
{
    use AuthUserTrait;

    protected ?string $generatedAuthUrl = null;

    /**
     * When false (default) every server-side OIDC request is routed through
     * {@see NoPrivateNetworkHttpClient}, which rejects any hop resolving to a private,
     * loopback, link-local (incl. 169.254.169.254 cloud metadata) or reserved address —
     * the SSRF guard. Admins running a provider on an internal network can opt out.
     */
    protected bool $allowPrivateProviderHosts = false;

    protected ?int $httpResponseCode = null;

    protected ?string $httpResponseContentType = null;

    /**
     * @param bool $allow
     */
    public function setAllowPrivateProviderHosts(bool $allow): void
    {
        $this->allowPrivateProviderHosts = $allow;
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

    /**
     * Replaces the library's raw cURL transport with Symfony HttpClient so that every
     * outbound OIDC request (discovery, token, JWKS, userinfo) — and every redirect hop —
     * is screened by {@see NoPrivateNetworkHttpClient} unless an admin has opted out.
     *
     * @inheritDoc
     */
    protected function fetchURL(string $url, ?string $post_body = null, array $headers = [])
    {
        $method = 'GET';
        $requestHeaders = $headers;
        $requestHeaders[] = 'User-Agent: ' . $this->getUserAgent();

        $options = [
            'max_redirects' => 20,
            'timeout' => $this->getTimeout(),
            'max_duration' => $this->getTimeout(),
            'verify_peer' => $this->getVerifyPeer(),
            'verify_host' => $this->getVerifyHost(),
        ];

        if ($post_body !== null) {
            $method = 'POST';
            $contentType = is_object(json_decode($post_body, false))
                ? 'application/json'
                : 'application/x-www-form-urlencoded';
            $requestHeaders[] = "Content-Type: $contentType";
            $options['body'] = $post_body;
        }

        $options['headers'] = $requestHeaders;

        $certPath = $this->getCertPath();
        if (!empty($certPath)) {
            $options['cafile'] = $certPath;
        }

        $client = HttpClient::create();
        if (!$this->allowPrivateProviderHosts) {
            $client = new NoPrivateNetworkHttpClient($client);
        }

        try {
            $response = $client->request($method, $url, $options);
            $this->httpResponseCode = $response->getStatusCode();
            $contentTypeHeader = $response->getHeaders(false)['content-type'][0] ?? null;
            $this->httpResponseContentType = $contentTypeHeader;

            return $response->getContent(false);
        } catch (HttpClientExceptionInterface $e) {
            throw new OpenIDConnectClientException($e->getMessage(), 0, $e);
        }
    }

    /**
     * @inheritDoc
     */
    public function getResponseCode(): int
    {
        return (int) $this->httpResponseCode;
    }

    /**
     * @inheritDoc
     */
    public function getResponseContentType()
    {
        return $this->httpResponseContentType;
    }
}
