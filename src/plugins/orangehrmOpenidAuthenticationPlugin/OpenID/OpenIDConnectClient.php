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
use OrangeHRM\OpenidAuthentication\Exception\OIDCUrlNotAllowedException;
use OrangeHRM\OpenidAuthentication\Utility\OIDCUrlValidator;

class OpenIDConnectClient extends \Jumbojett\OpenIDConnectClient
{
    use AuthUserTrait;

    protected ?string $generatedAuthUrl = null;

    private ?OIDCUrlValidator $urlValidator = null;

    private int $lastResponseCode = 0;

    private ?string $lastResponseContentType = null;

    private ?string $capturedWellKnownConfig = null;

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
     * @return OIDCUrlValidator
     */
    public function getUrlValidator(): OIDCUrlValidator
    {
        return $this->urlValidator ??= new OIDCUrlValidator();
    }

    /**
     * @param OIDCUrlValidator $urlValidator
     */
    public function setUrlValidator(OIDCUrlValidator $urlValidator): void
    {
        $this->urlValidator = $urlValidator;
    }

    /**
     * Every outbound request (discovery, token, userinfo) flows through here. The target is
     * re-validated on each call and cURL is pinned to the validated IP via CURLOPT_RESOLVE to close
     * the DNS-rebinding window; redirect-following is disabled so a 30x cannot reach an internal host.
     *
     * @inheritDoc
     * @throws OpenIDConnectClientException
     */
    protected function fetchURL(string $url, ?string $post_body = null, array $headers = [])
    {
        try {
            $validatedIp = $this->getUrlValidator()->resolveValidatedIp($url);
        } catch (OIDCUrlNotAllowedException $e) {
            throw new OpenIDConnectClientException('Refusing to fetch disallowed OIDC URL: ' . $e->getMessage());
        }

        $parts = parse_url($url);
        $host = $parts['host'] ?? '';
        if (strlen($host) > 1 && $host[0] === '[' && substr($host, -1) === ']') {
            $host = substr($host, 1, -1);
        }
        $scheme = strtolower($parts['scheme'] ?? 'https');
        $port = $parts['port'] ?? ($scheme === 'http' ? 80 : 443);
        $resolveTarget = strpos($validatedIp, ':') !== false ? '[' . $validatedIp . ']' : $validatedIp;

        $ch = curl_init();

        if ($post_body !== null) {
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
            curl_setopt($ch, CURLOPT_POSTFIELDS, $post_body);
            $contentType = is_object(json_decode($post_body, false))
                ? 'application/json'
                : 'application/x-www-form-urlencoded';
            $headers[] = "Content-Type: $contentType";
        }

        curl_setopt($ch, CURLOPT_USERAGENT, $this->getUserAgent());
        if (count($headers) > 0) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        }
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RESOLVE, ["$host:$port:$resolveTarget"]);
        curl_setopt($ch, CURLOPT_HEADER, 0);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
        // OIDC mandates TLS; always verify the certificate.
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeOut);

        $output = curl_exec($ch);

        $info = curl_getinfo($ch);
        $this->lastResponseCode = (int)($info['http_code'] ?? 0);
        $this->lastResponseContentType = $info['content_type'] ?? null;

        if ($output === false) {
            $error = 'Curl error: (' . curl_errno($ch) . ') ' . curl_error($ch);
            curl_close($ch);
            throw new OpenIDConnectClientException($error);
        }

        curl_close($ch);

        // Capture the discovery document so it can be cached for later logins.
        if (
            is_string($output)
            && substr((string)parse_url($url, PHP_URL_PATH), -strlen('/.well-known/openid-configuration'))
            === '/.well-known/openid-configuration'
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
