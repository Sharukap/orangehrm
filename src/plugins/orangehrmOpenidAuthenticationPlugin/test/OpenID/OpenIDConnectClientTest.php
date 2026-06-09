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

namespace OrangeHRM\Tests\OpenidAuthentication\OpenID;

use Jumbojett\OpenIDConnectClientException;
use OrangeHRM\OpenidAuthentication\OpenID\OpenIDConnectClient;
use OrangeHRM\Tests\Util\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * The outbound-fetch guard must reject internal / non-http(s) targets before any usable response
 * is returned, and capture the discovery document so it can be cached.
 *
 * @group OpenIDAuth
 */
class OpenIDConnectClientTest extends TestCase
{
    /**
     * Expose the protected fetchURL and allow injecting a test HTTP client.
     */
    private function getClient(): OpenIDConnectClient
    {
        return new class ('https://idp.example.com') extends OpenIDConnectClient {
            public function fetch(string $url, ?string $postBody = null): string
            {
                return $this->fetchURL($url, $postBody);
            }
        };
    }

    /**
     * Literal private/reserved/loopback/metadata targets are rejected by the egress guard before
     * any connection, so these run without network access. Non-http schemes are rejected up front.
     *
     * @dataProvider blockedTargetProvider
     */
    public function testFetchUrlRejectsDisallowedTargets(string $url): void
    {
        $this->expectException(OpenIDConnectClientException::class);
        $this->getClient()->fetch($url);
    }

    public function blockedTargetProvider(): array
    {
        return [
            'loopback' => ['http://127.0.0.1/.well-known/openid-configuration'],
            'cloud metadata' => ['http://169.254.169.254/latest/meta-data/'],
            'rfc1918' => ['http://10.1.2.3:9200/'],
            'cgnat' => ['http://100.64.1.1/'],
            'ipv6 loopback' => ['http://[::1]/'],
            'non-http scheme' => ['gopher://93.184.216.34/'],
        ];
    }

    public function testFetchUrlRejectsNonHttpSchemeWithClearMessage(): void
    {
        $this->expectException(OpenIDConnectClientException::class);
        $this->expectExceptionMessage('disallowed scheme');
        $this->getClient()->fetch('ftp://files.example.com/');
    }

    /**
     * A successful discovery fetch returns the body and captures the document for caching.
     */
    public function testFetchUrlCapturesDiscoveryDocument(): void
    {
        $discovery = json_encode([
            'issuer' => 'https://idp.example.com',
            'authorization_endpoint' => 'https://idp.example.com/authorize',
        ]);

        $client = $this->getClient();
        $client->setHttpClient(new MockHttpClient(
            new MockResponse($discovery, ['response_headers' => ['content-type' => 'application/json']])
        ));

        $output = $client->fetch('https://idp.example.com/.well-known/openid-configuration');

        $this->assertSame($discovery, $output);
        $this->assertSame($discovery, $client->getCapturedWellKnownConfig());
        $this->assertSame(200, $client->getResponseCode());
        $this->assertSame('application/json', $client->getResponseContentType());
    }

    /**
     * A non-discovery fetch (e.g. userinfo) does not capture a well-known document.
     */
    public function testFetchUrlDoesNotCaptureNonDiscoveryResponse(): void
    {
        $client = $this->getClient();
        $client->setHttpClient(new MockHttpClient(
            new MockResponse(json_encode(['email' => 'a@example.com']))
        ));

        $client->fetch('https://idp.example.com/userinfo');

        $this->assertNull($client->getCapturedWellKnownConfig());
    }

    /**
     * When the discovery document is injected (from cache), reading a provider config value must
     * NOT trigger an outbound discovery fetch.
     */
    public function testInjectedWellKnownConfigSkipsDiscovery(): void
    {
        $client = new class ('https://idp.example.com') extends OpenIDConnectClient {
            public function configValue(string $param)
            {
                return $this->getProviderConfigValue($param);
            }

            protected function fetchURL(string $url, ?string $post_body = null, array $headers = [])
            {
                throw new \RuntimeException('discovery must not be fetched when config is cached');
            }
        };

        $client->providerConfigParam(['authorization_endpoint' => 'https://idp.example.com/authorize']);

        $this->assertEquals('https://idp.example.com/authorize', $client->configValue('authorization_endpoint'));
    }
}
