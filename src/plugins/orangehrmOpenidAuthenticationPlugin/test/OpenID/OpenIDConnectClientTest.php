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

/**
 * The outbound-fetch guard must reject internal / non-http(s) targets (and therefore never reach
 * cURL) before any network connection is attempted.
 *
 * @group OpenIDAuth
 */
class OpenIDConnectClientTest extends TestCase
{
    private function getClient(): OpenIDConnectClient
    {
        // Expose the protected fetchURL so the SSRF guard can be exercised directly.
        return new class ('https://idp.example.com') extends OpenIDConnectClient {
            public function fetch(string $url): string
            {
                return $this->fetchURL($url);
            }
        };
    }

    /**
     * @dataProvider blockedTargetProvider
     */
    public function testFetchUrlRejectsDisallowedTargets(string $url): void
    {
        $this->expectException(OpenIDConnectClientException::class);
        $this->expectExceptionMessage('Refusing to fetch disallowed OIDC URL');
        $this->getClient()->fetch($url);
    }

    public function blockedTargetProvider(): array
    {
        return [
            'loopback' => ['http://127.0.0.1/.well-known/openid-configuration'],
            'cloud metadata' => ['http://169.254.169.254/latest/meta-data/'],
            'rfc1918' => ['http://10.1.2.3:9200/'],
            'ipv6 loopback' => ['http://[::1]/'],
            'non-http scheme' => ['gopher://93.184.216.34/'],
        ];
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
