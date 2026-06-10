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
 * @group OpenIDAuth
 */
class OpenIDConnectClientTest extends TestCase
{
    /**
     * Exposes the protected transport so SSRF egress behaviour can be asserted directly.
     */
    private function getClient(string $providerUrl): OpenIDConnectClient
    {
        return new class ($providerUrl, 'client-id', 'client-secret') extends OpenIDConnectClient {
            public function exposedFetchURL(string $url, ?string $postBody = null, array $headers = [])
            {
                return $this->fetchURL($url, $postBody, $headers);
            }
        };
    }

    /**
     * @dataProvider blockedTargetProvider
     */
    public function testFetchUrlBlocksRequestsToPrivateOrInternalTargets(string $url): void
    {
        $client = $this->getClient($url);

        $this->expectException(OpenIDConnectClientException::class);
        $this->expectExceptionMessageMatches('/blocked/i');

        $client->exposedFetchURL($url);
    }

    public function blockedTargetProvider(): array
    {
        return [
            'loopback IPv4' => ['http://127.0.0.1:19877/.well-known/openid-configuration'],
            'cloud metadata' => ['http://169.254.169.254/latest/meta-data/'],
            'private RFC1918' => ['http://10.0.0.5/.well-known/openid-configuration'],
            'loopback hostname' => ['http://localhost:8080/.well-known/openid-configuration'],
        ];
    }

    /**
     * With the admin opt-out enabled, the private-network egress filter must not be applied:
     * the request fails for ordinary connection reasons, never with a "blocked" rejection.
     */
    public function testFetchUrlAllowsPrivateTargetsWhenOptedIn(): void
    {
        $client = $this->getClient('http://127.0.0.1:19877');
        $client->setAllowPrivateProviderHosts(true);

        try {
            $client->exposedFetchURL('http://127.0.0.1:19877/.well-known/openid-configuration');
            $this->fail('Expected a transport failure connecting to a closed port.');
        } catch (OpenIDConnectClientException $e) {
            $this->assertStringNotContainsStringIgnoringCase('blocked', $e->getMessage());
        }
    }
}
