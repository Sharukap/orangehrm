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

namespace OrangeHRM\Tests\OpenidAuthentication\Utility;

use OrangeHRM\OpenidAuthentication\Exception\OIDCUrlNotAllowedException;
use OrangeHRM\OpenidAuthentication\Utility\OIDCUrlValidator;
use OrangeHRM\Tests\Util\TestCase;

/**
 * Regression cover for the OIDC provider-URL SSRF allowlist.
 *
 * @group OpenIDAuth
 */
class OIDCUrlValidatorTest extends TestCase
{
    /**
     * Builds a validator with a fixed host->IP resolution map so DNS is deterministic.
     *
     * @param array<string, string[]> $dnsMap
     */
    private function getValidator(array $dnsMap = []): OIDCUrlValidator
    {
        return new class ($dnsMap) extends OIDCUrlValidator {
            /** @var array<string, string[]> */
            private array $dnsMap;

            public function __construct(array $dnsMap)
            {
                $this->dnsMap = $dnsMap;
            }

            protected function resolveHostToIps(string $host): array
            {
                return $this->dnsMap[$host] ?? [];
            }
        };
    }

    /**
     * @dataProvider allowedUrlProvider
     */
    public function testAllowedUrls(string $url, array $dnsMap): void
    {
        $this->assertTrue($this->getValidator($dnsMap)->isAllowedProviderUrl($url));
    }

    public function allowedUrlProvider(): array
    {
        return [
            'public https literal IP' => ['https://8.8.8.8/', []],
            'public host' => ['https://accounts.google.com', ['accounts.google.com' => ['142.250.72.1']]],
            'public http host' => ['http://idp.example.com/', ['idp.example.com' => ['93.184.216.34']]],
            'public IPv6 literal' => ['https://[2606:4700:4700::1111]/', []],
        ];
    }

    /**
     * @dataProvider blockedUrlProvider
     */
    public function testBlockedUrls(string $url, array $dnsMap): void
    {
        $this->assertFalse($this->getValidator($dnsMap)->isAllowedProviderUrl($url));
    }

    public function blockedUrlProvider(): array
    {
        return [
            'loopback literal' => ['http://127.0.0.1/', []],
            'cloud metadata' => ['http://169.254.169.254/latest/meta-data/', []],
            'rfc1918 10/8' => ['http://10.0.0.5:8080/', []],
            'rfc1918 172.16/12' => ['https://172.16.5.4/', []],
            'rfc1918 192.168/16' => ['http://192.168.1.1/', []],
            'cgnat 100.64/10' => ['http://100.64.0.1/', []],
            'ipv6 loopback literal' => ['http://[::1]/', []],
            'non-http scheme ftp' => ['ftp://example.com/', ['example.com' => ['93.184.216.34']]],
            'file scheme' => ['file:///etc/passwd', []],
            'missing host' => ['not-a-valid-url', []],
            'host resolves to private (rebinding)' => ['https://evil.example.com/', ['evil.example.com' => ['10.0.0.9']]],
            'host resolves to mixed public+private' => ['https://mixed.example.com/', ['mixed.example.com' => ['8.8.8.8', '10.0.0.9']]],
            'host does not resolve' => ['https://nxdomain.example.com/', []],
        ];
    }

    public function testResolveValidatedIpReturnsResolvedPublicIp(): void
    {
        $ip = $this->getValidator(['idp.example.com' => ['93.184.216.34']])
            ->resolveValidatedIp('https://idp.example.com/');
        $this->assertEquals('93.184.216.34', $ip);
    }

    public function testResolveValidatedIpThrowsForPrivateHost(): void
    {
        $this->expectException(OIDCUrlNotAllowedException::class);
        $this->getValidator()->resolveValidatedIp('http://127.0.0.1/');
    }
}
