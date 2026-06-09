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

use OrangeHRM\OpenidAuthentication\Utility\OIDCUrlValidator;
use OrangeHRM\Tests\Util\TestCase;

/**
 * SSRF guard for OIDC provider URLs: scheme allowlist + rejection of any host resolving to a
 * private/reserved/loopback/link-local/metadata/CGNAT address (unless the admin opt-out is on).
 *
 * @group OpenIDAuth
 */
class OIDCUrlValidatorTest extends TestCase
{
    /**
     * Literal IPs (and scheme-only checks) need no DNS resolution; the opt-out is off here.
     *
     * @dataProvider literalUrlProvider
     */
    public function testIsAllowedProviderUrlWithLiterals(string $url, bool $expected): void
    {
        $this->assertSame($expected, $this->validator()->isAllowedProviderUrl($url));
    }

    public function literalUrlProvider(): array
    {
        return [
            'public ipv4 https' => ['https://93.184.216.34/', true],
            'public ipv4 http' => ['http://93.184.216.34:8443/', true],
            'public ipv6' => ['https://[2606:2800:220:1:248:1893:25c8:1946]/', true],
            'ftp scheme' => ['ftp://93.184.216.34/', false],
            'file scheme' => ['file:///etc/passwd', false],
            'gopher scheme' => ['gopher://93.184.216.34/', false],
            'no scheme' => ['93.184.216.34', false],
            'garbage' => ['not a url', false],
            'loopback' => ['http://127.0.0.1/', false],
            'metadata' => ['http://169.254.169.254/latest/meta-data/', false],
            'rfc1918 10' => ['http://10.0.0.1/', false],
            'rfc1918 172' => ['http://172.16.5.4/', false],
            'rfc1918 192' => ['http://192.168.1.1/', false],
            'all zeros' => ['http://0.0.0.0/', false],
            'ipv6 loopback' => ['http://[::1]/', false],
            'ipv6 link local' => ['http://[fe80::1]/', false],
        ];
    }

    public function testHostResolvingOnlyToPublicIsAllowed(): void
    {
        $this->assertTrue(
            $this->validator(['93.184.216.34'])->isAllowedProviderUrl('https://idp.example.com/')
        );
    }

    public function testHostResolvingToAnyPrivateIsRejected(): void
    {
        // DNS-rebinding shape: a mix of public and private records must be rejected.
        $this->assertFalse(
            $this->validator(['93.184.216.34', '10.0.0.5'])->isAllowedProviderUrl('https://rebind.example.com/')
        );
    }

    public function testHostThatDoesNotResolveIsRejected(): void
    {
        $this->assertFalse($this->validator([])->isAllowedProviderUrl('https://nonexistent.example.com/'));
    }

    public function testPrivateHostAllowedWhenOptOutEnabled(): void
    {
        // With the admin opt-out on, an internal IdP host is allowed...
        $this->assertTrue(
            $this->validator(['10.0.0.5'], true)->isAllowedProviderUrl('https://keycloak.internal/')
        );
        // ...but a non-http(s) scheme is still rejected regardless of the opt-out.
        $this->assertFalse(
            $this->validator(['10.0.0.5'], true)->isAllowedProviderUrl('ftp://keycloak.internal/')
        );
    }

    /**
     * Validator with DNS resolution and the config opt-out stubbed, so tests stay offline.
     *
     * @param string[]|null $stubIps null = resolve literally (IP hosts only); array = forced records
     * @param bool $allowPrivate
     * @return OIDCUrlValidator
     */
    private function validator(?array $stubIps = null, bool $allowPrivate = false): OIDCUrlValidator
    {
        return new class ($stubIps, $allowPrivate) extends OIDCUrlValidator {
            /** @var string[]|null */
            private ?array $stubIps;
            private bool $allowPrivate;

            public function __construct(?array $stubIps, bool $allowPrivate)
            {
                $this->stubIps = $stubIps;
                $this->allowPrivate = $allowPrivate;
            }

            protected function arePrivateHostsAllowed(): bool
            {
                return $this->allowPrivate;
            }

            protected function resolveHostToIps(string $host): array
            {
                return $this->stubIps ?? parent::resolveHostToIps($host);
            }
        };
    }
}
