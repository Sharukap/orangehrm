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

namespace OrangeHRM\Tests\Core\Utility;

use OrangeHRM\Core\Utility\TrustedHosts;
use OrangeHRM\Framework\Http\Request;
use OrangeHRM\Tests\Util\TestCase;
use Symfony\Component\HttpFoundation\Exception\SuspiciousOperationException;

/**
 * @group Core
 * @group Utility
 */
class TrustedHostsTest extends TestCase
{
    protected function tearDown(): void
    {
        Request::setTrustedHosts([]);
    }

    private function getRequestWithHost(string $host): Request
    {
        return Request::create('http://' . $host . '/web/index.php/auth/login');
    }

    public function testConfFromBeforeUpgradeWithoutMethodIsIgnored(): void
    {
        $this->assertSame([], TrustedHosts::configure(new class () {
        }));
        $this->assertSame('evil.test', $this->getRequestWithHost('evil.test')->getHost());
    }

    public function testEmptyListDisablesHostChecking(): void
    {
        $conf = new class () {
            public function getTrustedHosts(): array
            {
                return [];
            }
        };
        $this->assertSame([], TrustedHosts::configure($conf));
        $this->assertSame('evil.test', $this->getRequestWithHost('evil.test')->getHost());
    }

    public function testConfiguredHostsAreEnforced(): void
    {
        $conf = new class () {
            public function getTrustedHosts(): array
            {
                return ['^hrm\.test$', '^localhost$'];
            }
        };
        $this->assertSame(['^hrm\.test$', '^localhost$'], TrustedHosts::configure($conf));

        $this->assertSame('hrm.test', $this->getRequestWithHost('hrm.test')->getHost());
        $this->assertSame('localhost', $this->getRequestWithHost('localhost:8080')->getHost());

        $this->expectException(SuspiciousOperationException::class);
        $this->getRequestWithHost('evil.test')->getHost();
    }

    public function testNonStringEntriesAreIgnored(): void
    {
        $conf = new class () {
            public function getTrustedHosts(): array
            {
                return ['^hrm\.test$', '', null, 123];
            }
        };
        $this->assertSame(['^hrm\.test$'], TrustedHosts::configure($conf));
    }

    public function testIsRequestHostTrusted(): void
    {
        $this->assertTrue(TrustedHosts::isRequestHostTrusted($this->getRequestWithHost('evil.test')));

        Request::setTrustedHosts(['^hrm\.test$']);
        $this->assertTrue(TrustedHosts::isRequestHostTrusted($this->getRequestWithHost('hrm.test')));
        $this->assertFalse(TrustedHosts::isRequestHostTrusted($this->getRequestWithHost('evil.test')));
    }

    public function testGetUntrustedHostResponse(): void
    {
        $response = TrustedHosts::getUntrustedHostResponse();
        $this->assertSame(400, $response->getStatusCode());
        $this->assertStringNotContainsString('/', $response->getContent());
    }
}
