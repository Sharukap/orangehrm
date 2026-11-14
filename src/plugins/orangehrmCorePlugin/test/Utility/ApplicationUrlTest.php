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

use OrangeHRM\Core\Utility\ApplicationUrl;
use OrangeHRM\Tests\Util\TestCase;

/**
 * @group Core
 * @group Utility
 */
class ApplicationUrlTest extends TestCase
{
    /**
     * @dataProvider validOriginDataProvider
     */
    public function testNormalizeAcceptsOrigin(string $input, string $expected): void
    {
        $this->assertSame($expected, ApplicationUrl::normalize($input));
        $this->assertTrue(ApplicationUrl::isValid($input));
    }

    public function validOriginDataProvider(): array
    {
        return [
            'http host' => ['http://hrm.test', 'http://hrm.test'],
            'https host' => ['https://hrm.example.com', 'https://hrm.example.com'],
            'with port' => ['https://hrm.test:8443', 'https://hrm.test:8443'],
            'trailing slash removed' => ['http://hrm.test/', 'http://hrm.test'],
            'surrounding whitespace trimmed' => ['  http://hrm.test  ', 'http://hrm.test'],
            'scheme and host lower-cased' => ['HTTPS://HRM.Test', 'https://hrm.test'],
            'localhost with port' => ['http://localhost:8080', 'http://localhost:8080'],
            'ipv4' => ['http://192.168.1.10', 'http://192.168.1.10'],
            'ipv6' => ['http://[::1]:8080', 'http://[::1]:8080'],
        ];
    }

    /**
     * @dataProvider invalidOriginDataProvider
     */
    public function testNormalizeRejectsNonOrigin(string $input): void
    {
        $this->assertNull(ApplicationUrl::normalize($input));
        $this->assertFalse(ApplicationUrl::isValid($input));
    }

    public function invalidOriginDataProvider(): array
    {
        return [
            'empty' => [''],
            'no scheme' => ['hrm.test'],
            'protocol relative' => ['//evil.test'],
            'path' => ['http://hrm.test/path'],
            'subfolder path' => ['http://hrm.test/orangehrm/'],
            'query' => ['http://hrm.test/?x=1'],
            'query without slash' => ['http://hrm.test?x=1'],
            'fragment' => ['http://hrm.test/#a'],
            'credentials' => ['http://user:pw@hrm.test'],
            'at sign host spoof' => ['http://hrm.test@evil.test'],
            'javascript scheme' => ['javascript:alert(1)'],
            'ftp scheme' => ['ftp://hrm.test'],
            'html injection' => ['http://hrm.test"><script>alert(1)</script>'],
            'whitespace inside' => ['http://hrm .test'],
            'newline' => ["http://hrm.test\r\nX: y"],
            'port zero' => ['http://hrm.test:0'],
            'port too large' => ['http://hrm.test:65536'],
            'empty port' => ['http://hrm.test:'],
            'backslash' => ['http://hrm.test\\evil.test'],
            'too long' => ['http://' . str_repeat('a', 250) . '.test'],
        ];
    }
}
