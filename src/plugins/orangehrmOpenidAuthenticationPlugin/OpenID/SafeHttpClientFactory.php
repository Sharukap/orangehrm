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

use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\HttpClient\NoPrivateNetworkHttpClient;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Builds the HTTP client used for every outbound OIDC request (discovery, token, userinfo).
 *
 * The client is wrapped in Symfony's NoPrivateNetworkHttpClient, which resolves the target host
 * and rejects the request before connecting if the address falls in a blocked subnet, re-checks
 * the IP cURL actually connected to (closing the DNS-rebinding window), and re-checks every
 * redirect hop. This is the single point where the SSRF egress policy is defined.
 */
final class SafeHttpClientFactory
{
    /**
     * Subnets that outbound OIDC requests are refused to. This is Symfony's standard
     * private/reserved set (see NoPrivateNetworkHttpClient::PRIVATE_SUBNETS) plus CGNAT
     * (100.64.0.0/10), which the standard set omits. Passing an explicit list replaces the
     * library default, so the full set is reproduced here.
     */
    public const BLOCKED_SUBNETS = [
        '127.0.0.0/8',
        '10.0.0.0/8',
        '192.168.0.0/16',
        '172.16.0.0/12',
        '169.254.0.0/16',
        '100.64.0.0/10',
        '0.0.0.0/8',
        '240.0.0.0/4',
        '::1/128',
        'fc00::/7',
        'fe80::/10',
        '::ffff:0:0/96',
        '::/128',
        '::/96',
        '2002::/16',
        '2001::/32',
        '64:ff9b::/96',
        '64:ff9b:1::/48',
    ];

    private function __construct()
    {
    }

    /**
     * @return HttpClientInterface an SSRF-guarded client; redirects are not followed.
     */
    public static function create(): HttpClientInterface
    {
        return new NoPrivateNetworkHttpClient(
            HttpClient::create(['max_redirects' => 0]),
            self::BLOCKED_SUBNETS
        );
    }
}
