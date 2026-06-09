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

namespace OrangeHRM\OpenidAuthentication\Utility;

use OrangeHRM\OpenidAuthentication\OpenID\SafeHttpClientFactory;
use Symfony\Component\HttpFoundation\IpUtils;

/**
 * Write-time guard for OIDC provider URLs: rejects a URL whose scheme is not http/https or whose
 * host resolves to any blocked (private/reserved/loopback/link-local/metadata/CGNAT) address, so an
 * internal URL is never persisted as a provider. Classification reuses Symfony's IpUtils against
 * the same subnet list the runtime egress guard enforces (SafeHttpClientFactory::BLOCKED_SUBNETS);
 * the runtime guard remains the authoritative defence at fetch time.
 */
class OIDCUrlValidator
{
    /**
     * @param string $url
     * @return bool true when the URL is safe to persist and fetch server-side
     */
    public function isAllowedProviderUrl(string $url): bool
    {
        $scheme = strtolower((string)parse_url($url, PHP_URL_SCHEME));
        if (!in_array($scheme, ['http', 'https'], true)) {
            return false;
        }

        $host = (string)parse_url($url, PHP_URL_HOST);
        if ($host === '') {
            return false;
        }

        // Strip brackets from IPv6 literals (e.g. [::1]).
        if (strlen($host) > 1 && $host[0] === '[' && substr($host, -1) === ']') {
            $host = substr($host, 1, -1);
        }

        $ips = $this->resolveHostToIps($host);
        if (empty($ips)) {
            return false;
        }

        foreach ($ips as $ip) {
            if (IpUtils::checkIp($ip, SafeHttpClientFactory::BLOCKED_SUBNETS)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Resolve a host (or accept an IP literal) to all of its A/AAAA records. Isolated for testability.
     *
     * @param string $host
     * @return string[]
     */
    protected function resolveHostToIps(string $host): array
    {
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return [$host];
        }

        $ips = [];
        $records = @dns_get_record($host, DNS_A | DNS_AAAA);
        if (is_array($records)) {
            foreach ($records as $record) {
                if (!empty($record['ip'])) {
                    $ips[] = $record['ip'];
                }
                if (!empty($record['ipv6'])) {
                    $ips[] = $record['ipv6'];
                }
            }
        }

        if (empty($ips)) {
            $byName = @gethostbynamel($host);
            if (is_array($byName)) {
                $ips = $byName;
            }
        }

        return array_values(array_unique($ips));
    }
}
