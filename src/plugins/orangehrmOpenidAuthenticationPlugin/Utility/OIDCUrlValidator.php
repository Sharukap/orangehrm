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

use OrangeHRM\OpenidAuthentication\Exception\OIDCUrlNotAllowedException;

/**
 * Validates OIDC provider URLs against SSRF abuse.
 *
 * A URL is allowed only when its scheme is http/https and every IP address its host resolves to
 * is a routable public address — rejecting loopback, RFC1918, link-local (incl. the cloud metadata
 * service 169.254.169.254), CGNAT and IPv6 special ranges. All A/AAAA records are checked, so a
 * host that resolves to a mix of public and private addresses is rejected (DNS-rebinding defence).
 */
class OIDCUrlValidator
{
    /**
     * CIDR ranges that FILTER_FLAG_NO_PRIV_RANGE / NO_RES_RANGE do not already cover.
     * Currently just CGNAT (100.64.0.0/10).
     */
    private const EXTRA_BLOCKED_V4_CIDRS = ['100.64.0.0/10'];

    /**
     * @param string $url
     * @return bool true when the URL is safe to fetch server-side
     */
    public function isAllowedProviderUrl(string $url): bool
    {
        try {
            $this->resolveValidatedIp($url);
            return true;
        } catch (OIDCUrlNotAllowedException $e) {
            return false;
        }
    }

    /**
     * Validate the URL and return the public IP its host resolves to (used to pin the HTTP client).
     *
     * @param string $url
     * @return string a routable public IP literal
     * @throws OIDCUrlNotAllowedException
     */
    public function resolveValidatedIp(string $url): string
    {
        $scheme = strtolower((string)parse_url($url, PHP_URL_SCHEME));
        if (!in_array($scheme, ['http', 'https'], true)) {
            throw new OIDCUrlNotAllowedException('Provider URL must use http or https');
        }

        $host = (string)parse_url($url, PHP_URL_HOST);
        if ($host === '') {
            throw new OIDCUrlNotAllowedException('Provider URL host is missing or malformed');
        }

        // Strip brackets from IPv6 literals (e.g. [::1]).
        if (strlen($host) > 1 && $host[0] === '[' && substr($host, -1) === ']') {
            $host = substr($host, 1, -1);
        }

        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            $ips = [$host];
        } else {
            $ips = $this->resolveHostToIps($host);
        }

        if (empty($ips)) {
            throw new OIDCUrlNotAllowedException('Provider URL host could not be resolved');
        }

        $firstPublicIp = null;
        foreach ($ips as $ip) {
            if ($this->isBlockedIp($ip)) {
                throw new OIDCUrlNotAllowedException('Provider URL resolves to a disallowed (private/reserved) address');
            }
            $firstPublicIp ??= $ip;
        }

        return $firstPublicIp;
    }

    /**
     * @param string $ip
     * @return bool
     */
    protected function isBlockedIp(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return true;
        }

        // Rejects private (10/8, 172.16/12, 192.168/16, fc00::/7) and reserved ranges
        // (incl. 127/8, 169.254/16 link-local + cloud metadata, 0.0.0.0/8, ::1, fe80::/10, ...).
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return true;
        }

        foreach (self::EXTRA_BLOCKED_V4_CIDRS as $cidr) {
            if ($this->ipv4InCidr($ip, $cidr)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param string $ip
     * @param string $cidr
     * @return bool
     */
    private function ipv4InCidr(string $ip, string $cidr): bool
    {
        $ipLong = ip2long($ip);
        if ($ipLong === false) {
            return false; // not IPv4
        }
        [$subnet, $bits] = explode('/', $cidr);
        $subnetLong = ip2long($subnet);
        $mask = $bits === '0' ? 0 : (-1 << (32 - (int)$bits)) & 0xFFFFFFFF;
        return ($ipLong & $mask) === ($subnetLong & $mask);
    }

    /**
     * Resolve a hostname to all of its A and AAAA records. Isolated for testability.
     *
     * @param string $host
     * @return string[]
     */
    protected function resolveHostToIps(string $host): array
    {
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
