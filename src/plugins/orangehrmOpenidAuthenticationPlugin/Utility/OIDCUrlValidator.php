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

use OrangeHRM\Core\Traits\Service\ConfigServiceTrait;

/**
 * Write-time guard for OIDC provider URLs (SSRF hardening).
 *
 * A provider URL is allowed only when its scheme is http/https and every address its host resolves
 * to is a public, routable address. The public/private decision uses PHP's built-in
 * filter_var(FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE), which
 * rejects loopback, RFC1918 private, link-local (incl. the 169.254.169.254 cloud-metadata address)
 * and reserved ranges — no hand-maintained CIDR list. All resolved A/AAAA records are checked.
 *
 * Admins running an OIDC provider on an internal network (e.g. self-hosted Keycloak) can relax the
 * private-address rejection via the `oidc.allow_private_provider_hosts` config (default off); the
 * http/https scheme requirement is always enforced.
 */
class OIDCUrlValidator
{
    use ConfigServiceTrait;

    /**
     * @param string $url
     * @return bool true when the URL is safe to persist (and later fetch server-side)
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

        if ($this->arePrivateHostsAllowed()) {
            return true;
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
            $isPublic = filter_var(
                $ip,
                FILTER_VALIDATE_IP,
                FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
            );
            if ($isPublic === false) {
                return false;
            }
        }

        return true;
    }

    /**
     * @return bool whether provider URLs resolving to private/internal addresses are allowed
     */
    protected function arePrivateHostsAllowed(): bool
    {
        return $this->getConfigService()->isOidcPrivateProviderHostAllowed();
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
