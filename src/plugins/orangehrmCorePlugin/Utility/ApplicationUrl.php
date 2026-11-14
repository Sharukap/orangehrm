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

namespace OrangeHRM\Core\Utility;

/**
 * The Application URL is the trusted public origin of this instance (scheme://host[:port]).
 * It is used instead of the request Host header when building absolute links sent out of band
 * (e.g. password reset emails).
 */
final class ApplicationUrl
{
    public const MAX_LENGTH = 255;
    private const ALLOWED_SCHEMES = ['http', 'https'];

    private function __construct()
    {
    }

    /**
     * Returns the normalized origin (lower-case scheme and host, no trailing slash),
     * or null when the value is not a plain http(s) origin.
     */
    public static function normalize(string $url): ?string
    {
        $url = trim($url);
        if ($url === '' || strlen($url) > self::MAX_LENGTH) {
            return null;
        }
        // Reject whitespace, control characters, backslashes and characters that can break out of markup
        if (preg_match('/[\s\x00-\x1F\x7F\\\\"\'<>`]/', $url)) {
            return null;
        }
        if (substr($url, -1) === '/') {
            $url = substr($url, 0, -1);
        }
        if (!preg_match('#^([a-zA-Z][a-zA-Z0-9+.-]*)://([^/?\#@]+)$#', $url, $matches)) {
            return null;
        }
        $scheme = strtolower($matches[1]);
        if (!in_array($scheme, self::ALLOWED_SCHEMES, true)) {
            return null;
        }

        $authority = strtolower($matches[2]);
        if (!preg_match('#^(\[[0-9a-f:.]+\]|[^:\[\]]+)(?::(\d{1,5}))?$#', $authority, $parts)) {
            return null;
        }
        $host = $parts[1];
        $port = $parts[2] ?? null;

        if ($host[0] === '[') {
            if (filter_var(substr($host, 1, -1), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
                return null;
            }
        } elseif (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false
            && filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false
        ) {
            return null;
        }

        if ($port !== null) {
            $portNumber = (int)$port;
            if ($portNumber < 1 || $portNumber > 65535) {
                return null;
            }
            return "$scheme://$host:$portNumber";
        }
        return "$scheme://$host";
    }

    public static function isValid(string $url): bool
    {
        return self::normalize($url) !== null;
    }
}
