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

use OrangeHRM\Framework\Http\Request;
use OrangeHRM\Framework\Http\Response;
use Symfony\Component\HttpFoundation\Exception\SuspiciousOperationException;

/**
 * Optional hardening: when lib/confs/Conf.php defines getTrustedHosts() returning host regex patterns,
 * requests whose Host header does not match get rejected with HTTP 400.
 */
final class TrustedHosts
{
    private function __construct()
    {
    }

    /**
     * @param object $conf instance of the installation's Conf class
     * @return string[] the patterns that were applied (empty = host checking disabled)
     */
    public static function configure(object $conf): array
    {
        if (!method_exists($conf, 'getTrustedHosts')) {
            return [];
        }
        $patterns = array_values(
            array_filter(
                (array)$conf->getTrustedHosts(),
                static fn ($pattern): bool => is_string($pattern) && $pattern !== ''
            )
        );
        if ($patterns !== []) {
            Request::setTrustedHosts($patterns);
        }
        return $patterns;
    }

    /**
     * Must be checked before the kernel handles the request: the router context reads the host
     * outside the kernel's exception handling.
     */
    public static function isRequestHostTrusted(Request $request): bool
    {
        try {
            $request->getHost();
            return true;
        } catch (SuspiciousOperationException $e) {
            return false;
        }
    }

    public static function getUntrustedHostResponse(): Response
    {
        return new Response('Bad Request', Response::HTTP_BAD_REQUEST, ['Content-Type' => 'text/plain']);
    }
}
