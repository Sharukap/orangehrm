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

namespace OrangeHRM\Tests\Core\Security;

use OrangeHRM\Config\Config;
use OrangeHRM\Tests\Util\TestCase;

/**
 * Guards the document-root Apache hardening rules.
 *
 * Regression cover for OPOS-2: the root `.htaccess` denied `*.yml` but not
 * `*.yaml`, leaving `installer/cli_install_config.yaml` (which holds plaintext
 * DB credentials post-install) fetchable by direct URL on Apache deployments.
 *
 * @group Core
 * @group Security
 */
class HtaccessSecurityTest extends TestCase
{
    private string $htaccessContents;

    protected function setUp(): void
    {
        $htaccessPath = Config::get(Config::BASE_DIR) . '/.htaccess';
        $this->assertFileExists($htaccessPath, 'Document-root .htaccess is missing');
        $this->htaccessContents = file_get_contents($htaccessPath);
    }

    /**
     * Sensitive YAML credential files must be denied by the root .htaccess.
     */
    public function testYamlFilesAreDenied(): void
    {
        $this->assertTrue(
            $this->isDeniedByHtaccess('cli_install_config.yaml'),
            'installer/cli_install_config.yaml must be blocked by the root .htaccess (OPOS-2)'
        );
        $this->assertTrue(
            $this->isDeniedByHtaccess('anything.yaml'),
            '.yaml files must be blocked by the root .htaccess'
        );
    }

    /**
     * Existing `.yml` coverage must not regress.
     */
    public function testYmlFilesRemainDenied(): void
    {
        $this->assertTrue(
            $this->isDeniedByHtaccess('config.yml'),
            '.yml files must remain blocked by the root .htaccess'
        );
    }

    /**
     * Sanity check: regular application entry points must stay reachable, so
     * the assertions above are meaningful and not "everything is denied".
     */
    public function testRegularFilesAreNotDenied(): void
    {
        $this->assertFalse(
            $this->isDeniedByHtaccess('index.php'),
            'index.php must remain web-accessible'
        );
    }

    /**
     * Mirrors how Apache evaluates the deny rules in this .htaccess: every
     * `<Files glob>` block is matched with fnmatch and every `<FilesMatch regex>`
     * block with PCRE. Only blocks that actually deny access are considered.
     */
    private function isDeniedByHtaccess(string $fileName): bool
    {
        // <Files PATTERN> ... </Files> (glob match)
        if (preg_match_all('#<Files\s+([^>~]+?)\s*>(.*?)</Files>#is', $this->htaccessContents, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $match) {
                if ($this->blockDenies($match[2]) && fnmatch(trim($match[1]), $fileName)) {
                    return true;
                }
            }
        }

        // <FilesMatch "REGEX"> ... </FilesMatch> (PCRE match)
        if (preg_match_all('#<FilesMatch\s+"(.*?)"\s*>(.*?)</FilesMatch>#is', $this->htaccessContents, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $match) {
                if ($this->blockDenies($match[2]) && preg_match('#' . $match[1] . '#', $fileName)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * A directive block denies access if it carries an (uncommented) deny rule
     * in either the Apache 2.2 or 2.4 syntax.
     */
    private function blockDenies(string $blockBody): bool
    {
        foreach (explode("\n", $blockBody) as $line) {
            $line = trim($line);
            if ($line === '' || (isset($line[0]) && $line[0] === '#')) {
                continue;
            }
            if (stripos($line, 'deny from all') !== false || stripos($line, 'Require all denied') !== false) {
                return true;
            }
        }
        return false;
    }
}
