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

import {translate as translatorFactory} from '@/core/plugins/i18n/translate';

const translate = translatorFactory();

const HOSTNAME =
  /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i;
const IPV6 = /^\[[0-9a-f:.]+\]$/i;

/**
 * Client-side mirror of OrangeHRM\Core\Utility\ApplicationUrl: accepts only an
 * http(s) origin (scheme://host[:port]) with an optional trailing slash.
 * The server re-validates; this only gives early feedback.
 */
export const validApplicationUrl = function (value: string): boolean | string {
  if (!value) return true;
  const message = translate('admin.expected_application_url_format');
  const url = value.trim().replace(/\/$/, '');
  if (url.length > 255 || /[\s"'<>`\\]/.test(url)) return message;

  const match = /^(https?):\/\/([^/?#@]+)$/i.exec(url);
  if (!match) return message;

  const authority = /^(\[[0-9a-f:.]+\]|[^:[\]]+)(?::(\d{1,5}))?$/i.exec(
    match[2],
  );
  if (!authority) return message;

  const [, host, port] = authority;
  if (!IPV6.test(host) && !HOSTNAME.test(host)) return message;
  if (port !== undefined && (Number(port) < 1 || Number(port) > 65535)) {
    return message;
  }
  return true;
};
