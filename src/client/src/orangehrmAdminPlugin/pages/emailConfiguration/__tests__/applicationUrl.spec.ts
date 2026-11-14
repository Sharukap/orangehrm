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

import {validApplicationUrl} from '../applicationUrl';

jest.mock('@/core/plugins/i18n/translate', () => {
  return {
    translate: () => (langString: string) =>
      langString === 'admin.expected_application_url_format'
        ? 'Expected format: https://hrm.example.com'
        : langString,
  };
});

describe('orangehrmAdminPlugin/emailConfiguration/applicationUrl::validApplicationUrl', () => {
  test.each([
    'http://hrm.test',
    'https://hrm.example.com',
    'https://hrm.test:8443',
    'http://hrm.test/',
    'http://localhost:8080',
    'http://192.168.1.10',
    'http://[::1]:8080',
    '',
  ])('accepts %p', (value) => {
    expect(validApplicationUrl(value)).toBe(true);
  });

  test.each([
    'hrm.test',
    '//evil.test',
    'http://hrm.test/path',
    'http://hrm.test/?x=1',
    'http://hrm.test?x=1',
    'http://hrm.test/#a',
    'http://user:pw@hrm.test',
    'http://hrm.test@evil.test',
    'javascript:alert(1)',
    'ftp://hrm.test',
    'http://hrm.test"><script>alert(1)</script>',
    'http://hrm .test',
    'http://hrm.test:0',
    'http://hrm.test:65536',
    'http://hrm.test\\evil.test',
  ])('rejects %p with a message', (value) => {
    expect(validApplicationUrl(value)).toBe(
      'Expected format: https://hrm.example.com',
    );
  });
});
