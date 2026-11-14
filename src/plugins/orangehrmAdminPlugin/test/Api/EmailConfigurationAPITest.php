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

namespace OrangeHRM\Tests\Admin\Api;

use OrangeHRM\Admin\Api\EmailConfigurationAPI;
use OrangeHRM\Core\Service\ConfigService;
use OrangeHRM\Entity\Config;
use OrangeHRM\Entity\EmailConfiguration;
use OrangeHRM\Core\Api\V2\RequestParams;
use OrangeHRM\Framework\Services;
use OrangeHRM\Tests\Util\EndpointIntegrationTestCase;
use OrangeHRM\Tests\Util\Integration\TestCaseParams;
use OrangeHRM\Tests\Util\TestDataService;

/**
 * @group Admin
 * @group APIv2
 */
class EmailConfigurationAPITest extends EndpointIntegrationTestCase
{
    public function setUp(): void
    {
        TestDataService::truncateSpecificTables([EmailConfiguration::class]);
        $this->populateFixtures('EmailConfigurationAPITest.yml');
        $this->removeApplicationUrl();
    }

    private function removeApplicationUrl(): void
    {
        $this->getEntityManager()->createQueryBuilder()
            ->delete(Config::class, 'config')
            ->where('config.name = :name')
            ->setParameter('name', ConfigService::KEY_INSTANCE_APPLICATION_URL)
            ->getQuery()
            ->execute();
    }

    private function createKernelForTestCase(TestCaseParams $testCaseParams): void
    {
        $this->createKernelWithMockServices([
            Services::AUTH_USER => $this->getMockAuthUser($testCaseParams),
            Services::CONFIG_SERVICE => new ConfigService(),
        ]);
    }

    /**
     * @dataProvider dataProviderForTestGetOne
     */
    public function testGetOne(TestCaseParams $testCaseParams): void
    {
        $this->createKernelForTestCase($testCaseParams);
        $api = $this->getApiEndpointMock(EmailConfigurationAPI::class, $testCaseParams);
        $this->assertValidTestCase($api, 'getOne', $testCaseParams);
    }

    public function dataProviderForTestGetOne(): array
    {
        return $this->getTestCases('EmailConfigurationAPITestCases.yml', 'GetOne');
    }

    /**
     * @dataProvider dataProviderForTestUpdate
     */
    public function testUpdate(TestCaseParams $testCaseParams): void
    {
        $this->createKernelForTestCase($testCaseParams);
        $api = $this->getApiEndpointMock(EmailConfigurationAPI::class, $testCaseParams);
        $this->assertValidTestCase($api, 'update', $testCaseParams);
    }

    public function dataProviderForTestUpdate(): array
    {
        return $this->getTestCases('EmailConfigurationAPITestCases.yml', 'Update');
    }

    /**
     * @dataProvider dataProviderForTestUpdateWithEmptyConfiguration
     */
    public function testUpdateWithEmptyConfiguration(TestCaseParams $testCaseParams): void
    {
        TestDataService::truncateSpecificTables([EmailConfiguration::class]);
        $this->createKernelForTestCase($testCaseParams);
        $api = $this->getApiEndpointMock(EmailConfigurationAPI::class, $testCaseParams);
        $this->assertValidTestCase($api, 'update', $testCaseParams);
    }

    public function dataProviderForTestUpdateWithEmptyConfiguration(): array
    {
        return $this->getTestCases('EmailConfigurationAPITestCases.yml', 'UpdateWithEmptyConfiguration');
    }

    public function testGetOneReturnsConfiguredApplicationUrl(): void
    {
        $this->createKernelWithMockServices([Services::CONFIG_SERVICE => new ConfigService()]);
        (new ConfigService())->setApplicationUrl('https://hrm.example.com');
        $this->getEntityManager()->flush();

        $result = (new EmailConfigurationAPI($this->getRequest()))->getOne();

        $this->assertSame('https://hrm.example.com', $result->getMeta()->get('applicationUrl'));
    }

    public function testUpdatePersistsApplicationUrl(): void
    {
        $this->createKernelWithMockServices([Services::CONFIG_SERVICE => new ConfigService()]);
        $api = $this->getApiEndpointMockBuilder(EmailConfigurationAPI::class, [
            RequestParams::PARAM_TYPE_BODY => [
                'mailType' => 'sendmail',
                'sentAs' => 'test@orangehrm.com',
                'applicationUrl' => 'https://hrm.example.com/',
            ],
        ])->onlyMethods([])->getMock();
        $api->update();

        $this->getEntityManager()->clear();
        $this->assertSame('https://hrm.example.com', (new ConfigService())->getApplicationUrl());
    }

    public function testUpdateWithoutApplicationUrlKeepsStoredValue(): void
    {
        $this->createKernelWithMockServices([Services::CONFIG_SERVICE => new ConfigService()]);
        (new ConfigService())->setApplicationUrl('https://hrm.example.com');
        $this->getEntityManager()->flush();

        $api = $this->getApiEndpointMockBuilder(EmailConfigurationAPI::class, [
            RequestParams::PARAM_TYPE_BODY => ['mailType' => 'sendmail', 'sentAs' => 'test@orangehrm.com'],
        ])->onlyMethods([])->getMock();
        $result = $api->update();

        $this->assertSame('https://hrm.example.com', $result->getMeta()->get('applicationUrl'));
    }

    public function testDelete(): void
    {
        $api = new EmailConfigurationAPI($this->getRequest());
        $this->expectNotImplementedException();
        $api->delete();
    }

    public function testGetValidationRuleForDelete(): void
    {
        $api = new EmailConfigurationAPI($this->getRequest());
        $this->expectNotImplementedException();
        $api->getValidationRuleForDelete();
    }
}
