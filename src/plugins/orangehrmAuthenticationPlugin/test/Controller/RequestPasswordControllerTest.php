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

namespace OrangeHRM\Tests\Authentication\Controller;

use OrangeHRM\Authentication\Controller\RequestPasswordController;
use OrangeHRM\Authentication\Csrf\CsrfTokenManager;
use OrangeHRM\Core\Service\ConfigService;
use OrangeHRM\Core\Service\EmailService;
use OrangeHRM\Core\Vue\Prop;
use OrangeHRM\Framework\Http\Request;
use OrangeHRM\Framework\Services;
use OrangeHRM\Tests\Util\KernelTestCase;
use OrangeHRM\Tests\Util\Mock\ArrayCsrfTokenStorage;

/**
 * @group Authentication
 * @group Controller
 */
class RequestPasswordControllerTest extends KernelTestCase
{
    private function getController(bool $isEmailConfigSet, ?string $applicationUrl): RequestPasswordController
    {
        $configService = $this->getMockBuilder(ConfigService::class)
            ->onlyMethods(['getApplicationUrl'])
            ->getMock();
        $configService->method('getApplicationUrl')->willReturn($applicationUrl);
        $this->createKernelWithMockServices([Services::CONFIG_SERVICE => $configService]);
        $this->getContainer()->register(Services::CSRF_TOKEN_STORAGE, ArrayCsrfTokenStorage::class);
        $this->getContainer()->register(Services::CSRF_TOKEN_MANAGER, CsrfTokenManager::class);

        $emailService = $this->getMockBuilder(EmailService::class)
            ->onlyMethods(['isConfigSet'])
            ->getMock();
        $emailService->method('isConfigSet')->willReturn($isEmailConfigSet);

        $controller = $this->getMockBuilder(RequestPasswordController::class)
            ->onlyMethods(['getEmailService'])
            ->getMock();
        $controller->method('getEmailService')->willReturn($emailService);
        return $controller;
    }

    /**
     * @return array<string, Prop>
     */
    private function getPropsByName(RequestPasswordController $controller): array
    {
        $props = [];
        foreach ($controller->getComponent()->getProps() as $prop) {
            $props[$prop->getName()] = $prop;
        }
        return $props;
    }

    public function testShowsResetFormWhenEmailAndApplicationUrlConfigured(): void
    {
        $controller = $this->getController(true, 'http://hrm.test');
        $controller->preRender(new Request());

        $this->assertSame('request-reset-password', $controller->getComponent()->getName());
        $this->assertArrayHasKey('token', $this->getPropsByName($controller));
    }

    public function testShowsWarningWhenApplicationUrlNotConfigured(): void
    {
        $controller = $this->getController(true, null);
        $controller->preRender(new Request());

        $this->assertSame('email-configuration-warning', $controller->getComponent()->getName());
        $props = $this->getPropsByName($controller);
        $this->assertArrayHasKey('application-url-missing', $props);
        $this->assertTrue($props['application-url-missing']->getRawValue());
        $this->assertArrayNotHasKey('token', $props);
    }

    public function testShowsEmailWarningWhenEmailNotConfigured(): void
    {
        $controller = $this->getController(false, 'http://hrm.test');
        $controller->preRender(new Request());

        $this->assertSame('email-configuration-warning', $controller->getComponent()->getName());
        $props = $this->getPropsByName($controller);
        $this->assertFalse($props['application-url-missing']->getRawValue());
    }
}
