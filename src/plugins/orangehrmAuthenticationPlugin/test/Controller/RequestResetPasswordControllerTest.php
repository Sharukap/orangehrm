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

use OrangeHRM\Authentication\Controller\RequestResetPasswordController;
use OrangeHRM\Authentication\Csrf\CsrfTokenManager;
use OrangeHRM\Authentication\Service\ResetPasswordService;
use OrangeHRM\Core\Service\ConfigService;
use OrangeHRM\Entity\User;
use OrangeHRM\Framework\Http\Request;
use OrangeHRM\Framework\Http\RequestStack;
use OrangeHRM\Framework\Services;
use OrangeHRM\Tests\Util\KernelTestCase;

/**
 * @group Authentication
 * @group Controller
 */
class RequestResetPasswordControllerTest extends KernelTestCase
{
    private const BASE = 'http://hrm.test';

    private function handle(?string $applicationUrl, ResetPasswordService $resetPasswordService): string
    {
        $configService = $this->getMockBuilder(ConfigService::class)
            ->onlyMethods(['getApplicationUrl'])
            ->getMock();
        $configService->method('getApplicationUrl')->willReturn($applicationUrl);

        $csrfTokenManager = $this->getMockBuilder(CsrfTokenManager::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['isValid'])
            ->getMock();
        $csrfTokenManager->method('isValid')->willReturn(true);

        $request = Request::create(
            'http://hrm.test/index.php/auth/requestResetPassword',
            'POST',
            ['_token' => 'token', 'username' => 'someone']
        );
        $requestStack = new RequestStack();
        $requestStack->push($request);

        $this->createKernelWithMockServices([
            Services::CONFIG_SERVICE => $configService,
            Services::CSRF_TOKEN_MANAGER => $csrfTokenManager,
            Services::REQUEST_STACK => $requestStack,
        ]);

        $controller = $this->getMockBuilder(RequestResetPasswordController::class)
            ->onlyMethods(['getResetPasswordService'])
            ->getMock();
        $controller->method('getResetPasswordService')->willReturn($resetPasswordService);

        return $controller->handle($request)->getTargetUrl();
    }

    private function getResetPasswordService(?User $user, bool $sent = true): ResetPasswordService
    {
        $service = $this->getMockBuilder(ResetPasswordService::class)
            ->onlyMethods(['searchForUserRecord', 'logPasswordResetRequest'])
            ->getMock();
        $service->method('searchForUserRecord')->willReturn($user);
        $service->method('logPasswordResetRequest')->willReturn($sent);
        return $service;
    }

    public function testExistingAndUnknownUsersGetSameResponseWhenApplicationUrlNotConfigured(): void
    {
        $existing = $this->handle(null, $this->getResetPasswordService(new User(), false));
        $unknown = $this->handle(null, $this->getResetPasswordService(null));

        $this->assertSame($existing, $unknown);
        $this->assertSame(self::BASE . '/auth/requestPasswordResetCode', $existing);
    }

    public function testDoesNotLookUpUserWhenApplicationUrlNotConfigured(): void
    {
        $service = $this->getMockBuilder(ResetPasswordService::class)
            ->onlyMethods(['searchForUserRecord', 'logPasswordResetRequest'])
            ->getMock();
        $service->expects($this->never())->method('searchForUserRecord');
        $service->expects($this->never())->method('logPasswordResetRequest');

        $this->handle(null, $service);
    }

    public function testUnknownUserRedirectsToSuccessWhenConfigured(): void
    {
        $this->assertSame(
            self::BASE . '/auth/sendPasswordReset',
            $this->handle('http://hrm.test', $this->getResetPasswordService(null))
        );
    }

    public function testExistingUserRedirectsToSuccessWhenEmailSent(): void
    {
        $this->assertSame(
            self::BASE . '/auth/sendPasswordReset',
            $this->handle('http://hrm.test', $this->getResetPasswordService(new User(), true))
        );
    }

    public function testExistingUserRedirectsToFailureWhenEmailNotSent(): void
    {
        $this->assertSame(
            self::BASE . '/auth/sendPasswordResetFailure',
            $this->handle('http://hrm.test', $this->getResetPasswordService(new User(), false))
        );
    }
}
