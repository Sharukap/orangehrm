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

namespace OrangeHRM\OpenidAuthentication\Service;

use OrangeHRM\Admin\Dao\UserDao;
use OrangeHRM\Admin\Dto\UserSearchFilterParams;
use OrangeHRM\Authentication\Dto\UserCredential;
use OrangeHRM\Authentication\Exception\AuthenticationException;
use OrangeHRM\Authentication\Service\AuthenticationService;
use OrangeHRM\Authentication\Traits\Service\AuthenticationServiceTrait;
use OrangeHRM\Core\Traits\Auth\AuthUserTrait;
use OrangeHRM\Core\Traits\CacheTrait;
use OrangeHRM\Core\Utility\EncryptionHelperTrait;
use OrangeHRM\Entity\AuthProviderExtraDetails;
use OrangeHRM\Entity\EmployeeTerminationRecord;
use OrangeHRM\Entity\OpenIdProvider;
use OrangeHRM\Entity\OpenIdUserIdentity;
use OrangeHRM\Entity\User;
use OrangeHRM\Framework\Routing\UrlGenerator;
use OrangeHRM\Framework\Services;
use OrangeHRM\OpenidAuthentication\Dao\AuthProviderDao;
use OrangeHRM\OpenidAuthentication\Dto\ProviderSearchFilterParams;
use OrangeHRM\OpenidAuthentication\OpenID\OpenIDConnectClient;
use OrangeHRM\OpenidAuthentication\Traits\Service\SocialMediaAuthenticationServiceTrait;

class SocialMediaAuthenticationService
{
    use SocialMediaAuthenticationServiceTrait;
    use AuthenticationServiceTrait;
    use EncryptionHelperTrait;
    use AuthUserTrait;
    use CacheTrait;

    private AuthenticationService $authenticationService;
    private AuthProviderDao $authProviderDao;
    private UserDao $userDao;

    public const SCOPE = 'email';

    /**
     * Cross-request cache of provider OIDC discovery documents.
     */
    private const WELL_KNOWN_CACHE_PREFIX = 'oidc.well_known.';
    private const WELL_KNOWN_CACHE_TTL = 86400;

    /**
     * @return AuthProviderDao
     */
    public function getAuthProviderDao(): AuthProviderDao
    {
        return $this->authProviderDao ??= new AuthProviderDao();
    }

    /**
     * @return UserDao
     */
    public function getUserDao(): UserDao
    {
        return $this->userDao ??= new UserDao();
    }

    /**
     * @param AuthProviderExtraDetails $provider
     * @param string $scope
     * @param string $redirectUrl
     *
     * @return OpenIDConnectClient
     */
    public function initiateAuthentication(AuthProviderExtraDetails $provider, string $scope, string $redirectUrl): OpenIDConnectClient
    {
        $providerUrl = $provider->getOpenIdProvider()->getProviderUrl();

        $oidcClient = new OpenIDConnectClient(
            $providerUrl,
            $provider->getClientId(),
            self::encryptionEnabled()
                ? self::getCryptographer()->decrypt($provider->getClientSecret())
                : $provider->getClientSecret(),
        );

        $oidcClient->addScope([$scope]);
        $oidcClient->setRedirectURL($redirectUrl);

        // If the discovery document is cached, inject it so this (public) login path performs no
        // live discovery fetch. When absent, discovery still runs but is guarded + IP-checked.
        $cachedConfig = $this->getCachedWellKnownConfig($providerUrl);
        if (is_array($cachedConfig)) {
            $oidcClient->providerConfigParam($cachedConfig);
        }

        return $oidcClient;
    }

    /**
     * Store the discovery document fetched by the client (if any) for reuse on later logins.
     *
     * @param string $providerUrl
     * @param OpenIDConnectClient $oidcClient
     */
    public function cacheDiscoveredConfig(string $providerUrl, OpenIDConnectClient $oidcClient): void
    {
        $config = $oidcClient->getCapturedWellKnownConfig();
        if ($config === null) {
            return;
        }
        try {
            $cacheItem = $this->getCache()->getItem($this->getWellKnownCacheKey($providerUrl));
            $cacheItem->set($config);
            $cacheItem->expiresAfter(self::WELL_KNOWN_CACHE_TTL);
            $this->getCache()->save($cacheItem);
        } catch (\Throwable $e) {
            // Cache is an optimisation only; never let a cache failure disrupt authentication.
        }
    }

    /**
     * @param string $providerUrl
     * @return array|null
     */
    private function getCachedWellKnownConfig(string $providerUrl): ?array
    {
        try {
            $cacheItem = $this->getCache()->getItem($this->getWellKnownCacheKey($providerUrl));
            if (!$cacheItem->isHit()) {
                return null;
            }
            $config = json_decode((string)$cacheItem->get(), true);
            return is_array($config) ? $config : null;
        } catch (\Throwable $e) {
            // Cache unavailable — fall back to (guarded) live discovery.
            return null;
        }
    }

    /**
     * @param string $providerUrl
     * @return string
     */
    private function getWellKnownCacheKey(string $providerUrl): string
    {
        return self::WELL_KNOWN_CACHE_PREFIX . md5($providerUrl);
    }

    /**
     * @return string
     */
    public function getRedirectURL(): string
    {
        /** @var UrlGenerator $urlGenerator */
        $urlGenerator = $this->getContainer()->get(Services::URL_GENERATOR);
        return $urlGenerator->generate('auth_oidc_login_redirect', [], UrlGenerator::ABSOLUTE_URL);
    }

    /**
     * @return string
     */
    public function getScope(): string
    {
        return self::SCOPE;
    }

    /**
     * @param UserCredential $userCredential
     * @return User[]
     */
    private function getSystemUsers(UserCredential $userCredential): array
    {
        $userSearchFilterParams = new UserSearchFilterParams();
        $userSearchFilterParams->setUsername($userCredential->getUsername());

        return $this->getUserDao()->searchSystemUsers($userSearchFilterParams);
    }

    /**
     * @param UserCredential $userCredentials
     *
     * @return User
     * @throws AuthenticationException
     */
    public function getUserForAuthenticate(UserCredential $userCredentials): User
    {
        $users = $this->getSystemUsers($userCredentials);
        if (empty($users)) {
            throw AuthenticationException::noUserFound();
        }

        if (sizeof($users) > 1) {
            throw AuthenticationException::multipleUserReturned();
        }

        $user = $users[0];

        if (!$user instanceof User || $user->isDeleted()) {
            throw AuthenticationException::invalidCredentials();
        } else {
            if (!$user->getStatus()) {
                throw AuthenticationException::userDisabled();
            } elseif ($user->getEmpNumber() === null) {
                throw AuthenticationException::employeeNotAssigned();
            } elseif ($user->getEmployee()->getEmployeeTerminationRecord() instanceof EmployeeTerminationRecord) {
                throw AuthenticationException::employeeTerminated();
            }
            return $user;
        }
    }

    /**
     * @param User $user
     * @param OpenIdProvider $provider
     *
     * @return OpenIdUserIdentity
     */
    public function setOIDCUserIdentity(User $user, OpenIdProvider $provider): OpenIdUserIdentity
    {
        $openIdUserIdentity = new OpenIdUserIdentity();
        $openIdUserIdentity->setUser($user);
        $openIdUserIdentity->setOpenIdProvider($provider);

        return $this->getAuthProviderDao()->saveUserIdentity($openIdUserIdentity);
    }

    /**
     * @param User $user
     *
     * @return bool
     * @throws AuthenticationException
     */
    public function handleOIDCAuthentication(User $user): bool
    {
        return $this->getAuthenticationService()->setCredentialsForUser($user);
    }

    /**
     * @return bool
     */
    public function isSocialMediaAuthEnable(): bool
    {
        $providerSearchFilterParams = new ProviderSearchFilterParams();
        $providerSearchFilterParams->setName(null);
        $providerSearchFilterParams->setStatus(true);

        $count = $this->getAuthProviderDao()->getAuthProviderCount($providerSearchFilterParams);
        return $count > 0;
    }
}
