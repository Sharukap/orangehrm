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

namespace OrangeHRM\Tests\Claim\Dao;

use Doctrine\ORM\TransactionRequiredException;
use OrangeHRM\Claim\Dao\ClaimDao;
use OrangeHRM\Claim\Dto\ClaimRequestSearchFilterParams;
use OrangeHRM\Config\Config;
use OrangeHRM\Entity\ClaimRequest;
use OrangeHRM\ORM\Doctrine;
use OrangeHRM\Tests\Util\KernelTestCase;
use OrangeHRM\Tests\Util\TestDataService;

/**
 * @group Claim
 * @group Dao
 */
class ClaimDaoRequestTest extends KernelTestCase
{
    private ClaimDao $claimDao;

    protected function setUp(): void
    {
        $this->claimDao = new ClaimDao();
        $requestFixture = Config::get(Config::PLUGINS_DIR) . '/orangehrmClaimPlugin/test/fixtures/MyClaimRequestAPITest.yaml';
        TestDataService::populate($requestFixture);
    }

    public function testGetClaimRequestById(): void
    {
        $result = $this->claimDao->getClaimRequestById(1);
        $this->assertEquals(1, $result->getId());
    }

    public function testGetClaimRequestList(): void
    {
        $claimRequestSearchFilterParams = new ClaimRequestSearchFilterParams();
        $claimRequestSearchFilterParams->setEmpNumbers([4]);
        $claimRequests = $this->claimDao->getClaimRequestList($claimRequestSearchFilterParams);
        $this->assertEquals(4, count($claimRequests));
    }

    /**
     * The locked read must take a pessimistic write lock: Doctrine raises
     * TransactionRequiredException when a pessimistic-write query is issued without an
     * active transaction, which confirms the read is locked rather than a plain findOneBy().
     */
    public function testGetClaimRequestByIdForUpdateRequiresTransactionForLock(): void
    {
        $this->expectException(TransactionRequiredException::class);
        $this->claimDao->getClaimRequestByIdForUpdate(1);
    }

    public function testGetClaimRequestByIdForUpdateReturnsRequestWithinTransaction(): void
    {
        $connection = Doctrine::getEntityManager()->getConnection();
        $connection->beginTransaction();
        try {
            $result = $this->claimDao->getClaimRequestByIdForUpdate(1);
            $this->assertInstanceOf(ClaimRequest::class, $result);
            $this->assertEquals(1, $result->getId());
            $this->assertNull($this->claimDao->getClaimRequestByIdForUpdate(99999));
        } finally {
            $connection->rollBack();
        }
    }
}
