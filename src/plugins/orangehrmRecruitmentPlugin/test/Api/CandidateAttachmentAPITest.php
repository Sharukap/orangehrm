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

namespace OrangeHRM\Tests\Recruitment\Api;

use OrangeHRM\Core\Api\V2\Validator\ParamRule;
use OrangeHRM\Core\Api\V2\Validator\ParamRuleCollection;
use OrangeHRM\Core\Api\V2\Validator\Rules;
use OrangeHRM\Entity\Candidate;
use OrangeHRM\Recruitment\Api\CandidateAttachmentAPI;
use OrangeHRM\Tests\Util\EndpointTestCase;

/**
 * @group Recruitment
 * @group APIv2
 */
class CandidateAttachmentAPITest extends EndpointTestCase
{
    /**
     * GET /api/v2/recruitment/candidate/{candidateId}/attachment must enforce per-record
     * access scope so a HiringManager/Interviewer cannot read attachment metadata of
     * candidates outside their accessible vacancies.
     */
    public function testGetValidationRuleForGetOneEnforcesCandidateAccessScope(): void
    {
        $api = new CandidateAttachmentAPI($this->getRequest());
        $this->assertCandidateIdGatedByAccessibleEntityRule($api->getValidationRuleForGetOne());
    }

    /**
     * PUT /api/v2/recruitment/candidate/{candidateId}/attachment (which can permanently
     * delete a resume via currentAttachment=deleteCurrent) must enforce per-record access scope.
     */
    public function testGetValidationRuleForUpdateEnforcesCandidateAccessScope(): void
    {
        $api = new CandidateAttachmentAPI($this->getRequest());
        $this->assertCandidateIdGatedByAccessibleEntityRule($api->getValidationRuleForUpdate());
    }

    /**
     * POST /api/v2/recruitment/candidate/attachments must enforce per-record access scope too,
     * so an attachment cannot be created against a candidate the user cannot access.
     */
    public function testGetValidationRuleForCreateEnforcesCandidateAccessScope(): void
    {
        $api = new CandidateAttachmentAPI($this->getRequest());
        $this->assertCandidateIdGatedByAccessibleEntityRule($api->getValidationRuleForCreate());
    }

    private function assertCandidateIdGatedByAccessibleEntityRule(ParamRuleCollection $collection): void
    {
        $candidateIdRule = null;
        foreach ($collection->getParamValidations() as $paramRule) {
            if ($paramRule instanceof ParamRule
                && $paramRule->getParamKey() === CandidateAttachmentAPI::PARAMETER_CANDIDATE_ID) {
                $candidateIdRule = $paramRule;
                break;
            }
        }

        $this->assertNotNull(
            $candidateIdRule,
            'Expected a validation rule for the candidateId parameter'
        );

        $hasAccessibleEntityRule = false;
        foreach ($candidateIdRule->getRules() as $rule) {
            if ($rule->getRuleClass() === Rules::IN_ACCESSIBLE_ENTITY_ID
                && in_array(Candidate::class, $rule->getRuleConstructorParams(), true)) {
                $hasAccessibleEntityRule = true;
                break;
            }
        }

        $this->assertTrue(
            $hasAccessibleEntityRule,
            'candidateId must be guarded by an IN_ACCESSIBLE_ENTITY_ID rule against Candidate::class '
            . 'to prevent cross-candidate access'
        );
    }
}
