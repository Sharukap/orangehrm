<?php
/**
 * OrangeHRM is a comprehensive Human Resource Management (HRM) System that captures
 * all the essential functionalities required for any enterprise.
 * Copyright (C) 2006 OrangeHRM Inc., http://www.orangehrm.com
 *
 * OrangeHRM is free software; you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * OrangeHRM is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program;
 * if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301, USA
 */

namespace OrangeHRM\Performance\Dto;

use OrangeHRM\Core\Dto\FilterParams;

class EmployeeTrackerSearchFilterParams extends FilterParams
{
    public const ALLOWED_SORT_FIELDS = [
        'tracker.trackerName',
        'employee.lastName',
        'tracker.addedDate',
        'tracker.modifiedDate'
    ];

    public const INCLUDE_EMPLOYEES_ONLY_CURRENT = 'onlyCurrent';
    public const INCLUDE_EMPLOYEES_ONLY_PAST = 'onlyPast';
    public const INCLUDE_EMPLOYEES_CURRENT_AND_PAST = 'currentAndPast';

    public const INCLUDE_EMPLOYEES = [
        self::INCLUDE_EMPLOYEES_ONLY_CURRENT,
        self::INCLUDE_EMPLOYEES_ONLY_PAST,
        self::INCLUDE_EMPLOYEES_CURRENT_AND_PAST,
    ];

    private ?array $empNumbers = null;
    private ?string $nameOrId = null;
    private string $includeEmployees = self::INCLUDE_EMPLOYEES_ONLY_CURRENT;

    public function __construct()
    {
        $this->setSortField('tracker.modifiedDate');
        $this->setSortOrder('DESC');
    }

    /**
     * @return array|null
     */
    public function getEmpNumbers(): ?array
    {
        return $this->empNumbers;
    }

    /**
     * @param array|null $empNumbers
     */
    public function setEmpNumbers(?array $empNumbers): void
    {
        $this->empNumbers = $empNumbers;
    }

    /**
     * @return string
     */
    public function getIncludeEmployees(): string
    {
        return $this->includeEmployees;
    }

    /**
     * @param string|null $includeEmployees
     */
    public function setIncludeEmployees(?string $includeEmployees): void
    {
        $this->includeEmployees = $includeEmployees;
    }

    /**
     * @return string|null
     */
    public function getNameOrId(): ?string
    {
        return $this->nameOrId;
    }

    /**
     * @param string|null $nameOrId
     */
    public function setNameOrId(?string $nameOrId): void
    {
        $this->nameOrId = $nameOrId;
    }
}
