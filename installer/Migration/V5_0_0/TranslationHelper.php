<?php

namespace OrangeHRM\Installer\Migration\V5_0_0;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Exception;
use Doctrine\DBAL\Query\QueryBuilder;
use OrangeHRM\Core\Traits\ORM\EntityManagerHelperTrait;
use OrangeHRM\Installer\Util\V1\Dto\TransUnit;
use Symfony\Component\Yaml\Yaml;

class TranslationHelper
{
    use EntityManagerHelperTrait;

    protected ?LangStringHelper $langStringHelper = null;

    /**
     * @param string $language
     * @param string $groupName
     * @return void
     */
    public function addTranslations(string $language): void
    {
        $filepath = 'installer/Migration/V5_0_0/translation/' . $language . '.yaml';
        $yml = Yaml::parseFile($filepath);
        $translations = array_shift($yml);
        foreach ($translations as $translation) {
            $sourceObj = new TransUnit($translation['target'], $translation['unitId']);
            $this->saveTranslationRecord($translation['group'], $sourceObj, $language);
        }
    }

    /**
     * @param string $groupName
     * @param TransUnit $source
     * @param string $language
     * @return void
     */
    private function saveTranslationRecord(string $groupName, TransUnit $source, string $language): void
    {
        $groupId = $this->getLangStringHelper()->getGroupId($groupName);
        $langStringId = $this->getLangStringHelper()->getLangStringIdByUnitIdAndGroup($source->getUnitId(), $groupId);
        if ($langStringId == null) {
            var_dump(
                $source->getUnitId(),
                $groupName
            );
            return;
            /*throw new Exception(
                'Cannot add a translation to a non existent lang string: ' .$source->getUnitId()
            );*/
        }
        $langId = $this->getLanguageId($language);
        $existTranslation = $this->getTranslationRecord($langStringId, $langId);
        if ($existTranslation != null) {
            // TODO hanldle customized translations
        } else {
            $insetQuery = $this->createQueryBuilder();
            $insetQuery->insert('ohrm_i18n_translate')
                ->values(
                    [
                        'lang_string_id' => ':langStringId',
                        'language_id' => ':langId',
                        'value' => ':target',
                    ]
                )
                ->setParameter('langStringId', $langStringId)
                ->setParameter('langId', $langId)
                ->setParameter('target', $source->getTarget())
                ->executeQuery();
        }
    }

    /**
     * @return LangStringHelper
     */
    private function getLangStringHelper(): LangStringHelper
    {
        if (is_null($this->langStringHelper)) {
            $this->langStringHelper = new LangStringHelper($this->getConnection());
        }
        return $this->langStringHelper;
    }

    /**
     * @return Connection
     */
    protected function getConnection(): Connection
    {
        return $this->getEntityManager()->getConnection();
    }

    /**
     * @param string $langCode
     * @return int
     * @throws Exception
     */
    private function getLanguageId(string $langCode): int
    {
        $searchQuery = $this->createQueryBuilder();
        $searchQuery->select('language.id')->from('ohrm_i18n_language', 'language')->where('language.code = :langCode')->setParameter('langCode', $langCode);
        return $searchQuery->executeQuery()->fetchOne();
    }

    /**
     * @return QueryBuilder
     */
    protected function createQueryBuilder(): QueryBuilder
    {
        return $this->getEntityManager()->getConnection()->createQueryBuilder();
    }

    /**
     * @param array $langStringId
     * @param int $langId
     * @return string
     * @throws Exception
     */
    private function getTranslationRecord(int $langStringId, int $langId): string
    {
        $searchQuery = $this->createQueryBuilder();
        $searchQuery->select('translate.id')
            ->from('ohrm_i18n_translate', 'translate')
            ->where('translate.language_id = :langCode')
            ->andWhere('translate.lang_string_id = :langStringId')
            ->setParameter('langCode', $langId)
            ->setParameter('langStringId', $langStringId);
        return $searchQuery->executeQuery()->fetchOne();
    }
}
