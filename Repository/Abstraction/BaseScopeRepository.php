<?php

namespace MisfitPixel\Common\Auth\Repository\Abstraction;


use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use MisfitPixel\Common\Auth\Entity\Scope;
use MisfitPixel\Common\Model\Repository\Abstraction\BaseRepository;

/**
 * Class BaseScopeRepository
 * @package MisfitPixel\Common\Auth\Repository\Abstraction
 */
abstract class BaseScopeRepository extends BaseRepository implements ScopeRepositoryInterface
{
    /**
     * @param string $identifier
     * @return Scope|null
     */
    public function findOneByIdentifier(string $identifier): ?Scope
    {
        return $this->findOneBy([
            'identifier' => $identifier
        ]);
    }

    /**
     * @param $identifier
     * @return Scope|null
     */
    public function getScopeEntityByIdentifier($identifier): ?Scope
    {
        return $this->findOneByIdentifier($identifier);
    }
}
