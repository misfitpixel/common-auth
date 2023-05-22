<?php

namespace MisfitPixel\Common\Auth\Repository\Abstraction;


use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use MisfitPixel\Common\Auth\Entity\User;
use MisfitPixel\Common\Model\Repository\Abstraction\BaseRepository;

/**
 * Class BaseUserRepository
 * @package MisfitPixel\Common\Auth\Repository\Abstraction
 */
abstract class BaseUserRepository extends BaseRepository implements UserRepositoryInterface
{
    /**
     * @param string $username
     * @return User|null
     */
    public function findOneByUsername(string $username): ?User
    {
        return $this->findOneBy([
            'username' => $username
        ]);
    }

    /**
     * @param $username
     * @param $password
     * @param $grantType
     * @param ClientEntityInterface $clientEntity
     * @return User|null
     */
    public function getUserEntityByUserCredentials($username, $password, $grantType, ClientEntityInterface $clientEntity): ?User
    {
        $user = $this->findOneByUsername($username);

        if(
            $user === null ||
            !$user->isPassword($password)
        ) {
            return null;
        }

        return $user;
    }
}
