<?php

namespace MisfitPixel\Common\Auth\Entity;


use League\OAuth2\Server\Entities\UserEntityInterface;
use MisfitPixel\Common\Model\Entity\Abstraction\Dated;
use MisfitPixel\Common\Model\Entity\Abstraction\Descriptive;
use MisfitPixel\Common\Model\Entity\Abstraction\Persistent;
use MisfitPixel\Common\Model\Entity\Abstraction\Respondent;
use MisfitPixel\Common\Model\Entity\Abstraction\Statused;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Class User
 * @package MisfitPixel\Common\Auth\Entity
 */
class User implements UserInterface, PasswordAuthenticatedUserInterface, UserEntityInterface
{
    use Dated, Statused, Descriptive, Persistent, Respondent;

    /** @var int|null  */
    protected ?int $id = null;

    /** @var string */
    protected string $username;

    /** @var string */
    protected string $password;

    /** @var string|null  */
    protected ?string $salt = null;

    /**
     * @return int|null
     */
    public function getId(): ?int
    {
        return $this->id;
    }

    /**
     * @return string
     */
    public function getUsername(): string
    {
        return $this->username;
    }

    /**
     * @param string $username
     * @return $this
     */
    public function setUsername(string $username): self
    {
        $this->username = $username;

        return $this;
    }

    /**
     * @return string
     */
    public function getPassword(): string
    {
        return $this->password;
    }

    /**
     * @param string $plaintextPassword
     * @return $this
     * @throws \Exception
     */
    public function setPassword(string $plaintextPassword): self
    {
        if($this->salt == null) {
            $this->salt = bin2hex(random_bytes(16));
        }

        /** @var \Symfony\Component\PasswordHasher\Hasher\UserPasswordHasher $encoder */
        $encoder = $this->getContainer()->get('security.user_password_hasher');

        $this->password = $encoder->hashPassword($this, $plaintextPassword);

        return $this;
    }

    /**
     * @param string $plaintextPassword
     * @return bool
     */
    public function isPassword(string $plaintextPassword): bool
    {
        /** @var \Symfony\Component\PasswordHasher\Hasher\UserPasswordHasher $encoder */
        $encoder = $this->getContainer()->get('security.user_password_hasher');

        return $encoder->isPasswordValid($this, $plaintextPassword);
    }

    /**
     * @return string
     */
    public function getSalt(): string
    {
        return $this->salt;
    }

    /**
     * @return void
     */
    public function eraseCredentials()
    {
        return;
    }

    public function getRoles(): array
    {
        /**
         * TODO: get roles from database RBAC system.
         * TODO: get roles from scopes?
         */
        return [];
    }

    /**
     * @return string
     */
    public function getIdentifier(): string
    {
        return $this->getUsername();
    }
}
