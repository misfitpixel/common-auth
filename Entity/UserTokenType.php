<?php

namespace MisfitPixel\Common\Auth\Entity;


use MisfitPixel\Common\Model\Entity\Abstraction\Respondent;

/**
 * Class UserTokenType
 * @package MisfitPixel\Common\Auth\Entity
 */
class UserTokenType
{
    const ACCESS_TOKEN = 1;
    const REFRESH_TOKEN = 2;
    const AUTHORIZATION_CODE = 3;
    const PASSWORD_RESET = 4;

    use Respondent;

    /** @var int|null  */
    protected ?int $id;

    /** @var string */
    protected string $name;

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
    public function getName(): string
    {
        return $this->name;
    }
}
