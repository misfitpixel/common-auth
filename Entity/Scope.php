<?php

namespace MisfitPixel\Common\Auth\Entity;


use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\ScopeTrait;
use MisfitPixel\Common\Model\Entity\Abstraction\Respondent;

/**
 * Class Scope
 * @package MisfitPixel\Common\Auth\Entity
 */
class Scope implements ScopeEntityInterface
{
    use Respondent, ScopeTrait;

    /** @var int|null  */
    protected ?int $id;

    /** @var string  */
    protected string $name;

    /** @var string  */
    protected string $identifier;

    /** @var string|null  */
    protected ?string $description;

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

    /**
     * @return string
     */
    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    /**
     * @return string|null
     */
    public function getDescription():? string
    {
        return $this->description;
    }
}
