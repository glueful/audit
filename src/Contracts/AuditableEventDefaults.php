<?php

declare(strict_types=1);

namespace Glueful\Extensions\Audit\Contracts;

/**
 * Sensible defaults for {@see AuditableEvent}: no target, no field changes, no extra metadata.
 *
 * Pull this into an event so it only has to define the two required verbs —
 * `auditAction()` and `auditCategory()` — and override the rest as needed.
 */
trait AuditableEventDefaults
{
    /** @return array{type?:string|null,uuid?:string|null,label?:string|null} */
    public function auditTarget(): array
    {
        return [];
    }

    /** @return array<string,array<string,mixed>>|null */
    public function auditChanges(): ?array
    {
        return null;
    }

    /** @return array<string,mixed> */
    public function auditMetadata(): array
    {
        return [];
    }

    /** @return array{uuid?:string|null,label?:string|null} */
    public function auditActor(): array
    {
        return [];
    }
}
