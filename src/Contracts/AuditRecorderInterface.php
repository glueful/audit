<?php

declare(strict_types=1);

namespace Glueful\Extensions\Audit\Contracts;

use Glueful\Extensions\Audit\Support\AuditEntry;

/**
 * Write seam for the audit trail.
 *
 * Apps and sibling extensions can type-hint this (instead of the concrete
 * {@see \Glueful\Extensions\Audit\Services\AuditRecorder}) to record their own
 * {@see AuditEntry} rows — e.g. from a subscriber on their own domain events. The
 * concrete recorder is bound to this id, so `app($context, AuditRecorderInterface::class)`
 * resolves it. For the zero-boilerplate path, implement {@see AuditableEvent} instead.
 */
interface AuditRecorderInterface
{
    /** Persist one normalized audit row. Best-effort — never throws. */
    public function record(AuditEntry $entry): void;
}
