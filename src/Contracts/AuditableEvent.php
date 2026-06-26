<?php

declare(strict_types=1);

namespace Glueful\Extensions\Audit\Contracts;

/**
 * Makes any dispatched event self-auditing.
 *
 * The audit extension subscribes to this interface, so ANY event implementing it that is
 * dispatched through the framework event dispatcher is recorded automatically — the app
 * needs no subscriber and no reference to the recorder. The subscriber fills in the actor
 * and request context (ip / user_agent / request_id / event_id); the event supplies the
 * semantic fields below.
 *
 * Use the {@see AuditableEventDefaults} trait to implement only auditAction() and
 * auditCategory():
 *
 *     final class InvoicePaid extends BaseEvent implements AuditableEvent
 *     {
 *         use AuditableEventDefaults;
 *
 *         public function __construct(public readonly string $invoiceUuid)
 *         {
 *             parent::__construct();
 *         }
 *
 *         public function auditAction(): string { return 'paid'; }
 *         public function auditCategory(): string { return 'billing'; }
 *         public function auditTarget(): array { return ['type' => 'invoice', 'uuid' => $this->invoiceUuid]; }
 *     }
 */
interface AuditableEvent
{
    /** The verb, e.g. "created", "published", "exported". */
    public function auditAction(): string;

    /** The bucket, e.g. "content", "data", "billing" — drives the category column and filter. */
    public function auditCategory(): string;

    /**
     * What was acted on. Any omitted key is treated as null.
     *
     * @return array{type?:string|null,uuid?:string|null,label?:string|null}
     */
    public function auditTarget(): array;

    /**
     * Field-level changes for an update (`{field: {from?, to}}`), or null for non-updates.
     *
     * @return array<string,array<string,mixed>>|null
     */
    public function auditChanges(): ?array;

    /**
     * Extra domain context, merged on top of the resolved request context
     * (ip / user_agent / request_id / event_id). Sensitive keys are redacted by the recorder.
     *
     * @return array<string,mixed>
     */
    public function auditMetadata(): array;

    /**
     * The actor that caused the event, as a fallback for when there is no HTTP request to resolve
     * one from (after-commit dispatch, CLI/queue). Return an empty array to defer entirely to
     * request resolution. When a request DOES resolve an actor, it wins (it carries the display
     * label); this only fills in otherwise-`system` rows.
     *
     * @return array{uuid?:string|null,label?:string|null}
     */
    public function auditActor(): array;
}
