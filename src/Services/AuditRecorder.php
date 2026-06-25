<?php

declare(strict_types=1);

namespace Glueful\Extensions\Audit\Services;

use Glueful\Bootstrap\ApplicationContext;
use Glueful\Helpers\Utils;
use Glueful\Extensions\Audit\Support\AuditEntry;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * Write path for the audit trail.
 *
 * The single method the subscribers call. Three load-bearing properties:
 *
 *  1. Recursion guard — writes via a RAW insert through the framework query builder
 *     ({@see db()}->table('audit_logs')->insert(...)), NEVER BaseRepository::create(),
 *     so the write itself dispatches no EntityCreatedEvent and can never audit itself.
 *  2. Redaction — `changes`/`context` are redacted by field-name pattern (from
 *     config('audit.redact_fields'), `*` wildcards supported) before being written;
 *     matched values become "[redacted]", recursively through nested arrays.
 *  3. Best-effort / non-throwing — a failed audit write must never break the audited
 *     operation: the insert is wrapped in try/catch, logged, and swallowed.
 */
final class AuditRecorder
{
    private const REDACTED = '[redacted]';

    public function __construct(private readonly ApplicationContext $context)
    {
    }

    public function record(AuditEntry $entry): void
    {
        try {
            $patterns = $this->redactPatterns();

            $changes = $entry->changes !== null ? $this->redact($entry->changes, $patterns) : null;
            $context = $entry->context !== null ? $this->redact($entry->context, $patterns) : null;

            $now = date('Y-m-d H:i:s');

            // RAW insert through the query builder — NOT BaseRepository::create() — so
            // this write dispatches no entity event (recursion guard).
            db($this->context)->table('audit_logs')->insert([
                'uuid' => Utils::generateNanoID(12),
                'occurred_at' => $this->formatOccurredAt($entry->occurredAt),
                'actor_uuid' => $entry->actorUuid,
                'actor_label' => $entry->actorLabel,
                'action' => $entry->action,
                'category' => $entry->category,
                'target_type' => $entry->targetType,
                'target_uuid' => $entry->targetUuid,
                'target_label' => $entry->targetLabel,
                'changes' => $changes !== null ? json_encode($changes) : null,
                'context' => $context !== null ? json_encode($context) : null,
                'created_at' => $now,
            ]);
        } catch (Throwable $e) {
            // An audit failure must never break the audited operation.
            $this->logFailure($e);
        }
    }

    /**
     * Field-name patterns to redact (config-driven; `*` wildcards supported).
     *
     * @return list<string>
     */
    private function redactPatterns(): array
    {
        $configured = config($this->context, 'audit.redact_fields', []);
        if (!is_array($configured)) {
            return [];
        }

        $patterns = [];
        foreach ($configured as $pattern) {
            if (is_string($pattern) && $pattern !== '') {
                $patterns[] = strtolower($pattern);
            }
        }

        return $patterns;
    }

    /**
     * Recursively replace values whose keys match a redaction pattern.
     *
     * @param array<mixed> $data
     * @param list<string> $patterns
     * @return array<mixed>
     */
    private function redact(array $data, array $patterns): array
    {
        $result = [];
        foreach ($data as $key => $value) {
            if (is_string($key) && $this->isSensitiveKey($key, $patterns)) {
                $result[$key] = self::REDACTED;
                continue;
            }

            $result[$key] = is_array($value) ? $this->redact($value, $patterns) : $value;
        }

        return $result;
    }

    /**
     * @param list<string> $patterns
     */
    private function isSensitiveKey(string $key, array $patterns): bool
    {
        $normalized = strtolower($key);
        foreach ($patterns as $pattern) {
            if (str_contains($pattern, '*')) {
                if (fnmatch($pattern, $normalized)) {
                    return true;
                }
            } elseif ($pattern === $normalized) {
                return true;
            }
        }

        return false;
    }

    private function formatOccurredAt(string|float $occurredAt): string
    {
        if (is_float($occurredAt) || is_numeric($occurredAt)) {
            return date('Y-m-d H:i:s', (int) $occurredAt);
        }

        return $occurredAt;
    }

    private function logFailure(Throwable $e): void
    {
        $message = 'Audit write failed: ' . $e->getMessage();

        try {
            if ($this->context->hasContainer()) {
                $container = $this->context->getContainer();
                if ($container->has(LoggerInterface::class)) {
                    $logger = $container->get(LoggerInterface::class);
                    if ($logger instanceof LoggerInterface) {
                        $logger->error($message, ['exception' => $e]);
                        return;
                    }
                }
            }
        } catch (Throwable) {
            // Fall through to error_log below.
        }

        error_log($message);
    }
}
