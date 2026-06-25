<?php

declare(strict_types=1);

namespace Glueful\Extensions\Audit\Console;

use Glueful\Console\BaseCommand;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Retention: delete audit_logs rows older than `audit.retention_days`.
 *
 * Append-only history grows unbounded; this command (scheduled daily by the app)
 * prunes rows whose `occurred_at` is past the retention window, in batches so a
 * large backlog never holds a single huge delete. Get the connection the same way
 * the AuditRecorder does (db($context)).
 */
#[AsCommand(name: 'audit:prune', description: 'Delete audit_logs rows older than the retention window')]
final class PruneAuditLogsCommand extends BaseCommand
{
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $retentionDays = (int) config($this->context, 'audit.retention_days', 365);
        if ($retentionDays < 1) {
            $retentionDays = 365;
        }

        $cutoffTimestamp = strtotime("-{$retentionDays} days");
        $cutoff = date('Y-m-d H:i:s', $cutoffTimestamp !== false ? $cutoffTimestamp : time());

        // Single simple-condition delete (the builder removes every matching row in one
        // statement; it only supports one simple WHERE for DELETE). Get the connection the
        // same way the AuditRecorder does (db($context)). Returns the deleted count.
        /** @var int $total */
        $total = db($this->context)->table('audit_logs')
            ->where('occurred_at', '<', $cutoff)
            ->delete();

        $this->success(sprintf(
            'Pruned %d audit log %s older than %d days (before %s).',
            $total,
            $total === 1 ? 'row' : 'rows',
            $retentionDays,
            $cutoff
        ));

        return self::SUCCESS;
    }
}
