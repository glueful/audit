<?php

declare(strict_types=1);

namespace Glueful\Extensions\Audit\Database\Migrations;

use Glueful\Database\Migrations\MigrationInterface;
use Glueful\Database\Schema\Interfaces\SchemaBuilderInterface;

/**
 * Create the append-only audit_logs table.
 *
 * One normalized shape ("actor X did action Y to target Z at time T") that every
 * source fills. No foreign keys — actor_uuid/target_uuid are soft references to
 * rows that live in other packages (mirrors how auth_sessions indexes user_uuid).
 */
final class CreateAuditLogsTable implements MigrationInterface
{
    public function up(SchemaBuilderInterface $schema): void
    {
        if ($schema->hasTable('audit_logs')) {
            return;
        }

        $schema->createTable('audit_logs', function ($table): void {
            $table->bigInteger('id')->primary()->autoIncrement();
            $table->string('uuid', 12);
            $table->timestamp('occurred_at');
            $table->string('actor_uuid', 12)->nullable();
            $table->string('actor_label', 255)->nullable();
            $table->string('action', 32);
            $table->string('category', 24);
            $table->string('target_type', 64)->nullable();
            $table->string('target_uuid', 64)->nullable();
            $table->string('target_label', 255)->nullable();
            $table->json('changes')->nullable();
            $table->json('context')->nullable();
            $table->timestamp('created_at')->nullable();
            $table->unique('uuid');
            $table->index('occurred_at');
            $table->index(['actor_uuid', 'occurred_at'], 'idx_audit_actor');
            $table->index(['target_type', 'target_uuid', 'occurred_at'], 'idx_audit_target');
            $table->index(['category', 'occurred_at'], 'idx_audit_category');
        });
    }

    public function down(SchemaBuilderInterface $schema): void
    {
        $schema->dropTableIfExists('audit_logs');
    }

    public function getDescription(): string
    {
        return 'Create the append-only audit_logs table with actor/target/category indexes.';
    }
}
