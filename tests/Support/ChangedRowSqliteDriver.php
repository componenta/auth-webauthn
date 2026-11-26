<?php

declare(strict_types=1);

namespace Componenta\Auth\WebAuthn\Tests\Support;

use Cycle\Database\Driver\SQLite\SQLiteDriver;

/**
 * Models changed-row counts for this fixture's single-row UPDATE statements.
 * The database executes real SQL; snapshots include every persisted column.
 * This does not emulate MySQL isolation or its other engine-specific behavior.
 */
final class ChangedRowSqliteDriver extends SQLiteDriver
{
    #[\Override]
    public function execute(string $query, array $parameters = []): int
    {
        if (preg_match('/\A\s*UPDATE\s/i', $query) !== 1) {
            return parent::execute($query, $parameters);
        }

        $before = $this->snapshot();
        $matchedRows = parent::execute($query, $parameters);

        if ($matchedRows > 1) {
            throw new \LogicException(
                'Changed-row fixture supports single-row updates only.',
            );
        }

        return $before === $this->snapshot() ? 0 : $matchedRows;
    }

    /** @return array<string, array<array-key, mixed>> */
    private function snapshot(): array
    {
        $tables = $this->query(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
            . " AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )->fetchAll();
        $snapshot = [];

        foreach ($tables as $table) {
            if (!is_array($table) || !is_string($table['name'] ?? null)) {
                throw new \UnexpectedValueException('Invalid fixture table.');
            }

            $name = $table['name'];
            $quoted = '"' . str_replace('"', '""', $name) . '"';
            $snapshot[$name] = $this->query(
                'SELECT * FROM ' . $quoted . ' ORDER BY rowid',
            )->fetchAll();
        }

        return $snapshot;
    }
}
