#!/usr/bin/env bash
# NEXUS PRO — Backup de datos
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="$ROOT/.backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

echo "Backup → $BACKUP_DIR"
cp -r "$ROOT/data/"*.db    "$BACKUP_DIR/" 2>/dev/null || true
cp -r "$ROOT/nexus_api/"*.db "$BACKUP_DIR/" 2>/dev/null || true
cp    "$ROOT/.env"           "$BACKUP_DIR/env.bak" 2>/dev/null || true
cp -r "$ROOT/data/reports"   "$BACKUP_DIR/reports" 2>/dev/null || true

ARCHIVE="$ROOT/.backups/nexus_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
tar -czf "$ARCHIVE" -C "$BACKUP_DIR" . 2>/dev/null

SIZE=$(du -sh "$ARCHIVE" | cut -f1)
echo "✓ Backup completado: $ARCHIVE ($SIZE)"
ls -lh "$ROOT/.backups/"*.tar.gz 2>/dev/null | tail -5
