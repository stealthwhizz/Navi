"""Validate actual PostgreSQL DDL/JSONB/upsert semantics without binding a socket.

This supplements, and does not replace, TEST_DATABASE_URL connection tests.
"""

from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def main():
    postgres = shutil.which("postgres")
    if not postgres:
        candidates = sorted(Path("/usr/lib/postgresql").glob("*/bin/postgres"))
        postgres = str(candidates[-1]) if candidates else None
    if not postgres:
        raise SystemExit("PostgreSQL server binaries are required for this check.")
    initdb = str(Path(postgres).with_name("initdb"))
    schema = (Path(__file__).resolve().parents[1] / "navi/schema.sql").read_text()
    with tempfile.TemporaryDirectory(prefix="navi-schema-") as temporary:
        data = str(Path(temporary) / "data")
        init = subprocess.run([initdb,"-D",data,"-A","trust","--no-locale","--encoding=UTF8"],capture_output=True,text=True,timeout=30)
        if init.returncode:
            raise SystemExit(init.stderr)
        checks = """
        BEGIN;
        INSERT INTO cf_scans VALUES ('one','project',now(),now(),'{"summary":{"total":1}}'::jsonb);
        INSERT INTO cf_scans VALUES ('two','project',now(),now(),'{"summary":{"total":1}}'::jsonb);
        INSERT INTO cf_issues VALUES ('project','operation','one','one');
        INSERT INTO cf_issues VALUES ('project','operation','two','two') ON CONFLICT(project,id) DO UPDATE SET last_scan=excluded.last_scan;
        INSERT INTO cf_occurrences VALUES ('one','operation','{"cwe":"CWE-89","evidence":["proof"]}'::jsonb);
        INSERT INTO cf_occurrences VALUES ('two','operation','{"cwe":"CWE-89","evidence":["proof"]}'::jsonb);
        INSERT INTO cf_experiments VALUES ('trial-one','project','2026-10-31T00:00:00Z','{"before":{"outcome":"violation","request":{"status":200}},"after":{"outcome":"blocked","request":{"status":403}},"comparison":{"verified":true}}'::jsonb);
        INSERT INTO cf_experiments VALUES ('trial-two','project','2026-10-31T00:01:00Z','{"before":{"outcome":"permitted"}}'::jsonb);
        INSERT INTO cf_experiments VALUES ('other-trial','other-project',now(),'{}'::jsonb);
        DO $$ BEGIN
          IF (SELECT count(*) FROM cf_schema_version) != 2 THEN RAISE EXCEPTION 'Missing or duplicated schema versions'; END IF;
          IF (SELECT count(*) FROM cf_issues WHERE project='project') != 1 THEN RAISE EXCEPTION 'Duplicate issues'; END IF;
          IF (SELECT count(*) FROM cf_occurrences) != 2 THEN RAISE EXCEPTION 'Missing scan history'; END IF;
          IF (SELECT issue->>'cwe' FROM cf_occurrences WHERE scan_id='one') != 'CWE-89' THEN RAISE EXCEPTION 'JSONB round trip failed'; END IF;
          IF (SELECT first_scan FROM cf_issues WHERE id='operation') != 'one' THEN RAISE EXCEPTION 'First occurrence lost'; END IF;
          IF (SELECT last_scan FROM cf_issues WHERE id='operation') != 'two' THEN RAISE EXCEPTION 'Last occurrence incorrect'; END IF;
          IF (SELECT count(*) FROM cf_experiments WHERE project='project') != 2 THEN RAISE EXCEPTION 'Experiment project isolation failed'; END IF;
          IF (SELECT id FROM cf_experiments WHERE project='project' ORDER BY created DESC LIMIT 1) != 'trial-two' THEN RAISE EXCEPTION 'Experiment history ordering failed'; END IF;
          IF (SELECT evidence #>> '{after,request,status}' FROM cf_experiments WHERE id='trial-one') != '403' THEN RAISE EXCEPTION 'Protected response evidence lost'; END IF;
          IF (SELECT evidence #>> '{comparison,verified}' FROM cf_experiments WHERE id='trial-one') != 'true' THEN RAISE EXCEPTION 'Comparison verdict lost'; END IF;
        END $$;
        ROLLBACK;
        """
        commands = " ".join((schema + schema + checks).splitlines()) + "\n"
        result = subprocess.run([postgres,"--single","-D",data,"postgres"],input=commands,capture_output=True,text=True,timeout=30)
        if result.returncode or re.search(r"(?:ERROR|FATAL|PANIC):",result.stderr):
            raise SystemExit(result.stderr + result.stdout)
        print("PASS: PostgreSQL schema, repeated migrations, JSONB evidence, issue upserts, per-scan history, and scoped access-experiment history.")


if __name__ == "__main__":
    main()
