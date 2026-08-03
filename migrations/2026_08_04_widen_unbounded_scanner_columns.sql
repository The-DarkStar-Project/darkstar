-- Widen the columns that receive unbounded scanner output.
-- Apply to each tenant schema; db_helper also applies these on demand.
-- Re-running these statements is a no-op.
--
-- 1. asmevents.source_module
-- BBOT's CSV column "Source Module" carries event.module_sequence, which is a
-- discovery chain ("httpx->excavate->httpx"), not a single module name. It has
-- no upper bound, so VARCHAR(50) made MariaDB reject the ASM batch insert with
-- error 1406 (22001) and fail the whole scan after all scanning had completed.
--
-- 2. vulnerability.affected_item
-- Nine scanners (dalfox, nuclei, retire.js, trufflehog, ZAP, Nikto, Wapiti,
-- bbot, the asteroid modules) write a full URL here, and sanitize_string()
-- HTML-escapes it first, which inflates the length further.
--
-- 3. vulnerability.access
-- Holds a json.dumps() of the access object from the CIRCL CVE API, whose
-- shape is not under our control.

ALTER TABLE asmevents MODIFY COLUMN source_module VARCHAR(255) DEFAULT NULL;
ALTER TABLE vulnerability MODIFY COLUMN affected_item TEXT;
ALTER TABLE vulnerability MODIFY COLUMN access TEXT;
