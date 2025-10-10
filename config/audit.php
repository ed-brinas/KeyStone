<?php
return [
// Where daily .jsonl files are stored (absolute path is resolved at runtime)
'dir' => env('AUDIT_DIR', storage_path('app/audit')),


// If null, HMAC signing is disabled. If set, each line is signed with SHA‑256 HMAC.
'hmacKey' => env('AUDIT_HMAC_KEY', null),


// Each day has one file like 2025-10-10.jsonl
'filenameFormat' => 'Y-m-d',
];
