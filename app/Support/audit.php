<?php


use App\Services\AuditLogService;


if (! function_exists('audit')) {
    /** Quick helper: appends a log line using the container service. */
    function audit(array $data): void
    {
        app(AuditLogService::class)->write($data);
    }
}
