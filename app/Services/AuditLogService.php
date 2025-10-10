<?php


namespace App\Services;


use Illuminate\Support\Str;


class AuditLogService
{
protected string $dir; // audit folder
protected ?string $key; // HMAC key (optional)
protected string $nameFormat; // daily file name format


public function __construct()
{
$this->dir = config('audit.dir');
$this->key = config('audit.hmacKey');
$this->nameFormat = config('audit.filenameFormat', 'Y-m-d');
if (!is_dir($this->dir)) {
@mkdir($this->dir, 0700, true);
}
}


/** Append an audit line and return the written array. */
public function write(array $data): array
{
$now = now()->toImmutable();
$file = $this->filePath($now);


$prevHash = $this->lastHash($file); // hash chain link


// Normalize payload
$payload = [
'id' => (string) Str::uuid(),
'at' => $now->toRfc3339String(),
'action' => (string) ($data['action'] ?? 'unknown'),
'outcome' => (string) ($data['outcome'] ?? 'unknown'),
'adminSam' => $data['adminSam'] ?? null,
'targetSam' => $data['targetSam'] ?? null,
'srcIp' => $data['srcIp'] ?? request()->ip(),
'details' => $data['details'] ?? null,
'prevHash' => $prevHash, // previous line's rowHash (or null for first)
];


// Compute row hash on the JSON of the payload (without rowHash/hmac)
$material = json_encode($payload, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
$rowHash = hash('sha256', $material);


// Optional HMAC of (material|rowHash)
$hmac = $this->key ? hash_hmac('sha256', $material.'|'.$rowHash, $this->key) : null;


$record = $payload + ['rowHash' => $rowHash, 'hmac' => $hmac];


// Append atomically (exclusive lock)
$fp = fopen($file, 'ab');
if ($fp === false) {
throw new \RuntimeException("Cannot open audit file: $file");
}
if (flock($fp, LOCK_EX)) {
fwrite($fp, json_encode($record, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE).PHP_EOL);
fflush($fp);
flock($fp, LOCK_UN);
}
fclose($fp);


return $record;
}


// ----- helpers -----
protected function filePath(?\DateTimeInterface $date = null): string
{
$date ??= now();
$name = $date->format($this->nameFormat).'.jsonl';
return rtrim($this->dir, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.$name;
}


protected function lastHash(string $file): ?string
{
if (!is_file($file) || filesize($file) === 0) return null;
$fp = fopen($file, 'rb'); $pos = -1; $buffer = '';
do {
fseek($fp, $pos, SEEK_END);
$ch = fgetc($fp);
if ($ch === "\n" && $buffer !== '') break; // stop at previous newline
$buffer = $ch.$buffer;
$pos--;
} while (ftell($fp) > 1);
}
