<?php


namespace App\Console\Commands;


use Illuminate\Console\Command;


class AuditVerify extends Command
{
protected $signature = 'audit:verify {date? : YYYY-MM-DD}';
protected $description = 'Verify hash chain (and HMAC) for a specific day or all days';


public function handle(): int
{
$dir = config('audit.dir');
$key = config('audit.hmacKey');
$dates = [];


if ($d = $this->argument('date')) {
$dates = [$d];
} else {
foreach (glob($dir.DIRECTORY_SEPARATOR.'*.jsonl') as $f) {
$dates[] = basename($f, '.jsonl');
}
sort($dates);
}


$ok = true;
foreach ($dates as $date) {
$file = $dir.DIRECTORY_SEPARATOR.$date.'.jsonl';
if (!is_file($file)) { $this->warn("Missing: $file"); $ok = false; continue; }
$prev = null; $lineNo = 0; $fh = fopen($file, 'rb');
while (($line = fgets($fh)) !== false) {
$lineNo++;
$row = json_decode($line, true);
if (!$row) { $this->error("$date#$lineNo invalid JSON"); $ok = false; break; }


$copy = $row; unset($copy['rowHash'], $copy['hmac']);
$material = json_encode($copy, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
$calc = hash('sha256', $material);
if (!hash_equals($calc, $row['rowHash'] ?? '')) { $this->error("$date#$lineNo rowHash mismatch"); $ok = false; break; }


if (($row['prevHash'] ?? null) !== $prev) {
if (!($prev === null && ($row['prevHash'] ?? null) === null)) {
$this->error("$date#$lineNo chain break"); $ok = false; break; }
}


if ($key) {
$h = hash_hmac('sha256', $material.'|'.$row['rowHash'], $key);
if (!hash_equals($h, $row['hmac'] ?? '')) { $this->error("$date#$lineNo HMAC mismatch"); $ok = false; break; }
}


$prev = $row['rowHash'];
}
fclose($fh);
if ($ok) $this->info("$date OK");
}
return $ok ? self::SUCCESS : self::FAILURE;
}
}
