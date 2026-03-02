<?php
declare(strict_types=1);

/*
  Quick suspicious file scanner (CLI)
  Usage:
    php quick_scan.php /path/to/scan --exclude=/proc --exclude=/sys --exclude=/dev --out=report.json

  Notes:
    - Signature based. False positive হতে পারে।
    - Large files এ পুরোটা না পড়ে head+tail পড়ে দ্রুত স্ক্যান করে।
*/

set_time_limit(0);

function usage(): void {
    $msg = "Usage:\n"
         . "  php quick_scan.php <root_path> [--exclude=/path] [--max-bytes=524288] [--max-size=10485760] [--out=report.json]\n"
         . "Example:\n"
         . "  php quick_scan.php /var/www --exclude=/proc --exclude=/sys --exclude=/dev --exclude=/var/lib/docker --out=report.json\n";
    fwrite(STDERR, $msg);
}

function normPath(string $p): string {
    $rp = realpath($p);
    return $rp !== false ? rtrim($rp, DIRECTORY_SEPARATOR) : rtrim($p, DIRECTORY_SEPARATOR);
}

function isExcluded(string $path, array $excludePrefixes): bool {
    $path = normPath($path);
    foreach ($excludePrefixes as $ex) {
        $ex = normPath($ex);
        if ($ex !== '' && str_starts_with($path, $ex)) return true;
    }
    return false;
}

function readHeadTail(string $file, int $maxBytes): ?string {
    $size = @filesize($file);
    if ($size === false) return null;

    $fh = @fopen($file, 'rb');
    if ($fh === false) return null;

    $data = '';
    if ($size <= $maxBytes) {
        $data = (string)@stream_get_contents($fh);
        fclose($fh);
        return $data;
    }

    $half = intdiv($maxBytes, 2);

    $head = (string)@fread($fh, $half);
    @fseek($fh, max(0, $size - $half));
    $tail = (string)@fread($fh, $half);

    fclose($fh);

    return $head . "\n...\n" . $tail;
}

function scanContent(string $content, array $patterns): array {
    $hits = [];

    foreach ($patterns as $name => $rx) {
        if (@preg_match($rx, $content) === 1) {
            $hits[] = $name;
        }
    }

    // Long base64 blob check
    if (@preg_match('/(?:[A-Za-z0-9+\/]{200,}={0,2})/', $content) === 1) {
        $hits[] = 'long_base64_blob';
    }

    return array_values(array_unique($hits));
}

function main(array $argv): int {
    if (count($argv) < 2) {
        usage();
        return 2;
    }

    $root = $argv[1];
    $rootReal = realpath($root);
    if ($rootReal === false || !is_dir($rootReal)) {
        fwrite(STDERR, "Invalid root path: {$root}\n");
        return 2;
    }

    $opts = getopt("", ["exclude::", "max-bytes::", "max-size::", "out::"]);
    $exclude = [];
    if (isset($opts["exclude"])) {
        if (is_array($opts["exclude"])) $exclude = $opts["exclude"];
        else $exclude = [$opts["exclude"]];
    }

    $maxBytes = isset($opts["max-bytes"]) ? (int)$opts["max-bytes"] : 512 * 1024;   // 512KB
    $maxSize  = isset($opts["max-size"])  ? (int)$opts["max-size"]  : 10 * 1024 * 1024; // 10MB
    $outFile  = isset($opts["out"]) ? (string)$opts["out"] : "";

    // Extensions to scan
    $exts = [
        "php" => true, "phtml" => true, "php5" => true, "php7" => true, "inc" => true,
        "js"  => true, "html"  => true, "htm"  => true,
        "py"  => true, "sh"    => true, "pl"   => true,
        "asp" => true, "aspx"  => true, "jsp"  => true,
    ];

    // Suspicious patterns (defensive signature set)
    $patterns = [
        "php_eval"            => '/\beval\s*\(/i',
        "php_assert"          => '/\bassert\s*\(/i',
        "php_base64_decode"   => '/\bbase64_decode\s*\(/i',
        "php_gzinflate"       => '/\bgzinflate\s*\(/i',
        "php_str_rot13"       => '/\bstr_rot13\s*\(/i',
        "php_create_function" => '/\bcreate_function\s*\(/i',
        "php_shell_exec"      => '/\bshell_exec\s*\(/i',
        "php_system"          => '/\bsystem\s*\(/i',
        "php_passthru"        => '/\bpassthru\s*\(/i',
        "php_exec"            => '/\bexec\s*\(/i',
        "php_proc_open"       => '/\bproc_open\s*\(/i',
        "php_popen"           => '/\bpopen\s*\(/i',
        "php_fsockopen"       => '/\bfsockopen\s*\(/i',
        "php_curl_exec"       => '/\bcurl_exec\s*\(/i',
        "php_preg_replace_e"  => '/preg_replace\s*\(.*?\/e[\'"]/is',
        "php_superglobals"    => '/\$_(GET|POST|REQUEST|COOKIE)\b/i',
        "php_php_input"       => '/php:\/\/input/i',
        "cmd_wget_curl"       => '/\b(wget|curl)\b/i',
        "cmd_powershell"      => '/\bpowershell\b/i',
        "cmd_nc_netcat"       => '/\b(nc|netcat)\b/i',
    ];

    $findings = [];
    $scanned = 0;
    $skipped = 0;

    $rootNorm = normPath($rootReal);
    $excludeNorm = array_map('normPath', $exclude);

    $dirIter = new RecursiveDirectoryIterator($rootNorm, FilesystemIterator::SKIP_DOTS);
    $iter = new RecursiveIteratorIterator($dirIter, RecursiveIteratorIterator::LEAVES_ONLY);

    foreach ($iter as $fileInfo) {
        /** @var SplFileInfo $fileInfo */
        $path = $fileInfo->getPathname();

        // Exclude prefixes
        if (isExcluded($path, $excludeNorm)) {
            $skipped++;
            continue;
        }

        if (!$fileInfo->isFile() || $fileInfo->isLink()) {
            $skipped++;
            continue;
        }

        $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        if ($ext === '' || !isset($exts[$ext])) {
            $skipped++;
            continue;
        }

        $size = $fileInfo->getSize();
        if ($size > $maxSize) {
            $skipped++;
            continue;
        }

        $scanned++;

        $content = readHeadTail($path, $maxBytes);
        if ($content === null || $content === '') continue;

        $hits = scanContent($content, $patterns);
        if (!empty($hits)) {
            $findings[] = [
                "path" => $path,
                "size" => $size,
                "hits" => $hits,
            ];
        }
    }

    // Sort by number of hits, then size
    usort($findings, function ($a, $b) {
        $ha = count($a["hits"]);
        $hb = count($b["hits"]);
        if ($ha !== $hb) return $hb <=> $ha;
        return ($b["size"] ?? 0) <=> ($a["size"] ?? 0);
    });

    $report = [
        "root" => $rootNorm,
        "scanned_files" => $scanned,
        "skipped_entries" => $skipped,
        "findings" => $findings,
    ];

    $json = json_encode($report, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);

    if ($outFile !== "") {
        $ok = @file_put_contents($outFile, $json);
        if ($ok === false) {
            fwrite(STDERR, "Failed to write report to: {$outFile}\n");
            echo $json . "\n";
            return 1;
        }
        fwrite(STDOUT, "Wrote report: {$outFile}\n");
        return 0;
    }

    echo $json . "\n";
    return 0;
}

exit(main($argv));
