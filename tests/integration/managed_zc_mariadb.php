<?php
/**
 * Smart Pro System Zero-Copy first enrollment — MariaDB integration test.
 *
 * Test-only SQL invariant model of Broker 0.60.42 atomic issuer. This is not
 * a deployed WordPress plugin or a claim that the actual WPDB wrapper passed.
 * Real InnoDB tables / connections / advisory locks are exercised in CI.
 * All installation IDs, secrets and keys are synthetic.
 */
declare(strict_types=1);
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

const IID = 'ID-00001';
const REF = 'SPMZ-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const NODES = 'zcqa_managed_nodes';
const PAIRS = 'zcqa_managed_pairings';
const LEDGER = 'zcqa_managed_zero_copy';
const LOCK_NAME = 'sprsb_managed_installation_ID-00001';

function db(): mysqli {
    $db = new mysqli(
        getenv('ZC_DB_HOST') ?: '127.0.0.1',
        getenv('ZC_DB_USER') ?: 'zc_tester',
        getenv('ZC_DB_PASS') ?: 'qa-only-password',
        getenv('ZC_DB_NAME') ?: 'zc_test',
        (int) (getenv('ZC_DB_PORT') ?: '3306')
    );
    $db->set_charset('utf8mb4');
    return $db;
}

function fetch(mysqli $db, string $sql, mixed ...$args): ?array {
    $stmt = $db->prepare($sql);
    if ($args) {
        $stmt->bind_param(str_repeat('s', count($args)), ...$args);
    }
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    return $row ?: null;
}

function scalar(mysqli $db, string $sql, mixed ...$args): mixed {
    $row = fetch($db, $sql, ...$args);
    return is_array($row) ? reset($row) : null;
}

function node_count(mysqli $db): int {
    return (int) scalar($db, 'SELECT COUNT(*) FROM ' . NODES . ' WHERE installation_ref=?', IID);
}
function ledger_row(mysqli $db): ?array {
    return fetch($db, 'SELECT * FROM ' . LEDGER . ' WHERE installation_ref=? AND request_ref=?', IID, REF);
}
function engine_is_innodb(mysqli $db): bool {
    foreach ([NODES, PAIRS, LEDGER] as $table) {
        $engine = scalar($db,
            'SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? LIMIT 1',
            $table);
        if (!is_string($engine) || strtolower($engine) !== 'innodb') {
            return false;
        }
    }
    return true;
}

function reset_schema(mysqli $db): void {
    $db->query('DROP TRIGGER IF EXISTS zcqa_refuse_ledger_update');
    foreach ([LEDGER, NODES, PAIRS] as $table) {
        $db->query('DROP TABLE IF EXISTS ' . $table);
    }
    $db->query("CREATE TABLE " . NODES . " (
        id bigint unsigned NOT NULL AUTO_INCREMENT,
        node_id varchar(64) NOT NULL,
        secret_hash varchar(255) NOT NULL,
        installation_ref varchar(100) NOT NULL DEFAULT '',
        status varchar(20) NOT NULL DEFAULT 'active',
        client varchar(50) NOT NULL DEFAULT '',
        client_version varchar(30) NOT NULL DEFAULT '',
        architecture varchar(20) NOT NULL DEFAULT '',
        paired_ip_hash char(64) NOT NULL DEFAULT '',
        paired_at datetime NOT NULL,
        last_seen_at datetime NULL,
        created_at datetime NOT NULL,
        updated_at datetime NOT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY node_id (node_id),
        KEY installation_status (installation_ref,status)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    $db->query("CREATE TABLE " . PAIRS . " (
        id bigint unsigned NOT NULL AUTO_INCREMENT,
        installation_ref varchar(100) NOT NULL DEFAULT '',
        status varchar(20) NOT NULL DEFAULT 'pending',
        created_at datetime NOT NULL,
        expires_at datetime NOT NULL,
        PRIMARY KEY (id),
        KEY installation_status (installation_ref,status)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    $db->query("CREATE TABLE " . LEDGER . " (
        id bigint unsigned NOT NULL AUTO_INCREMENT,
        installation_ref varchar(100) NOT NULL,
        request_ref char(37) NOT NULL,
        status varchar(32) NOT NULL DEFAULT 'pending_handoff',
        approved_by bigint unsigned NOT NULL,
        approved_at datetime NOT NULL,
        expires_at datetime NOT NULL,
        consent_hash char(64) NOT NULL,
        device_binding_hash char(64) NOT NULL DEFAULT '',
        node_id varchar(64) NOT NULL DEFAULT '',
        receiver_public_key_hex char(64) NOT NULL DEFAULT '',
        architecture varchar(20) NOT NULL DEFAULT '',
        envelope_sha256 char(64) NOT NULL DEFAULT '',
        sealed_envelope longtext NULL,
        identity_issued_at datetime NULL,
        updated_at datetime NOT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY installation_ref (installation_ref),
        UNIQUE KEY request_ref (request_ref),
        KEY status_expires (status,expires_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $now = time();
    $approved = gmdate('Y-m-d H:i:s', $now - 20);
    $expires = gmdate('Y-m-d H:i:s', $now + 580);
    $stmt = $db->prepare(
        'INSERT INTO '.LEDGER.' (installation_ref,request_ref,status,approved_by,approved_at,expires_at,consent_hash,device_binding_hash,updated_at) VALUES (?,?,"claim_locked",1,?,?,?,?,?)'
    );
    $consent = str_repeat('a', 64);
    $binding = str_repeat('b', 64);
    $stmt->bind_param('sssssss', $iid, $ref, $approved, $expires, $consent, $binding, $approved);
    $iid = IID; $ref = REF;
    $stmt->execute();
    $stmt->close();
}

function create_envelope(int $now, string $node, string $secret): string {
    // Encrypt using libsodium as the production Broker does; no test secret
    // leaves the transaction worker's local process or test database.
    $recipient = sodium_crypto_box_keypair();
    $public = sodium_crypto_box_publickey($recipient);
    $content = json_encode([
        'contract' => 'smart-pro-managed-zero-copy-identity-content-v1',
        'installation_id' => IID,
        'request_ref' => REF,
        'node_id' => $node,
        'node_secret' => $secret,
        'issued_at' => $now,
    ], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    $sealed = sodium_crypto_box_seal($content, $public);
    return json_encode([
        'contract' => 'smart-pro-managed-zero-copy-sealed-identity-v1',
        'installation_id' => IID,
        'request_ref' => REF,
        'receiver_public_key_hex' => bin2hex($public),
        'sealed_box_hex' => bin2hex($sealed),
        'issued_at' => $now,
        'expires_at' => $now + 120,
        'runtime_authorized' => false,
        'technician_access_granted' => false,
    ], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
}

/**
 * The critical ordering/queries mirror 0.60.42's issuer:
 * InnoDB engine preflight -> GET_LOCK -> BEGIN -> SELECT ... FOR UPDATE ->
 * conflict COUNTs -> INSERT node -> UPDATE exact locked ledger -> COMMIT.
 * This function deliberately does not imitate Portal proof or WordPress APIs.
 */
function issue_once(mysqli $db, string $fault=''): string {
    if (!engine_is_innodb($db)) {
        return 'storage_not_transactional';
    }
    if ((string) scalar($db, 'SELECT GET_LOCK(?, 2)', LOCK_NAME) !== '1') {
        return 'installation_lock_unavailable';
    }
    $started = false;
    $committed = false;
    try {
        $db->begin_transaction();
        $started = true;
        $row = fetch($db,
            'SELECT * FROM '.LEDGER.' WHERE installation_ref=? AND request_ref=? FOR UPDATE',
            IID, REF);
        if (!$row || $row['status'] !== 'claim_locked' || $row['node_id'] !== '' ||
            $row['envelope_sha256'] !== '' || strtotime($row['expires_at'].' UTC') <= time()) {
            return 'claim_not_locked';
        }
        $existing = node_count($db);
        $pending = (int) scalar($db,
            'SELECT COUNT(*) FROM '.PAIRS.' WHERE installation_ref=? AND status="pending"',
            IID);
        if ($existing !== 0 || $pending !== 0) {
            return 'conflicting_identity';
        }
        $node = 'SPMN-'.strtoupper(bin2hex(random_bytes(16)));
        $secret = 'SPMS-'.rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $hash = password_hash($secret, PASSWORD_DEFAULT);
        $now = time();
        $stamp = gmdate('Y-m-d H:i:s', $now);
        $insert = $db->prepare('INSERT INTO '.NODES.'
            (node_id,secret_hash,installation_ref,status,client,client_version,architecture,paired_ip_hash,paired_at,created_at,updated_at)
            VALUES (?, ?, ?, "active", "smart_pro_managed_support", "zero_copy_staged", "amd64", "", ?, ?, ?)');
        $iid = IID;
        $insert->bind_param('ssssss', $node, $hash, $iid, $stamp, $stamp, $stamp);
        $insert->execute();
        $insert->close();
        if ($fault === 'crash_after_insert') {
            // Simulate a killed PHP worker while its InnoDB transaction is open.
            exit(87);
        }
        if ($fault === 'throw_after_insert') {
            throw new RuntimeException('synthetic_interruption_after_insert');
        }
        $original = create_envelope($now, $node, $secret);
        $digest = hash('sha256', $original);
        $update = $db->prepare('UPDATE '.LEDGER.'
            SET status="issued_sealed", node_id=?,receiver_public_key_hex=?,
                architecture="amd64",envelope_sha256=?,sealed_envelope=?,
                identity_issued_at=?,updated_at=?
            WHERE installation_ref=? AND request_ref=? AND status="claim_locked"
              AND node_id="" AND envelope_sha256=""');
        $packet = json_decode($original, true);
        $public = $packet['receiver_public_key_hex'];
        $ref = REF;
        $update->bind_param('ssssssss', $node, $public, $digest, $original, $stamp, $stamp, $iid, $ref);
        $update->execute();
        $affected = $update->affected_rows;
        $update->close();
        if ($affected !== 1) {
            throw new RuntimeException('ledger_write_failed');
        }
        $db->commit();
        $committed = true;
        return 'issued_sealed';
    } catch (Throwable $e) {
        return 'transaction_failed';
    } finally {
        if ($started && !$committed) {
            try { $db->rollback(); } catch (Throwable $ignored) {}
        }
        try { scalar($db, 'SELECT RELEASE_LOCK(?)', LOCK_NAME); } catch (Throwable $ignored) {}
    }
}

function assert_true(bool $yes, string $case): void {
    if (!$yes) {
        fwrite(STDERR, "FAIL: ".$case."\n");
        exit(1);
    }
    echo "PASS: ".$case."\n";
}
function spawn(string $mode): array {
    $cmd = [PHP_BINARY, __FILE__, $mode];
    $proc = proc_open($cmd, [
        0=>['pipe','r'], 1=>['pipe','w'], 2=>['pipe','w'],
    ], $pipes, __DIR__);
    if (!is_resource($proc)) {
        throw new RuntimeException('worker_spawn_failed');
    }
    fclose($pipes[0]);
    return [$proc, $pipes];
}
function finish(array $job): array {
    [$proc, $pipes] = $job;
    $stdout = trim(stream_get_contents($pipes[1]));
    $stderr = trim(stream_get_contents($pipes[2]));
    fclose($pipes[1]); fclose($pipes[2]);
    $exit = proc_close($proc);
    return [$exit, $stdout, $stderr];
}

$mode = $argv[1] ?? 'suite';
if ($mode === 'worker') {
    try {
        $fault = in_array('--crash', $argv, true)
            ? 'crash_after_insert'
            : (in_array('--fail', $argv, true) ? 'throw_after_insert' : '');
        echo issue_once(db(), $fault)."\n";
    }
    catch (Throwable $e) { echo "unexpected_failure\n"; exit(2); }
    exit;
}

try {
    $db = db();
    if ($mode !== 'suite') { throw new RuntimeException('unsupported_mode'); }
    reset_schema($db);
    assert_true(engine_is_innodb($db), 'all three real storage engines are InnoDB');

    // Four distinct mysqli connections run at the same time.
    $workers = [];
    for ($i=0; $i<4; $i++) { $workers[] = spawn('worker'); }
    $out = [];
    foreach ($workers as $worker) {
        [$code,$result,$err] = finish($worker);
        assert_true($code===0 && $err==='', 'concurrent worker completed safely');
        $out[] = $result;
    }
    assert_true(count(array_filter($out, fn($x)=>$x==='issued_sealed'))===1,
        'exactly one of four concurrent issuance attempts committed');
    assert_true(node_count($db)===1, 'exactly one node persisted');
    $ledger = ledger_row($db);
    assert_true($ledger['status']==='issued_sealed' &&
                hash('sha256',$ledger['sealed_envelope'])===$ledger['envelope_sha256'],
        'atomic ledger ciphertext and digest match');
    $original = $ledger['sealed_envelope'];
    [$code,$result] = finish(spawn('worker'));
    assert_true($code===0 && $result==='claim_not_locked' &&
                node_count($db)===1 && ledger_row($db)['sealed_envelope']===$original,
        'lost response retry never remints node or original envelope');

    reset_schema($db);
    // Test deliberate rollback in an independent worker process.
    $proc = proc_open([PHP_BINARY, __FILE__, 'worker', '--fail'],
        [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']], $pipes);
    fclose($pipes[0]);
    $stdout = trim(stream_get_contents($pipes[1]));
    $stderr = trim(stream_get_contents($pipes[2]));
    fclose($pipes[1]);fclose($pipes[2]);
    assert_true(proc_close($proc)===0 && $stdout==='transaction_failed' && $stderr==='',
        'synthetic interruption after INSERT invokes rollback');
    assert_true(node_count($db)===0 && ledger_row($db)['status']==='claim_locked',
        'rollback removes node and leaves the original locked request unchanged');

    // Abrupt process termination closes the DB connection mid-transaction.
    reset_schema($db);
    $crash = proc_open([PHP_BINARY, __FILE__, 'worker', '--crash'],
        [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']], $pipes);
    fclose($pipes[0]);
    stream_get_contents($pipes[1]);
    $crashErr = stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]);
    $exitCode = proc_close($crash);
    assert_true($exitCode===87 && $crashErr==='',
        'PHP worker terminated abruptly while SQL transaction was uncommitted');
    assert_true(node_count($db)===0 && ledger_row($db)['status']==='claim_locked',
        'MariaDB rolls back uncommitted node after connection loss');
    [$code,$result] = finish(spawn('worker'));
    assert_true($code===0 && $result==='issued_sealed' &&
                node_count($db)===1,
        'new connection can safely issue once after the crashed worker');

    // A REAL database trigger raises a SQL error after node INSERT.
    $db->query("CREATE TRIGGER zcqa_refuse_ledger_update
        BEFORE UPDATE ON ".LEDGER." FOR EACH ROW
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='intentional qa failure'");
    [$code,$result] = finish(spawn('worker'));
    assert_true($code===0 && $result==='transaction_failed', 'real SQL trigger aborts UPDATE');
    assert_true(node_count($db)===0 && ledger_row($db)['status']==='claim_locked',
        'InnoDB rolls back node insert on failed ledger write');
    $db->query('DROP TRIGGER zcqa_refuse_ledger_update');

    // A connection holding the installation lock blocks another writer.
    reset_schema($db);
    assert_true((string) scalar($db, 'SELECT GET_LOCK(?,0)', LOCK_NAME)==='1',
        'first connection owns installation-scoped advisory lock');
    [$code,$result] = finish(spawn('worker'));
    assert_true($code===0 && $result==='installation_lock_unavailable' &&
                node_count($db)===0, 'second connection denied while lock held');
    scalar($db, 'SELECT RELEASE_LOCK(?)', LOCK_NAME);
    [$code,$result] = finish(spawn('worker'));
    assert_true($code===0 && $result==='issued_sealed', 'issuance can proceed after lock release');

    // An accidental nontransactional table must refuse issuance before BEGIN.
    reset_schema($db);
    $db->query('ALTER TABLE '.PAIRS.' ENGINE=MyISAM');
    [$code,$result] = finish(spawn('worker'));
    assert_true($code===0 && $result==='storage_not_transactional' &&
                node_count($db)===0, 'MyISAM drift fails closed before node insert');
    $db->query('ALTER TABLE '.PAIRS.' ENGINE=InnoDB');

    // Last-line SQL uniqueness: even if two approvals race, one row remains.
    reset_schema($db);
    $approved=gmdate('Y-m-d H:i:s');
    try {
        $db->query("INSERT INTO ".LEDGER."
            (installation_ref,request_ref,status,approved_by,approved_at,expires_at,consent_hash,device_binding_hash,updated_at)
            VALUES ('".IID."','SPMZ-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC','pending_handoff',1,
            '{$approved}','{$approved}','".str_repeat('a',64)."','".str_repeat('b',64)."','{$approved}')");
        assert_true(false, 'unexpected second approval accepted');
    } catch (mysqli_sql_exception $e) {
        assert_true((int)$e->getCode()===1062, 'unique Installation ID blocks second approval');
    }
    echo "MARIADB_INVARIANTS_PASS\n";
} catch (Throwable $e) {
    fwrite(STDERR, 'FAIL: test runner error ('.get_class($e).') '.$e->getMessage()."\n");
    exit(1);
}
