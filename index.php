<?php
// ============================================================
// MYBOUTIK - Backend complet PostgreSQL
// Plateforme multi-boutiques : creation de boutique, catalogue,
// vitrine publique, commandes paiement a la livraison (COD),
// livraisons, clients, finances, analytique, marketing.
// Meme style que ROM_MONEY/APPLICATION/index.php (routeur module/action,
// helpers ok()/fail()/db()/q(), JWT maison, aucune valeur par defaut
// codee en dur pour les secrets).
// ============================================================

define('DB_HOST',     getenv('DB_HOST')     ?: 'localhost');
define('DB_NAME',     getenv('DB_NAME')     ?: 'myboutik_db');
define('DB_USER',     getenv('DB_USER')     ?: 'postgres');
define('DB_PASS',     getenv('DB_PASS')     ?: '');
define('DB_PORT',     getenv('DB_PORT')     ?: '5432');
// Neon (et la plupart des Postgres serverless) exigent une connexion
// chiffree et refusent toute tentative en clair. Render Postgres et un
// Postgres local l'acceptent aussi sans probleme, donc ce reglage est sans
// danger dans tous les cas - mais il reste desactive par defaut (chaine
// vide) pour ne rien changer au comportement existant tant qu'il n'est pas
// explicitement demande.
define('DB_SSLMODE',  getenv('DB_SSLMODE')  ?: '');
define('JWT_SECRET',  getenv('JWT_SECRET')  ?: null);
// Cle dediee pour route_install() (creation/mise a jour des tables), separee
// de JWT_SECRET par souci de coherence avec ROM_MONEY. Si INSTALL_KEY n'est
// pas configuree, on retombe sur JWT_SECRET.
define('INSTALL_KEY', getenv('INSTALL_KEY') ?: JWT_SECRET);
// Aucune valeur de repli codee en dur pour ce secret : un secret visible
// dans le code source n'est plus un secret. Si JWT_SECRET n'est pas
// configuree sur l'hebergeur, l'app s'arrete plutot que de tourner avec
// un secret compromis/devinable.
if (!JWT_SECRET) {
    http_response_code(500);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['success'=>false,'message'=>'Configuration serveur incomplete: JWT_SECRET non defini.'], JSON_UNESCAPED_UNICODE);
    exit;
}
define('JWT_EXPIRY', 43200); // 12h
// IMPORTANT: par defaut (variable absente) on retombe sur 'production'
// (sur, ferme), jamais 'development' (permissif, ouvre le CORS a tout le
// web et affiche les erreurs BDD brutes). 'development' ne doit s'activer
// que par un choix EXPLICITE.
define('APP_ENV',   getenv('APP_ENV')   ?: 'production');
define('APP_DEBUG', APP_ENV === 'development');

// CORS restreint : seules les origines listees ici peuvent appeler l'API
// directement depuis un navigateur. A completer avec le(s) domaine(s) ou
// sont hebergees index.html / dashboard / store une fois deployees.
$ALLOWED_ORIGINS = [
    // 'https://myboutik.exemple.com',
];
$requestOrigin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($requestOrigin, $ALLOWED_ORIGINS, true)) {
    header("Access-Control-Allow-Origin: $requestOrigin");
} elseif (APP_ENV === 'development') {
    header("Access-Control-Allow-Origin: *"); // confort en developpement local uniquement
}
header("Vary: Origin");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Content-Type: application/json; charset=utf-8");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
header("Permissions-Policy: geolocation=(), camera=(), microphone=()");
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

// ============================================================
// HELPERS GENERIQUES
// ============================================================

function ok($data = null, $msg = 'OK', $code = 200) {
    http_response_code($code);
    echo json_encode(['success'=>true,'message'=>$msg,'data'=>$data], JSON_UNESCAPED_UNICODE);
    exit;
}
function fail($msg, $code = 400) {
    http_response_code($code);
    echo json_encode(['success'=>false,'message'=>$msg], JSON_UNESCAPED_UNICODE);
    exit;
}
function log_and_fail($e, $userMsg, $code = 500) {
    error_log('[MYBOUTIK] '.$userMsg.' :: '.$e->getMessage());
    fail(APP_DEBUG ? $e->getMessage() : $userMsg, $code);
}
function body() {
    $d = json_decode(file_get_contents('php://input'), true);
    return is_array($d) ? $d : [];
}
// Lit un parametre depuis le corps JSON en priorite, sinon la query string.
function bg($key, $default=null) {
    $b = body();
    if (array_key_exists($key, $b)) return $b[$key];
    return $_GET[$key] ?? $default;
}
function b64e($d) { return rtrim(strtr(base64_encode($d),'+/','-_'),'='); }
function b64d($d) { return base64_decode(strtr($d,'-_','+/').str_repeat('=',(3+strlen($d))%4)); }
function jwt_make($payload) {
    $h = b64e(json_encode(['alg'=>'HS256','typ'=>'JWT']));
    $payload['iat'] = time(); $payload['exp'] = time()+JWT_EXPIRY;
    $b = b64e(json_encode($payload));
    return "$h.$b.".b64e(hash_hmac('sha256',"$h.$b",JWT_SECRET,true));
}
function jwt_check($token) {
    $p = explode('.',$token);
    if(count($p)!==3) return null;
    if(!hash_equals(b64e(hash_hmac('sha256',"$p[0].$p[1]",JWT_SECRET,true)),$p[2])) return null;
    $pl = json_decode(b64d($p[1]),true);
    return ($pl && $pl['exp']>time()) ? $pl : null;
}
// Authentification du proprietaire de boutique(s) (table users). Seule
// identite de cette app (pas d'admin, pas de role separe pour l'instant).
function owner_auth() {
    $h = $_SERVER["HTTP_AUTHORIZATION"] ?? $_SERVER["REDIRECT_HTTP_AUTHORIZATION"] ?? (function_exists("getallheaders") ? (getallheaders()["Authorization"] ?? "") : "") ?? "";
    if(!str_starts_with($h,'Bearer ')) fail('Token manquant',401);
    $pl = jwt_check(substr($h,7));
    if(!$pl || ($pl['typ']??'')!=='owner') fail('Token invalide ou expire',401);
    $status = q("SELECT status FROM users WHERE id=?",[$pl['sub']])->fetchColumn();
    if($status === false) fail('Compte introuvable',401);
    if($status !== 'active') fail('Compte suspendu ou bloque', 403);
    return $pl;
}
function uid() { return bin2hex(random_bytes(8)); }
function order_ref() { return 'CMD-'.strtoupper(date('ymd')).'-'.strtoupper(substr(uniqid(),-6)); }

function slugify($text) {
    $text = trim((string)$text);
    $translit = @iconv('UTF-8','ASCII//TRANSLIT//IGNORE',$text);
    if ($translit !== false && $translit !== '') $text = $translit;
    $text = strtolower($text);
    $text = preg_replace('/[^a-z0-9]+/','-',$text);
    $text = trim($text,'-');
    if ($text === '') $text = 'boutique';
    return substr($text,0,60);
}
function unique_boutique_slug($base) {
    $slug = $base; $i = 1;
    while (q("SELECT 1 FROM boutiques WHERE slug=?",[$slug])->fetch()) {
        $i++; $slug = $base.'-'.$i;
    }
    return $slug;
}

function db(): PDO {
    static $pdo = null;
    if(!$pdo) {
        try {
            $dsn = "pgsql:host=".DB_HOST.";port=".DB_PORT.";dbname=".DB_NAME;
            if (DB_SSLMODE !== '') $dsn .= ";sslmode=".DB_SSLMODE;
            $pdo = new PDO(
                $dsn,
                DB_USER, DB_PASS,
                [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES=>true]
            );
        } catch(PDOException $e) {
            error_log('[MYBOUTIK] Erreur serveur :: BDD: '.$e->getMessage());
            fail(APP_DEBUG ? 'BDD: '.$e->getMessage() : 'Erreur serveur', 500);
        }
    }
    return $pdo;
}
function q($sql, $params=[]) {
    $s = db()->prepare($sql);
    $s->execute($params);
    return $s;
}

function rate_limit_check($bucket, $maxRequests, $windowSeconds) {
    try {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        if (mt_rand(1, 100) === 1) {
            q("DELETE FROM rate_limit_hits WHERE created_at < NOW() - INTERVAL '1 hour'");
        }
        $row = q("SELECT COUNT(*) c FROM rate_limit_hits
                  WHERE bucket=? AND ip_address=?
                  AND created_at > NOW() - (?::text || ' seconds')::interval",
                  [$bucket, $ip, $windowSeconds])->fetch();
        if ($row && (int)$row['c'] >= $maxRequests) {
            fail('Trop de requetes depuis cette adresse. Reessayez dans quelques instants.', 429);
        }
        q("INSERT INTO rate_limit_hits (bucket, ip_address) VALUES (?,?)", [$bucket, $ip]);
    } catch (PDOException $e) { /* table pas encore prete : on laisse passer */ }
}

function log_activity($boutiqueId, $message) {
    try { q("INSERT INTO activity_log (boutique_id, message) VALUES (?,?)", [$boutiqueId, $message]); }
    catch (PDOException $e) { /* jamais bloquant */ }
}

function period_clause($period, $col='created_at') {
    switch ($period) {
        case '7d':  return "$col >= NOW() - INTERVAL '7 days'";
        case '90d': return "$col >= NOW() - INTERVAL '90 days'";
        case 'all': return "1=1";
        case '30d':
        default:    return "$col >= NOW() - INTERVAL '30 days'";
    }
}

// Statuts consideres comme "argent encaisse" (validee ou livree), par
// opposition a pending (pas encore traitee)/refusee/annulee.
const ENCAISSE_STATUSES = "('processing','shipped','delivered')";

function require_boutique_owned($boutiqueId, $userId) {
    if (!$boutiqueId) fail('boutique_id manquant', 400);
    $row = q("SELECT * FROM boutiques WHERE id=? AND owner_user_id=?", [$boutiqueId, $userId])->fetch();
    if (!$row) fail('Boutique introuvable', 404);
    return $row;
}

// Paliers de grade (gamification), calcules sur le cumul "vie" des revenus
// encaisses de la boutique. Le cumul ne redescend jamais (meme principe que
// l'ecran "Mon grade" : chaque palier est acquis pour de bon).
const GRADES = [
    ['name'=>'Bronze','min'=>1000000],
    ['name'=>'Argent','min'=>5000000],
    ['name'=>'Or','min'=>10000000],
    ['name'=>'Platine','min'=>20000000],
    ['name'=>'Diamant','min'=>40000000],
    ['name'=>'Emeraude','min'=>80000000],
    ['name'=>'Rubis','min'=>100000000],
    ['name'=>'Maitre','min'=>200000000],
    ['name'=>'Grand Maitre','min'=>300000000],
    ['name'=>'Legende','min'=>500000000],
    ['name'=>'Titan','min'=>1000000000],
];
function compute_grade($totalEncaisse) {
    $current = null; $next = GRADES[0];
    foreach (GRADES as $i => $g) {
        if ($totalEncaisse >= $g['min']) { $current = $g; $next = GRADES[$i+1] ?? null; }
    }
    $prevMin = $current['min'] ?? 0;
    $nextMin = $next['min'] ?? null;
    $progress = $nextMin ? max(0,min(100, (($totalEncaisse-$prevMin)/($nextMin-$prevMin))*100)) : 100;
    return [
        'current_name'  => $current['name'] ?? null,
        'next_name'     => $next['name'] ?? null,
        'total'         => (float)$totalEncaisse,
        'next_min'      => $nextMin,
        'remaining'     => $nextMin ? max(0,$nextMin-$totalEncaisse) : 0,
        'progress_pct'  => round($progress,1),
        'all'           => GRADES,
    ];
}

// ============================================================
// ROUTEUR
// ============================================================
$uri    = trim(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), '/');
$parts  = explode('/', $uri);
$module = $parts[1] ?? ($parts[0] ?? '');
$action = $_GET['action'] ?? '';

try {
    switch ($module) {
        case 'install':   route_install(); break;
        case 'auth':      route_auth($action); break;
        case 'boutiques': route_boutiques($action); break;
        case 'products':  route_products($action); break;
        case 'shop':      route_shop($action); break;
        case 'orders':    route_orders($action); break;
        case 'deliveries':route_deliveries($action); break;
        case 'customers': route_customers($action); break;
        case 'contacts':  route_contacts($action); break;
        case 'finance':   route_finance($action); break;
        case 'analytics': route_analytics($action); break;
        case 'marketing': route_marketing($action); break;
        case 'health':    ok(['status'=>'up','time'=>date('c')]); break;
        default: fail('Module inconnu', 404);
    }
} catch (PDOException $e) {
    log_and_fail($e, 'Erreur base de donnees');
} catch (Throwable $e) {
    log_and_fail($e, 'Erreur serveur');
}

// ============================================================
// INSTALL — creation des tables
// ============================================================
function route_install() {
    $key = $_GET['key'] ?? '';
    if (APP_ENV !== 'development' && $key !== INSTALL_KEY) fail('Non autorise', 403);

    $sqls = [
    "CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(36) PRIMARY KEY,
        email VARCHAR(190) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        full_name VARCHAR(150),
        email_verified_at TIMESTAMP,
        verification_token VARCHAR(64),
        verification_sent_at TIMESTAMP,
        status VARCHAR(20) DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE TABLE IF NOT EXISTS boutiques (
        id VARCHAR(36) PRIMARY KEY,
        owner_user_id VARCHAR(36) NOT NULL,
        slug VARCHAR(80) NOT NULL UNIQUE,
        name VARCHAR(150) NOT NULL,
        currency VARCHAR(10) DEFAULT 'XOF',
        cod_enabled SMALLINT DEFAULT 1,
        status VARCHAR(20) DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE INDEX IF NOT EXISTS idx_boutiques_owner ON boutiques(owner_user_id)",
    "CREATE TABLE IF NOT EXISTS products (
        id VARCHAR(36) PRIMARY KEY,
        boutique_id VARCHAR(36) NOT NULL,
        name VARCHAR(200) NOT NULL,
        description TEXT,
        price DECIMAL(14,2) NOT NULL DEFAULT 0,
        cost_price DECIMAL(14,2),
        stock_qty INT DEFAULT 0,
        image_url TEXT,
        status VARCHAR(20) DEFAULT 'draft',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE INDEX IF NOT EXISTS idx_products_boutique ON products(boutique_id)",
    "CREATE TABLE IF NOT EXISTS product_variants (
        id VARCHAR(36) PRIMARY KEY,
        product_id VARCHAR(36) NOT NULL,
        name VARCHAR(100) NOT NULL,
        price DECIMAL(14,2),
        stock_qty INT DEFAULT 0
    )",
    "CREATE INDEX IF NOT EXISTS idx_variants_product ON product_variants(product_id)",
    "CREATE TABLE IF NOT EXISTS suppliers (
        id VARCHAR(36) PRIMARY KEY,
        boutique_id VARCHAR(36) NOT NULL,
        name VARCHAR(150) NOT NULL,
        phone VARCHAR(30),
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE INDEX IF NOT EXISTS idx_suppliers_boutique ON suppliers(boutique_id)",
    "CREATE TABLE IF NOT EXISTS supplier_orders (
        id VARCHAR(36) PRIMARY KEY,
        boutique_id VARCHAR(36) NOT NULL,
        supplier_id VARCHAR(36) NOT NULL,
        product_id VARCHAR(36),
        qty INT NOT NULL,
        unit_cost DECIMAL(14,2) NOT NULL DEFAULT 0,
        status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE INDEX IF NOT EXISTS idx_supplierorders_boutique ON supplier_orders(boutique_id)",
    "CREATE TABLE IF NOT EXISTS customers (
        id VARCHAR(36) PRIMARY KEY,
        boutique_id VARCHAR(36) NOT NULL,
        name VARCHAR(150),
        phone VARCHAR(30),
        email VARCHAR(190),
        address TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_customers_boutique_phone ON customers(boutique_id, phone)",
    "CREATE TABLE IF NOT EXISTS orders (
        id VARCHAR(36) PRIMARY KEY,
        boutique_id VARCHAR(36) NOT NULL,
        customer_id VARCHAR(36),
        ref VARCHAR(30) UNIQUE,
        status VARCHAR(20) DEFAULT 'pending',
        payment_method VARCHAR(20) DEFAULT 'cod',
        subtotal DECIMAL(14,2) DEFAULT 0,
        delivery_fee_charged DECIMAL(14,2) DEFAULT 0,
        total DECIMAL(14,2) DEFAULT 0,
        customer_name VARCHAR(150),
        customer_phone VARCHAR(30),
        customer_address TEXT,
        utm_source VARCHAR(100),
        utm_campaign VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        delivered_at TIMESTAMP
    )",
    "CREATE INDEX IF NOT EXISTS idx_orders_boutique ON orders(boutique_id)",
    "CREATE INDEX IF NOT EXISTS idx_orders_boutique_created ON orders(boutique_id, created_at)",
    "CREATE TABLE IF NOT EXISTS order_items (
        id VARCHAR(36) PRIMARY KEY,
        order_id VARCHAR(36) NOT NULL,
        product_id VARCHAR(36),
        product_name VARCHAR(200),
        variant_id VARCHAR(36),
        unit_price DECIMAL(14,2) NOT NULL DEFAULT 0,
        unit_cost DECIMAL(14,2) DEFAULT 0,
        qty INT NOT NULL DEFAULT 1
    )",
    "CREATE INDEX IF NOT EXISTS idx_items_order ON order_items(order_id)",
    "CREATE TABLE IF NOT EXISTS abandoned_carts (
        id VARCHAR(36) PRIMARY KEY,
        boutique_id VARCHAR(36) NOT NULL,
        session_id VARCHAR(64),
        phone VARCHAR(30),
        email VARCHAR(190),
        cart_snapshot TEXT,
        total DECIMAL(14,2) DEFAULT 0,
        converted SMALLINT DEFAULT 0,
        captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE INDEX IF NOT EXISTS idx_abandoned_boutique ON abandoned_carts(boutique_id)",
    "CREATE TABLE IF NOT EXISTS abandoned_settings (
        boutique_id VARCHAR(36) PRIMARY KEY,
        capture_enabled SMALLINT DEFAULT 1,
        timeout_minutes INT DEFAULT 15,
        email_alert SMALLINT DEFAULT 0
    )",
    "CREATE TABLE IF NOT EXISTS delivery_persons (
        id VARCHAR(36) PRIMARY KEY,
        boutique_id VARCHAR(36) NOT NULL,
        name VARCHAR(150) NOT NULL,
        phone VARCHAR(30),
        active SMALLINT DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE INDEX IF NOT EXISTS idx_delivpersons_boutique ON delivery_persons(boutique_id)",
    "CREATE TABLE IF NOT EXISTS delivery_assignments (
        id VARCHAR(36) PRIMARY KEY,
        order_id VARCHAR(36) NOT NULL UNIQUE,
        boutique_id VARCHAR(36) NOT NULL,
        delivery_person_id VARCHAR(36),
        status VARCHAR(20) DEFAULT 'to_assign',
        assigned_at TIMESTAMP,
        delivered_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE INDEX IF NOT EXISTS idx_delivassign_boutique ON delivery_assignments(boutique_id)",
    "CREATE TABLE IF NOT EXISTS contact_roles (
        id VARCHAR(36) PRIMARY KEY,
        boutique_id VARCHAR(36) NOT NULL,
        name VARCHAR(100) NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS contacts (
        id VARCHAR(36) PRIMARY KEY,
        boutique_id VARCHAR(36) NOT NULL,
        role_id VARCHAR(36),
        name VARCHAR(150) NOT NULL,
        phone VARCHAR(30),
        email VARCHAR(190),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE INDEX IF NOT EXISTS idx_contacts_boutique ON contacts(boutique_id)",
    "CREATE TABLE IF NOT EXISTS accounts (
        id VARCHAR(36) PRIMARY KEY,
        boutique_id VARCHAR(36) NOT NULL,
        name VARCHAR(100) NOT NULL,
        type VARCHAR(20) DEFAULT 'caisse',
        balance DECIMAL(14,2) DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE INDEX IF NOT EXISTS idx_accounts_boutique ON accounts(boutique_id)",
    "CREATE TABLE IF NOT EXISTS account_transactions (
        id VARCHAR(36) PRIMARY KEY,
        account_id VARCHAR(36) NOT NULL,
        boutique_id VARCHAR(36) NOT NULL,
        type VARCHAR(10) NOT NULL,
        amount DECIMAL(14,2) NOT NULL,
        note TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE INDEX IF NOT EXISTS idx_accounttx_account ON account_transactions(account_id)",
    "CREATE TABLE IF NOT EXISTS delivery_fees_paid (
        id VARCHAR(36) PRIMARY KEY,
        boutique_id VARCHAR(36) NOT NULL,
        order_id VARCHAR(36),
        amount DECIMAL(14,2) NOT NULL,
        note TEXT,
        account_id VARCHAR(36),
        paid_at DATE DEFAULT CURRENT_DATE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE INDEX IF NOT EXISTS idx_deliveryfees_boutique ON delivery_fees_paid(boutique_id)",
    "CREATE TABLE IF NOT EXISTS expenses (
        id VARCHAR(36) PRIMARY KEY,
        boutique_id VARCHAR(36) NOT NULL,
        label VARCHAR(200) NOT NULL,
        category VARCHAR(60),
        amount DECIMAL(14,2) NOT NULL,
        account_id VARCHAR(36),
        expense_date DATE DEFAULT CURRENT_DATE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE INDEX IF NOT EXISTS idx_expenses_boutique ON expenses(boutique_id)",
    "CREATE TABLE IF NOT EXISTS ad_expenses (
        id VARCHAR(36) PRIMARY KEY,
        boutique_id VARCHAR(36) NOT NULL,
        campaign_name VARCHAR(150),
        product_id VARCHAR(36),
        amount DECIMAL(14,2) NOT NULL,
        spend_date DATE DEFAULT CURRENT_DATE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE INDEX IF NOT EXISTS idx_adexpenses_boutique ON ad_expenses(boutique_id)",
    "CREATE TABLE IF NOT EXISTS newsletter_subscribers (
        id VARCHAR(36) PRIMARY KEY,
        boutique_id VARCHAR(36) NOT NULL,
        email VARCHAR(190) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_newsletter_boutique_email ON newsletter_subscribers(boutique_id, email)",
    "CREATE TABLE IF NOT EXISTS contact_messages (
        id VARCHAR(36) PRIMARY KEY,
        boutique_id VARCHAR(36) NOT NULL,
        name VARCHAR(150),
        email VARCHAR(190),
        message TEXT,
        is_read SMALLINT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE INDEX IF NOT EXISTS idx_contactmsg_boutique ON contact_messages(boutique_id)",
    "CREATE TABLE IF NOT EXISTS visits (
        id SERIAL PRIMARY KEY,
        boutique_id VARCHAR(36) NOT NULL,
        session_id VARCHAR(64),
        path VARCHAR(255),
        referrer VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE INDEX IF NOT EXISTS idx_visits_boutique_created ON visits(boutique_id, created_at)",
    "CREATE TABLE IF NOT EXISTS activity_log (
        id SERIAL PRIMARY KEY,
        boutique_id VARCHAR(36) NOT NULL,
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE INDEX IF NOT EXISTS idx_activity_boutique_created ON activity_log(boutique_id, created_at)",
    "CREATE TABLE IF NOT EXISTS rate_limit_hits (
        id SERIAL PRIMARY KEY,
        bucket VARCHAR(50),
        ip_address VARCHAR(64),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    ];

    $created = [];
    foreach ($sqls as $sql) {
        try {
            db()->exec($sql);
            preg_match('/TABLE IF NOT EXISTS (\w+)/', $sql, $m);
            if (!empty($m[1])) $created[] = $m[1];
        } catch (Exception $e) {
            fail('Erreur SQL: '.$e->getMessage(), 500);
        }
    }

    ok(['tables_created'=>$created], 'Installation terminee ! Toutes les tables ont ete creees.');
}

// ============================================================
// AUTH — inscription, verification email, connexion
// ============================================================
function route_auth($action) {
    switch ($action) {
        case 'register': auth_register(); break;
        case 'verify':   auth_verify(); break;
        case 'resend':   auth_resend(); break;
        case 'login':    auth_login(); break;
        case 'me':       auth_me(); break;
        default: fail('Action inconnue', 404);
    }
}

function auth_register() {
    rate_limit_check('auth_register', 10, 300);
    $b = body();
    $email = strtolower(trim($b['email'] ?? ''));
    $password = (string)($b['password'] ?? '');
    $fullName = trim($b['full_name'] ?? '');
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) fail('Adresse email invalide');
    if (strlen($password) < 6) fail('Le mot de passe doit contenir au moins 6 caracteres');

    $exists = q("SELECT id FROM users WHERE email=?", [$email])->fetch();
    if ($exists) fail('Un compte existe deja avec cet email', 409);

    $id = uid();
    $token = bin2hex(random_bytes(24));
    q("INSERT INTO users (id,email,password_hash,full_name,verification_token,verification_sent_at)
       VALUES (?,?,?,?,?,NOW())",
      [$id, $email, password_hash($password, PASSWORD_DEFAULT), $fullName, $token]);

    $verifyLink = auth_verify_link($token);
    // Aucun envoi d'email reel branche pour l'instant (necessite une cle
    // d'un fournisseur transactionnel - Brevo/SendGrid/Resend/SMTP - a
    // fournir avant la mise en production). En attendant, le lien est
    // journalise cote serveur pour pouvoir tester le parcours complet.
    error_log('[MYBOUTIK] Lien de verification pour '.$email.' : '.$verifyLink);

    $data = ['email' => $email];
    if (APP_ENV === 'development') $data['verify_link_dev_only'] = $verifyLink;
    ok($data, 'Compte cree. Verifiez votre email pour activer votre compte.', 201);
}

function auth_verify_link($token) {
    // Construit un lien pointant vers la page d'accueil (index.html), qui
    // lit ?verify=TOKEN au chargement pour appeler auth?action=verify.
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    $base = $origin ?: '';
    return $base.'/?verify='.$token;
}

function auth_verify() {
    $token = bg('token');
    if (!$token) fail('Token manquant');
    $user = q("SELECT id FROM users WHERE verification_token=?", [$token])->fetch();
    if (!$user) fail('Lien de verification invalide ou deja utilise', 404);
    q("UPDATE users SET email_verified_at=NOW(), verification_token=NULL WHERE id=?", [$user['id']]);
    ok(null, 'Email verifie. Vous pouvez vous connecter.');
}

function auth_resend() {
    rate_limit_check('auth_resend', 5, 300);
    $email = strtolower(trim(bg('email','')));
    $user = q("SELECT id,email_verified_at FROM users WHERE email=?", [$email])->fetch();
    // Reponse volontairement identique que l'email existe ou non, pour ne
    // pas laisser deviner quels emails sont deja inscrits.
    if ($user && !$user['email_verified_at']) {
        $token = bin2hex(random_bytes(24));
        q("UPDATE users SET verification_token=?, verification_sent_at=NOW() WHERE id=?", [$token, $user['id']]);
        error_log('[MYBOUTIK] Lien de verification (renvoi) pour '.$email.' : '.auth_verify_link($token));
    }
    ok(null, 'Si un compte existe avec cet email, un nouveau lien vient d\'etre envoye.');
}

function auth_login() {
    rate_limit_check('auth_login', 20, 300);
    $b = body();
    $email = strtolower(trim($b['email'] ?? ''));
    $password = (string)($b['password'] ?? '');
    $user = q("SELECT * FROM users WHERE email=?", [$email])->fetch();
    if (!$user || !password_verify($password, $user['password_hash'])) fail('Email ou mot de passe incorrect', 401);
    if ($user['status'] !== 'active') fail('Compte suspendu ou bloque', 403);
    if (!$user['email_verified_at']) fail('Veuillez verifier votre email avant de vous connecter', 403);

    $token = jwt_make(['sub'=>$user['id'], 'typ'=>'owner']);
    ok(['token'=>$token, 'user'=>[
        'id'=>$user['id'], 'email'=>$user['email'], 'full_name'=>$user['full_name'],
    ]], 'Connecte');
}

function auth_me() {
    $pl = owner_auth();
    $user = q("SELECT id,email,full_name,created_at FROM users WHERE id=?", [$pl['sub']])->fetch();
    if (!$user) fail('Compte introuvable', 404);
    ok($user);
}

// ============================================================
// BOUTIQUES — creation et gestion multi-boutiques d'un proprietaire
// ============================================================
function route_boutiques($action) {
    $pl = owner_auth();
    switch ($action) {
        case 'list':   boutiques_list($pl); break;
        case 'create': boutiques_create($pl); break;
        case 'update': boutiques_update($pl); break;
        case 'get':    boutiques_get($pl); break;
        case 'grade':  boutiques_grade($pl); break;
        default: fail('Action inconnue', 404);
    }
}

function boutiques_list($pl) {
    $rows = q("SELECT * FROM boutiques WHERE owner_user_id=? ORDER BY created_at ASC", [$pl['sub']])->fetchAll();
    foreach ($rows as &$r) {
        $r['stats'] = boutique_quick_stats($r['id']);
    }
    ok($rows);
}

function boutique_quick_stats($boutiqueId) {
    $cmd = (int)q("SELECT COUNT(*) c FROM orders WHERE boutique_id=?", [$boutiqueId])->fetch()['c'];
    $enAttente = (int)q("SELECT COUNT(*) c FROM orders WHERE boutique_id=? AND status='pending'", [$boutiqueId])->fetch()['c'];
    $ca = (float)q("SELECT COALESCE(SUM(total),0) s FROM orders WHERE boutique_id=? AND status IN ".ENCAISSE_STATUSES, [$boutiqueId])->fetch()['s'];
    return ['commandes'=>$cmd, 'en_attente'=>$enAttente, 'ca_encaisse'=>$ca];
}

function boutiques_create($pl) {
    $b = body();
    $name = trim($b['name'] ?? '');
    if ($name === '') fail('Le nom de la boutique est requis');
    $slug = unique_boutique_slug(slugify($name));
    $id = uid();
    q("INSERT INTO boutiques (id,owner_user_id,slug,name) VALUES (?,?,?,?)", [$id, $pl['sub'], $slug, $name]);
    // Compte caisse par defaut, pour que le Livre de Compte ne soit pas vide
    // des la creation (l'utilisateur peut le renommer/en ajouter d'autres).
    q("INSERT INTO accounts (id,boutique_id,name,type) VALUES (?,?,?,?)", [uid(), $id, 'Caisse', 'caisse']);
    q("INSERT INTO abandoned_settings (boutique_id) VALUES (?)", [$id]);
    log_activity($id, 'Boutique creee');
    $row = q("SELECT * FROM boutiques WHERE id=?", [$id])->fetch();
    ok($row, 'Boutique creee', 201);
}

function boutiques_update($pl) {
    $b = body();
    $id = $b['id'] ?? '';
    $row = require_boutique_owned($id, $pl['sub']);
    $name = trim($b['name'] ?? $row['name']);
    $codEnabled = isset($b['cod_enabled']) ? (int)!!$b['cod_enabled'] : $row['cod_enabled'];
    $currency = trim($b['currency'] ?? $row['currency']);
    q("UPDATE boutiques SET name=?, cod_enabled=?, currency=? WHERE id=?", [$name, $codEnabled, $currency, $id]);
    ok(q("SELECT * FROM boutiques WHERE id=?", [$id])->fetch(), 'Boutique mise a jour');
}

function boutiques_get($pl) {
    $row = require_boutique_owned($_GET['id'] ?? '', $pl['sub']);
    $row['stats'] = boutique_quick_stats($row['id']);
    ok($row);
}

function boutiques_grade($pl) {
    $row = require_boutique_owned($_GET['boutique_id'] ?? '', $pl['sub']);
    $total = (float)q("SELECT COALESCE(SUM(total),0) s FROM orders WHERE boutique_id=? AND status IN ".ENCAISSE_STATUSES, [$row['id']])->fetch()['s'];
    ok(compute_grade($total));
}

// ============================================================
// PRODUITS — catalogue, variantes, stock, fournisseurs
// ============================================================
function route_products($action) {
    $pl = owner_auth();
    switch ($action) {
        case 'list':   products_list($pl); break;
        case 'get':    products_get($pl); break;
        case 'create': products_create($pl); break;
        case 'update': products_update($pl); break;
        case 'delete': products_delete($pl); break;
        case 'stock_adjust': products_stock_adjust($pl); break;
        case 'suppliers_list':   suppliers_list($pl); break;
        case 'supplier_create':  supplier_create($pl); break;
        case 'supplier_update':  supplier_update($pl); break;
        case 'supplier_delete':  supplier_delete($pl); break;
        case 'supplier_orders_list':  supplier_orders_list($pl); break;
        case 'supplier_order_create': supplier_order_create($pl); break;
        case 'supplier_order_update_status': supplier_order_update_status($pl); break;
        default: fail('Action inconnue', 404);
    }
}

function products_list($pl) {
    $row = require_boutique_owned($_GET['boutique_id'] ?? '', $pl['sub']);
    $rows = q("SELECT * FROM products WHERE boutique_id=? ORDER BY created_at DESC", [$row['id']])->fetchAll();
    foreach ($rows as &$p) {
        $p['variants'] = q("SELECT * FROM product_variants WHERE product_id=? ORDER BY name", [$p['id']])->fetchAll();
    }
    ok($rows);
}

function product_owned($id, $boutiqueId) {
    $p = q("SELECT * FROM products WHERE id=? AND boutique_id=?", [$id, $boutiqueId])->fetch();
    if (!$p) fail('Produit introuvable', 404);
    return $p;
}

function products_get($pl) {
    $bt = require_boutique_owned($_GET['boutique_id'] ?? '', $pl['sub']);
    $p = product_owned($_GET['id'] ?? '', $bt['id']);
    $p['variants'] = q("SELECT * FROM product_variants WHERE product_id=? ORDER BY name", [$p['id']])->fetchAll();
    ok($p);
}

function products_create($pl) {
    $b = body();
    $bt = require_boutique_owned($b['boutique_id'] ?? '', $pl['sub']);
    $name = trim($b['name'] ?? '');
    if ($name === '') fail('Le nom du produit est requis');
    $id = uid();
    q("INSERT INTO products (id,boutique_id,name,description,price,cost_price,stock_qty,image_url,status)
       VALUES (?,?,?,?,?,?,?,?,?)",
      [$id, $bt['id'], $name, trim($b['description'] ?? ''), (float)($b['price'] ?? 0),
       isset($b['cost_price']) && $b['cost_price'] !== '' ? (float)$b['cost_price'] : null,
       (int)($b['stock_qty'] ?? 0), trim($b['image_url'] ?? ''), $b['status'] ?? 'draft']);
    foreach (($b['variants'] ?? []) as $v) {
        if (trim($v['name'] ?? '') === '') continue;
        q("INSERT INTO product_variants (id,product_id,name,price,stock_qty) VALUES (?,?,?,?,?)",
          [uid(), $id, trim($v['name']), isset($v['price']) && $v['price']!=='' ? (float)$v['price'] : null, (int)($v['stock_qty'] ?? 0)]);
    }
    log_activity($bt['id'], 'Produit ajoute: '.$name);
    ok(q("SELECT * FROM products WHERE id=?", [$id])->fetch(), 'Produit cree', 201);
}

function products_update($pl) {
    $b = body();
    $bt = require_boutique_owned($b['boutique_id'] ?? '', $pl['sub']);
    $p = product_owned($b['id'] ?? '', $bt['id']);
    $name = trim($b['name'] ?? $p['name']);
    q("UPDATE products SET name=?, description=?, price=?, cost_price=?, stock_qty=?, image_url=?, status=? WHERE id=?",
      [$name, trim($b['description'] ?? $p['description']), (float)($b['price'] ?? $p['price']),
       isset($b['cost_price']) && $b['cost_price'] !== '' ? (float)$b['cost_price'] : $p['cost_price'],
       (int)($b['stock_qty'] ?? $p['stock_qty']), trim($b['image_url'] ?? $p['image_url']),
       $b['status'] ?? $p['status'], $p['id']]);
    ok(q("SELECT * FROM products WHERE id=?", [$p['id']])->fetch(), 'Produit mis a jour');
}

function products_delete($pl) {
    $b = body();
    $bt = require_boutique_owned($b['boutique_id'] ?? '', $pl['sub']);
    $p = product_owned($b['id'] ?? '', $bt['id']);
    q("DELETE FROM product_variants WHERE product_id=?", [$p['id']]);
    q("DELETE FROM products WHERE id=?", [$p['id']]);
    ok(null, 'Produit supprime');
}

function products_stock_adjust($pl) {
    $b = body();
    $bt = require_boutique_owned($b['boutique_id'] ?? '', $pl['sub']);
    $p = product_owned($b['id'] ?? '', $bt['id']);
    $delta = (int)($b['delta'] ?? 0);
    q("UPDATE products SET stock_qty = stock_qty + ? WHERE id=?", [$delta, $p['id']]);
    ok(q("SELECT * FROM products WHERE id=?", [$p['id']])->fetch(), 'Stock ajuste');
}

function suppliers_list($pl) {
    $bt = require_boutique_owned($_GET['boutique_id'] ?? '', $pl['sub']);
    ok(q("SELECT * FROM suppliers WHERE boutique_id=? ORDER BY name", [$bt['id']])->fetchAll());
}
function supplier_create($pl) {
    $b = body();
    $bt = require_boutique_owned($b['boutique_id'] ?? '', $pl['sub']);
    $name = trim($b['name'] ?? '');
    if ($name === '') fail('Le nom du fournisseur est requis');
    $id = uid();
    q("INSERT INTO suppliers (id,boutique_id,name,phone,notes) VALUES (?,?,?,?,?)",
      [$id, $bt['id'], $name, trim($b['phone'] ?? ''), trim($b['notes'] ?? '')]);
    ok(q("SELECT * FROM suppliers WHERE id=?", [$id])->fetch(), 'Fournisseur ajoute', 201);
}
function supplier_owned($id, $boutiqueId) {
    $s = q("SELECT * FROM suppliers WHERE id=? AND boutique_id=?", [$id, $boutiqueId])->fetch();
    if (!$s) fail('Fournisseur introuvable', 404);
    return $s;
}
function supplier_update($pl) {
    $b = body();
    $bt = require_boutique_owned($b['boutique_id'] ?? '', $pl['sub']);
    $s = supplier_owned($b['id'] ?? '', $bt['id']);
    q("UPDATE suppliers SET name=?, phone=?, notes=? WHERE id=?",
      [trim($b['name'] ?? $s['name']), trim($b['phone'] ?? $s['phone']), trim($b['notes'] ?? $s['notes']), $s['id']]);
    ok(q("SELECT * FROM suppliers WHERE id=?", [$s['id']])->fetch(), 'Fournisseur mis a jour');
}
function supplier_delete($pl) {
    $b = body();
    $bt = require_boutique_owned($b['boutique_id'] ?? '', $pl['sub']);
    $s = supplier_owned($b['id'] ?? '', $bt['id']);
    q("DELETE FROM suppliers WHERE id=?", [$s['id']]);
    ok(null, 'Fournisseur supprime');
}

function supplier_orders_list($pl) {
    $bt = require_boutique_owned($_GET['boutique_id'] ?? '', $pl['sub']);
    $rows = q("SELECT so.*, s.name AS supplier_name, p.name AS product_name
               FROM supplier_orders so
               LEFT JOIN suppliers s ON s.id = so.supplier_id
               LEFT JOIN products p ON p.id = so.product_id
               WHERE so.boutique_id=? ORDER BY so.created_at DESC", [$bt['id']])->fetchAll();
    ok($rows);
}
function supplier_order_create($pl) {
    $b = body();
    $bt = require_boutique_owned($b['boutique_id'] ?? '', $pl['sub']);
    supplier_owned($b['supplier_id'] ?? '', $bt['id']);
    $id = uid();
    q("INSERT INTO supplier_orders (id,boutique_id,supplier_id,product_id,qty,unit_cost,status)
       VALUES (?,?,?,?,?,?,?)",
      [$id, $bt['id'], $b['supplier_id'], $b['product_id'] ?? null, (int)($b['qty'] ?? 1),
       (float)($b['unit_cost'] ?? 0), 'pending']);
    ok(q("SELECT * FROM supplier_orders WHERE id=?", [$id])->fetch(), 'Commande fournisseur creee', 201);
}
function supplier_order_update_status($pl) {
    $b = body();
    $bt = require_boutique_owned($b['boutique_id'] ?? '', $pl['sub']);
    $so = q("SELECT * FROM supplier_orders WHERE id=? AND boutique_id=?", [$b['id'] ?? '', $bt['id']])->fetch();
    if (!$so) fail('Commande fournisseur introuvable', 404);
    $status = $b['status'] ?? $so['status'];
    q("UPDATE supplier_orders SET status=? WHERE id=?", [$status, $so['id']]);
    // Une commande fournisseur marquee "received" reapprovisionne le stock.
    if ($status === 'received' && $so['status'] !== 'received' && $so['product_id']) {
        q("UPDATE products SET stock_qty = stock_qty + ? WHERE id=?", [$so['qty'], $so['product_id']]);
    }
    ok(q("SELECT * FROM supplier_orders WHERE id=?", [$so['id']])->fetch(), 'Statut mis a jour');
}

// ============================================================
// VITRINE PUBLIQUE (module "shop") — aucune authentification, utilisee par
// store/index.html : catalogue, fiche produit, commande COD, capture des
// paniers abandonnes, newsletter, formulaire de contact.
// ============================================================
function route_shop($action) {
    switch ($action) {
        case 'boutique':         shop_boutique(); break;
        case 'products':         shop_products(); break;
        case 'product':          shop_product(); break;
        case 'checkout':         shop_checkout(); break;
        case 'track_visit':      shop_track_visit(); break;
        case 'track_abandoned':  shop_track_abandoned(); break;
        case 'newsletter':       shop_newsletter(); break;
        case 'contact_message':  shop_contact_message(); break;
        default: fail('Action inconnue', 404);
    }
}

function public_boutique_by_slug($slug) {
    $row = q("SELECT id,slug,name,currency,cod_enabled,status FROM boutiques WHERE slug=?", [$slug])->fetch();
    if (!$row || $row['status'] !== 'active') fail('Boutique introuvable', 404);
    return $row;
}

function shop_boutique() {
    ok(public_boutique_by_slug($_GET['slug'] ?? ''));
}

function shop_products() {
    $bt = public_boutique_by_slug($_GET['slug'] ?? '');
    $rows = q("SELECT id,name,description,price,stock_qty,image_url FROM products
               WHERE boutique_id=? AND status='active' ORDER BY created_at DESC", [$bt['id']])->fetchAll();
    foreach ($rows as &$p) {
        $p['variants'] = q("SELECT id,name,price,stock_qty FROM product_variants WHERE product_id=? ORDER BY name", [$p['id']])->fetchAll();
    }
    ok($rows);
}

function shop_product() {
    $bt = public_boutique_by_slug($_GET['slug'] ?? '');
    $p = q("SELECT id,name,description,price,stock_qty,image_url FROM products
            WHERE id=? AND boutique_id=? AND status='active'", [$_GET['id'] ?? '', $bt['id']])->fetch();
    if (!$p) fail('Produit introuvable', 404);
    $p['variants'] = q("SELECT id,name,price,stock_qty FROM product_variants WHERE product_id=? ORDER BY name", [$p['id']])->fetchAll();
    ok($p);
}

// Commande a la livraison : cree/retrouve le client par telephone, cree la
// commande + ses lignes, decremente le stock. Tout dans une transaction
// pour ne jamais laisser une commande a moitie ecrite en cas d'erreur.
function shop_checkout() {
    rate_limit_check('shop_checkout', 20, 300);
    $b = body();
    $bt = public_boutique_by_slug($b['slug'] ?? '');
    if (!$bt['cod_enabled']) fail('Le paiement a la livraison n\'est pas active pour cette boutique', 400);
    $customer = $b['customer'] ?? [];
    $name = trim($customer['name'] ?? '');
    $phone = trim($customer['phone'] ?? '');
    $address = trim($customer['address'] ?? '');
    $items = $b['items'] ?? [];
    if ($name === '' || $phone === '') fail('Nom et telephone requis');
    if (!is_array($items) || count($items) === 0) fail('Le panier est vide');

    $pdo = db();
    $pdo->beginTransaction();
    try {
        $customerRow = q("SELECT id FROM customers WHERE boutique_id=? AND phone=?", [$bt['id'], $phone])->fetch();
        if ($customerRow) {
            $customerId = $customerRow['id'];
            q("UPDATE customers SET name=?, address=? WHERE id=?", [$name, $address, $customerId]);
        } else {
            $customerId = uid();
            q("INSERT INTO customers (id,boutique_id,name,phone,email,address) VALUES (?,?,?,?,?,?)",
              [$customerId, $bt['id'], $name, $phone, trim($customer['email'] ?? ''), $address]);
        }

        $subtotal = 0;
        $lineData = [];
        foreach ($items as $it) {
            $productId = $it['product_id'] ?? '';
            $qty = max(1, (int)($it['qty'] ?? 1));
            $product = q("SELECT * FROM products WHERE id=? AND boutique_id=? AND status='active'", [$productId, $bt['id']])->fetch();
            if (!$product) throw new Exception('Produit indisponible');
            $variant = null;
            if (!empty($it['variant_id'])) {
                $variant = q("SELECT * FROM product_variants WHERE id=? AND product_id=?", [$it['variant_id'], $productId])->fetch();
            }
            $unitPrice = $variant && $variant['price'] !== null ? (float)$variant['price'] : (float)$product['price'];
            $available = $variant ? (int)$variant['stock_qty'] : (int)$product['stock_qty'];
            if ($available < $qty) throw new Exception('Stock insuffisant pour '.$product['name']);
            $subtotal += $unitPrice * $qty;
            $lineData[] = [
                'product' => $product, 'variant' => $variant, 'qty' => $qty, 'unit_price' => $unitPrice,
            ];
        }
        $deliveryFee = max(0, (float)($b['delivery_fee'] ?? 0));
        $total = $subtotal + $deliveryFee;

        $orderId = uid();
        $ref = order_ref();
        q("INSERT INTO orders (id,boutique_id,customer_id,ref,status,payment_method,subtotal,delivery_fee_charged,total,
           customer_name,customer_phone,customer_address,utm_source,utm_campaign)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
          [$orderId, $bt['id'], $customerId, $ref, 'pending', 'cod', $subtotal, $deliveryFee, $total,
           $name, $phone, $address, trim($b['utm_source'] ?? ''), trim($b['utm_campaign'] ?? '')]);

        foreach ($lineData as $l) {
            q("INSERT INTO order_items (id,order_id,product_id,product_name,variant_id,unit_price,unit_cost,qty)
               VALUES (?,?,?,?,?,?,?,?)",
              [uid(), $orderId, $l['product']['id'],
               $l['product']['name'].($l['variant'] ? ' - '.$l['variant']['name'] : ''),
               $l['variant']['id'] ?? null, $l['unit_price'], $l['product']['cost_price'] ?? 0, $l['qty']]);
            if ($l['variant']) {
                q("UPDATE product_variants SET stock_qty = stock_qty - ? WHERE id=?", [$l['qty'], $l['variant']['id']]);
            } else {
                q("UPDATE products SET stock_qty = stock_qty - ? WHERE id=?", [$l['qty'], $l['product']['id']]);
            }
        }
        q("INSERT INTO delivery_assignments (id,order_id,boutique_id,status) VALUES (?,?,?,?)",
          [uid(), $orderId, $bt['id'], 'to_assign']);

        if (!empty($b['session_id'])) {
            q("UPDATE abandoned_carts SET converted=1 WHERE boutique_id=? AND session_id=? AND converted=0",
              [$bt['id'], $b['session_id']]);
        }

        $pdo->commit();
        log_activity($bt['id'], 'Nouvelle commande '.$ref.' ('.$name.')');
        ok(['ref'=>$ref, 'order_id'=>$orderId, 'total'=>$total], 'Commande enregistree', 201);
    } catch (Exception $e) {
        $pdo->rollBack();
        fail($e->getMessage(), 400);
    }
}

function shop_track_visit() {
    $b = body();
    $bt = public_boutique_by_slug($b['slug'] ?? '');
    q("INSERT INTO visits (boutique_id,session_id,path,referrer) VALUES (?,?,?,?)",
      [$bt['id'], substr(trim($b['session_id'] ?? ''),0,64), substr(trim($b['path'] ?? ''),0,255), substr(trim($b['referrer'] ?? ''),0,255)]);
    ok(null);
}

function shop_track_abandoned() {
    $b = body();
    $bt = public_boutique_by_slug($b['slug'] ?? '');
    $settings = q("SELECT * FROM abandoned_settings WHERE boutique_id=?", [$bt['id']])->fetch();
    if ($settings && !$settings['capture_enabled']) ok(null);
    $sessionId = trim($b['session_id'] ?? '');
    $phone = trim($b['phone'] ?? '');
    $email = trim($b['email'] ?? '');
    if ($phone === '' && $email === '') fail('Aucune information a capturer');
    $existing = $sessionId ? q("SELECT id FROM abandoned_carts WHERE boutique_id=? AND session_id=? AND converted=0",
        [$bt['id'], $sessionId])->fetch() : null;
    $cartJson = json_encode($b['cart'] ?? [], JSON_UNESCAPED_UNICODE);
    $total = (float)($b['total'] ?? 0);
    if ($existing) {
        q("UPDATE abandoned_carts SET phone=?, email=?, cart_snapshot=?, total=?, captured_at=NOW() WHERE id=?",
          [$phone, $email, $cartJson, $total, $existing['id']]);
    } else {
        q("INSERT INTO abandoned_carts (id,boutique_id,session_id,phone,email,cart_snapshot,total)
           VALUES (?,?,?,?,?,?,?)", [uid(), $bt['id'], $sessionId, $phone, $email, $cartJson, $total]);
    }
    ok(null);
}

function shop_newsletter() {
    $b = body();
    $bt = public_boutique_by_slug($b['slug'] ?? '');
    $email = strtolower(trim($b['email'] ?? ''));
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) fail('Adresse email invalide');
    q("INSERT INTO newsletter_subscribers (id,boutique_id,email) VALUES (?,?,?) ON CONFLICT (boutique_id,email) DO NOTHING",
      [uid(), $bt['id'], $email]);
    ok(null, 'Inscription confirmee');
}

function shop_contact_message() {
    rate_limit_check('shop_contact', 10, 300);
    $b = body();
    $bt = public_boutique_by_slug($b['slug'] ?? '');
    $message = trim($b['message'] ?? '');
    if ($message === '') fail('Le message ne peut pas etre vide');
    q("INSERT INTO contact_messages (id,boutique_id,name,email,message) VALUES (?,?,?,?,?)",
      [uid(), $bt['id'], trim($b['name'] ?? ''), trim($b['email'] ?? ''), $message]);
    ok(null, 'Message envoye');
}

// ============================================================
// COMMANDES — gestion cote marchand (liste, statut, creation manuelle) +
// commandes abandonnees
// ============================================================
function route_orders($action) {
    $pl = owner_auth();
    switch ($action) {
        case 'list':               orders_list($pl); break;
        case 'get':                orders_get($pl); break;
        case 'create':              orders_create_manual($pl); break;
        case 'update_status':       orders_update_status($pl); break;
        case 'abandoned_list':      abandoned_list($pl); break;
        case 'abandoned_mark':      abandoned_mark($pl); break;
        case 'abandoned_settings_get':  abandoned_settings_get($pl); break;
        case 'abandoned_settings_save': abandoned_settings_save($pl); break;
        default: fail('Action inconnue', 404);
    }
}

function order_owned($id, $boutiqueId) {
    $o = q("SELECT * FROM orders WHERE id=? AND boutique_id=?", [$id, $boutiqueId])->fetch();
    if (!$o) fail('Commande introuvable', 404);
    return $o;
}

function orders_list($pl) {
    $bt = require_boutique_owned($_GET['boutique_id'] ?? '', $pl['sub']);
    $status = $_GET['status'] ?? '';
    $qStr = trim($_GET['q'] ?? '');
    $sql = "SELECT * FROM orders WHERE boutique_id=?";
    $params = [$bt['id']];
    if ($status !== '' && $status !== 'all') { $sql .= " AND status=?"; $params[] = $status; }
    if ($qStr !== '') {
        $sql .= " AND (ref ILIKE ? OR customer_name ILIKE ? OR customer_phone ILIKE ?)";
        $like = '%'.$qStr.'%'; array_push($params, $like, $like, $like);
    }
    $sql .= " ORDER BY created_at DESC LIMIT 500";
    $rows = q($sql, $params)->fetchAll();
    ok($rows);
}

function orders_get($pl) {
    $bt = require_boutique_owned($_GET['boutique_id'] ?? '', $pl['sub']);
    $o = order_owned($_GET['id'] ?? '', $bt['id']);
    $o['items'] = q("SELECT * FROM order_items WHERE order_id=?", [$o['id']])->fetchAll();
    $o['delivery'] = q("SELECT * FROM delivery_assignments WHERE order_id=?", [$o['id']])->fetch();
    ok($o);
}

function orders_create_manual($pl) {
    $b = body();
    $bt = require_boutique_owned($b['boutique_id'] ?? '', $pl['sub']);
    $name = trim($b['customer_name'] ?? '');
    $phone = trim($b['customer_phone'] ?? '');
    $items = $b['items'] ?? [];
    if ($name === '' || $phone === '') fail('Nom et telephone du client requis');
    if (!is_array($items) || count($items) === 0) fail('Ajoutez au moins un produit');

    $customerRow = q("SELECT id FROM customers WHERE boutique_id=? AND phone=?", [$bt['id'], $phone])->fetch();
    if ($customerRow) {
        $customerId = $customerRow['id'];
        q("UPDATE customers SET name=?, address=? WHERE id=?", [$name, trim($b['customer_address'] ?? ''), $customerId]);
    } else {
        $customerId = uid();
        q("INSERT INTO customers (id,boutique_id,name,phone,address) VALUES (?,?,?,?,?)",
          [$customerId, $bt['id'], $name, $phone, trim($b['customer_address'] ?? '')]);
    }

    $subtotal = 0; $lineData = [];
    foreach ($items as $it) {
        $product = product_owned($it['product_id'] ?? '', $bt['id']);
        $qty = max(1, (int)($it['qty'] ?? 1));
        $unitPrice = isset($it['unit_price']) ? (float)$it['unit_price'] : (float)$product['price'];
        $subtotal += $unitPrice * $qty;
        $lineData[] = ['product'=>$product, 'qty'=>$qty, 'unit_price'=>$unitPrice];
    }
    $deliveryFee = max(0, (float)($b['delivery_fee'] ?? 0));
    $total = $subtotal + $deliveryFee;
    $orderId = uid(); $ref = order_ref();
    q("INSERT INTO orders (id,boutique_id,customer_id,ref,status,payment_method,subtotal,delivery_fee_charged,total,
       customer_name,customer_phone,customer_address) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
      [$orderId, $bt['id'], $customerId, $ref, 'pending', 'cod', $subtotal, $deliveryFee, $total,
       $name, $phone, trim($b['customer_address'] ?? '')]);
    foreach ($lineData as $l) {
        q("INSERT INTO order_items (id,order_id,product_id,product_name,unit_price,unit_cost,qty) VALUES (?,?,?,?,?,?,?)",
          [uid(), $orderId, $l['product']['id'], $l['product']['name'], $l['unit_price'], $l['product']['cost_price'] ?? 0, $l['qty']]);
        q("UPDATE products SET stock_qty = stock_qty - ? WHERE id=?", [$l['qty'], $l['product']['id']]);
    }
    q("INSERT INTO delivery_assignments (id,order_id,boutique_id,status) VALUES (?,?,?,?)", [uid(), $orderId, $bt['id'], 'to_assign']);
    log_activity($bt['id'], 'Commande manuelle creee '.$ref);
    ok(q("SELECT * FROM orders WHERE id=?", [$orderId])->fetch(), 'Commande creee', 201);
}

function orders_update_status($pl) {
    $b = body();
    $bt = require_boutique_owned($b['boutique_id'] ?? '', $pl['sub']);
    $o = order_owned($b['id'] ?? '', $bt['id']);
    $status = $b['status'] ?? '';
    $allowed = ['pending','processing','shipped','delivered','refused','cancelled'];
    if (!in_array($status, $allowed, true)) fail('Statut invalide');
    if ($status === 'delivered') {
        q("UPDATE orders SET status=?, delivered_at=NOW() WHERE id=?", [$status, $o['id']]);
    } else {
        q("UPDATE orders SET status=? WHERE id=?", [$status, $o['id']]);
    }
    log_activity($bt['id'], 'Commande '.$o['ref'].' -> '.$status);
    ok(q("SELECT * FROM orders WHERE id=?", [$o['id']])->fetch(), 'Statut mis a jour');
}

function abandoned_list($pl) {
    $bt = require_boutique_owned($_GET['boutique_id'] ?? '', $pl['sub']);
    $filter = $_GET['filter'] ?? 'abandoned';
    $sql = "SELECT * FROM abandoned_carts WHERE boutique_id=?";
    $params = [$bt['id']];
    if ($filter === 'abandoned') { $sql .= " AND converted=0"; }
    elseif ($filter === 'converted') { $sql .= " AND converted=1"; }
    $sql .= " ORDER BY captured_at DESC LIMIT 500";
    ok(q($sql, $params)->fetchAll());
}
function abandoned_mark($pl) {
    $b = body();
    $bt = require_boutique_owned($b['boutique_id'] ?? '', $pl['sub']);
    $row = q("SELECT id FROM abandoned_carts WHERE id=? AND boutique_id=?", [$b['id'] ?? '', $bt['id']])->fetch();
    if (!$row) fail('Introuvable', 404);
    q("UPDATE abandoned_carts SET converted=? WHERE id=?", [(int)!!($b['converted'] ?? true), $row['id']]);
    ok(null, 'Mis a jour');
}
function abandoned_settings_get($pl) {
    $bt = require_boutique_owned($_GET['boutique_id'] ?? '', $pl['sub']);
    $row = q("SELECT * FROM abandoned_settings WHERE boutique_id=?", [$bt['id']])->fetch();
    ok($row ?: ['boutique_id'=>$bt['id'],'capture_enabled'=>1,'timeout_minutes'=>15,'email_alert'=>0]);
}
function abandoned_settings_save($pl) {
    $b = body();
    $bt = require_boutique_owned($b['boutique_id'] ?? '', $pl['sub']);
    q("INSERT INTO abandoned_settings (boutique_id,capture_enabled,timeout_minutes,email_alert) VALUES (?,?,?,?)
       ON CONFLICT (boutique_id) DO UPDATE SET capture_enabled=EXCLUDED.capture_enabled,
       timeout_minutes=EXCLUDED.timeout_minutes, email_alert=EXCLUDED.email_alert",
      [$bt['id'], (int)!!($b['capture_enabled'] ?? 1), (int)($b['timeout_minutes'] ?? 15), (int)!!($b['email_alert'] ?? 0)]);
    ok(null, 'Reglages enregistres');
}

// ============================================================
// LIVRAISONS — livreurs et suivi de la livraison de chaque commande
// ============================================================
function route_deliveries($action) {
    $pl = owner_auth();
    switch ($action) {
        case 'list':           deliveries_list($pl); break;
        case 'persons':        delivery_persons_list($pl); break;
        case 'person_create':  delivery_person_create($pl); break;
        case 'person_update':  delivery_person_update($pl); break;
        case 'person_delete':  delivery_person_delete($pl); break;
        case 'assign':         delivery_assign($pl); break;
        case 'update_status':  delivery_update_status($pl); break;
        default: fail('Action inconnue', 404);
    }
}

function deliveries_list($pl) {
    $bt = require_boutique_owned($_GET['boutique_id'] ?? '', $pl['sub']);
    $status = $_GET['status'] ?? '';
    $sql = "SELECT da.*, o.ref, o.customer_name, o.customer_phone, o.customer_address, o.total,
                   dp.name AS delivery_person_name, dp.phone AS delivery_person_phone
            FROM delivery_assignments da
            JOIN orders o ON o.id = da.order_id
            LEFT JOIN delivery_persons dp ON dp.id = da.delivery_person_id
            WHERE da.boutique_id=?";
    $params = [$bt['id']];
    if ($status !== '' && $status !== 'all') { $sql .= " AND da.status=?"; $params[] = $status; }
    $sql .= " ORDER BY da.created_at DESC LIMIT 500";
    ok(q($sql, $params)->fetchAll());
}

function delivery_persons_list($pl) {
    $bt = require_boutique_owned($_GET['boutique_id'] ?? '', $pl['sub']);
    ok(q("SELECT * FROM delivery_persons WHERE boutique_id=? ORDER BY active DESC, name", [$bt['id']])->fetchAll());
}
function delivery_person_create($pl) {
    $b = body();
    $bt = require_boutique_owned($b['boutique_id'] ?? '', $pl['sub']);
    $name = trim($b['name'] ?? '');
    if ($name === '') fail('Le nom du livreur est requis');
    $id = uid();
    q("INSERT INTO delivery_persons (id,boutique_id,name,phone) VALUES (?,?,?,?)", [$id, $bt['id'], $name, trim($b['phone'] ?? '')]);
    ok(q("SELECT * FROM delivery_persons WHERE id=?", [$id])->fetch(), 'Livreur ajoute', 201);
}
function delivery_person_owned($id, $boutiqueId) {
    $row = q("SELECT * FROM delivery_persons WHERE id=? AND boutique_id=?", [$id, $boutiqueId])->fetch();
    if (!$row) fail('Livreur introuvable', 404);
    return $row;
}
function delivery_person_update($pl) {
    $b = body();
    $bt = require_boutique_owned($b['boutique_id'] ?? '', $pl['sub']);
    $row = delivery_person_owned($b['id'] ?? '', $bt['id']);
    q("UPDATE delivery_persons SET name=?, phone=?, active=? WHERE id=?",
      [trim($b['name'] ?? $row['name']), trim($b['phone'] ?? $row['phone']), isset($b['active']) ? (int)!!$b['active'] : $row['active'], $row['id']]);
    ok(q("SELECT * FROM delivery_persons WHERE id=?", [$row['id']])->fetch(), 'Livreur mis a jour');
}
function delivery_person_delete($pl) {
    $b = body();
    $bt = require_boutique_owned($b['boutique_id'] ?? '', $pl['sub']);
    $row = delivery_person_owned($b['id'] ?? '', $bt['id']);
    q("UPDATE delivery_persons SET active=0 WHERE id=?", [$row['id']]);
    ok(null, 'Livreur desactive');
}

function delivery_assign($pl) {
    $b = body();
    $bt = require_boutique_owned($b['boutique_id'] ?? '', $pl['sub']);
    $o = order_owned($b['order_id'] ?? '', $bt['id']);
    delivery_person_owned($b['delivery_person_id'] ?? '', $bt['id']);
    q("UPDATE delivery_assignments SET delivery_person_id=?, status='assigned', assigned_at=NOW() WHERE order_id=?",
      [$b['delivery_person_id'], $o['id']]);
    q("UPDATE orders SET status='processing' WHERE id=? AND status='pending'", [$o['id']]);
    log_activity($bt['id'], 'Commande '.$o['ref'].' assignee a un livreur');
    ok(q("SELECT * FROM delivery_assignments WHERE order_id=?", [$o['id']])->fetch(), 'Commande assignee');
}

function delivery_update_status($pl) {
    $b = body();
    $bt = require_boutique_owned($b['boutique_id'] ?? '', $pl['sub']);
    $o = order_owned($b['order_id'] ?? '', $bt['id']);
    $status = $b['status'] ?? '';
    $allowed = ['to_assign','assigned','in_delivery','delivered','refused'];
    if (!in_array($status, $allowed, true)) fail('Statut invalide');
    if ($status === 'delivered') {
        q("UPDATE delivery_assignments SET status=?, delivered_at=NOW() WHERE order_id=?", [$status, $o['id']]);
        q("UPDATE orders SET status='delivered', delivered_at=NOW() WHERE id=?", [$o['id']]);
    } else {
        q("UPDATE delivery_assignments SET status=? WHERE order_id=?", [$status, $o['id']]);
        if ($status === 'refused') q("UPDATE orders SET status='refused' WHERE id=?", [$o['id']]);
        if ($status === 'in_delivery') q("UPDATE orders SET status='shipped' WHERE id=?", [$o['id']]);
    }
    log_activity($bt['id'], 'Livraison '.$o['ref'].' -> '.$status);
    ok(q("SELECT * FROM delivery_assignments WHERE order_id=?", [$o['id']])->fetch(), 'Statut mis a jour');
}

// ============================================================
// CLIENTS (derives des commandes) + CARNET D'ADRESSES (contacts internes)
// ============================================================
function route_customers($action) {
    $pl = owner_auth();
    switch ($action) {
        case 'list': customers_list($pl); break;
        case 'get':  customers_get($pl); break;
        default: fail('Action inconnue', 404);
    }
}
function customers_list($pl) {
    $bt = require_boutique_owned($_GET['boutique_id'] ?? '', $pl['sub']);
    $qStr = trim($_GET['q'] ?? '');
    $sql = "SELECT c.*, COUNT(o.id) AS orders_count, COALESCE(SUM(CASE WHEN o.status IN ".ENCAISSE_STATUSES." THEN o.total ELSE 0 END),0) AS total_spent
            FROM customers c LEFT JOIN orders o ON o.customer_id = c.id
            WHERE c.boutique_id=?";
    $params = [$bt['id']];
    if ($qStr !== '') { $sql .= " AND (c.name ILIKE ? OR c.phone ILIKE ? OR c.email ILIKE ?)"; $like='%'.$qStr.'%'; array_push($params,$like,$like,$like); }
    $sql .= " GROUP BY c.id ORDER BY c.created_at DESC LIMIT 500";
    ok(q($sql, $params)->fetchAll());
}
function customers_get($pl) {
    $bt = require_boutique_owned($_GET['boutique_id'] ?? '', $pl['sub']);
    $c = q("SELECT * FROM customers WHERE id=? AND boutique_id=?", [$_GET['id'] ?? '', $bt['id']])->fetch();
    if (!$c) fail('Client introuvable', 404);
    $c['orders'] = q("SELECT * FROM orders WHERE customer_id=? ORDER BY created_at DESC", [$c['id']])->fetchAll();
    ok($c);
}

function route_contacts($action) {
    $pl = owner_auth();
    switch ($action) {
        case 'roles':        contact_roles_list($pl); break;
        case 'role_create':  contact_role_create($pl); break;
        case 'list':         contacts_list($pl); break;
        case 'create':       contacts_create($pl); break;
        case 'update':       contacts_update($pl); break;
        case 'delete':       contacts_delete($pl); break;
        default: fail('Action inconnue', 404);
    }
}
function contact_roles_list($pl) {
    $bt = require_boutique_owned($_GET['boutique_id'] ?? '', $pl['sub']);
    ok(q("SELECT * FROM contact_roles WHERE boutique_id=? ORDER BY name", [$bt['id']])->fetchAll());
}
function contact_role_create($pl) {
    $b = body();
    $bt = require_boutique_owned($b['boutique_id'] ?? '', $pl['sub']);
    $name = trim($b['name'] ?? '');
    if ($name === '') fail('Le nom du role est requis');
    $id = uid();
    q("INSERT INTO contact_roles (id,boutique_id,name) VALUES (?,?,?)", [$id, $bt['id'], $name]);
    ok(q("SELECT * FROM contact_roles WHERE id=?", [$id])->fetch(), 'Role cree', 201);
}
function contacts_list($pl) {
    $bt = require_boutique_owned($_GET['boutique_id'] ?? '', $pl['sub']);
    $sql = "SELECT c.*, r.name AS role_name FROM contacts c LEFT JOIN contact_roles r ON r.id=c.role_id WHERE c.boutique_id=?";
    $params = [$bt['id']];
    if (!empty($_GET['role_id'])) { $sql .= " AND c.role_id=?"; $params[] = $_GET['role_id']; }
    if (!empty($_GET['q'])) { $sql .= " AND c.name ILIKE ?"; $params[] = '%'.$_GET['q'].'%'; }
    $sql .= " ORDER BY c.name";
    ok(q($sql, $params)->fetchAll());
}
function contacts_create($pl) {
    $b = body();
    $bt = require_boutique_owned($b['boutique_id'] ?? '', $pl['sub']);
    $name = trim($b['name'] ?? '');
    if ($name === '') fail('Le nom du contact est requis');
    $id = uid();
    q("INSERT INTO contacts (id,boutique_id,role_id,name,phone,email) VALUES (?,?,?,?,?,?)",
      [$id, $bt['id'], $b['role_id'] ?? null, $name, trim($b['phone'] ?? ''), trim($b['email'] ?? '')]);
    ok(q("SELECT * FROM contacts WHERE id=?", [$id])->fetch(), 'Contact ajoute', 201);
}
function contact_owned($id, $boutiqueId) {
    $row = q("SELECT * FROM contacts WHERE id=? AND boutique_id=?", [$id, $boutiqueId])->fetch();
    if (!$row) fail('Contact introuvable', 404);
    return $row;
}
function contacts_update($pl) {
    $b = body();
    $bt = require_boutique_owned($b['boutique_id'] ?? '', $pl['sub']);
    $row = contact_owned($b['id'] ?? '', $bt['id']);
    q("UPDATE contacts SET role_id=?, name=?, phone=?, email=? WHERE id=?",
      [$b['role_id'] ?? $row['role_id'], trim($b['name'] ?? $row['name']), trim($b['phone'] ?? $row['phone']), trim($b['email'] ?? $row['email']), $row['id']]);
    ok(q("SELECT * FROM contacts WHERE id=?", [$row['id']])->fetch(), 'Contact mis a jour');
}
function contacts_delete($pl) {
    $b = body();
    $bt = require_boutique_owned($b['boutique_id'] ?? '', $pl['sub']);
    $row = contact_owned($b['id'] ?? '', $bt['id']);
    q("DELETE FROM contacts WHERE id=?", [$row['id']]);
    ok(null, 'Contact supprime');
}

// ============================================================
// FINANCES — Vue Globale, Livre de Compte, Frais de livraison,
// Finance Detaillee, Publicites & ROAS
// ============================================================
function route_finance($action) {
    $pl = owner_auth();
    switch ($action) {
        case 'overview':          finance_overview($pl); break;
        case 'accounts':          finance_accounts($pl); break;
        case 'account_create':    finance_account_create($pl); break;
        case 'account_transaction': finance_account_transaction($pl); break;
        case 'account_transfer':  finance_account_transfer($pl); break;
        case 'delivery_fees':        finance_delivery_fees($pl); break;
        case 'delivery_fee_create':  finance_delivery_fee_create($pl); break;
        case 'expenses':          finance_expenses($pl); break;
        case 'expense_create':    finance_expense_create($pl); break;
        case 'detail':             finance_detail($pl); break;
        case 'ads':                finance_ads($pl); break;
        case 'ad_expense_create':  finance_ad_expense_create($pl); break;
        default: fail('Action inconnue', 404);
    }
}

function finance_overview($pl) {
    $bt = require_boutique_owned($_GET['boutique_id'] ?? '', $pl['sub']);
    $period = $_GET['period'] ?? '30d';
    $pc = period_clause($period);

    $revenue = q("SELECT COALESCE(SUM(total),0) s, COUNT(*) c FROM orders
                  WHERE boutique_id=? AND status IN ".ENCAISSE_STATUSES." AND $pc", [$bt['id']])->fetch();
    $revenusEncaisses = (float)$revenue['s'];
    $nbEncaisse = (int)$revenue['c'];

    $coutProduits = (float)q("SELECT COALESCE(SUM(oi.unit_cost*oi.qty),0) s
                               FROM order_items oi JOIN orders o ON o.id=oi.order_id
                               WHERE o.boutique_id=? AND o.status='delivered' AND $pc", [$bt['id']])
                     ->fetch()['s'];
    $fraisLivraison = (float)q("SELECT COALESCE(SUM(amount),0) s FROM delivery_fees_paid
                                 WHERE boutique_id=? AND ".period_clause($period,'created_at'), [$bt['id']])->fetch()['s'];
    $fraisPub = (float)q("SELECT COALESCE(SUM(amount),0) s FROM ad_expenses
                           WHERE boutique_id=? AND ".period_clause($period,'created_at'), [$bt['id']])->fetch()['s'];
    $autresDepenses = (float)q("SELECT COALESCE(SUM(amount),0) s FROM expenses
                                 WHERE boutique_id=? AND ".period_clause($period,'created_at'), [$bt['id']])->fetch()['s'];

    $resultatNet = $revenusEncaisses - $coutProduits - $fraisLivraison - $fraisPub - $autresDepenses;

    $livraisonsFaites = (int)q("SELECT COUNT(*) c FROM orders WHERE boutique_id=? AND status='delivered' AND $pc", [$bt['id']])->fetch()['c'];

    ok([
        'revenus_encaisses'=>$revenusEncaisses, 'nb_commande_encaissee'=>$nbEncaisse,
        'livraisons_faites'=>$livraisonsFaites,
        'cout_produits'=>$coutProduits, 'frais_livraison'=>$fraisLivraison,
        'frais_pub'=>$fraisPub, 'autres_depenses'=>$autresDepenses,
        'resultat_net'=>$resultatNet,
    ]);
}

function finance_accounts($pl) {
    $bt = require_boutique_owned($_GET['boutique_id'] ?? '', $pl['sub']);
    $rows = q("SELECT * FROM accounts WHERE boutique_id=? ORDER BY created_at", [$bt['id']])->fetchAll();
    foreach ($rows as &$a) {
        $a['history'] = q("SELECT * FROM account_transactions WHERE account_id=? ORDER BY created_at DESC LIMIT 50", [$a['id']])->fetchAll();
    }
    ok($rows);
}
function finance_account_create($pl) {
    $b = body();
    $bt = require_boutique_owned($b['boutique_id'] ?? '', $pl['sub']);
    $name = trim($b['name'] ?? '');
    if ($name === '') fail('Le nom du compte est requis');
    $id = uid();
    q("INSERT INTO accounts (id,boutique_id,name,type,balance) VALUES (?,?,?,?,?)",
      [$id, $bt['id'], $name, $b['type'] ?? 'caisse', (float)($b['balance'] ?? 0)]);
    ok(q("SELECT * FROM accounts WHERE id=?", [$id])->fetch(), 'Compte cree', 201);
}
function account_owned($id, $boutiqueId) {
    $row = q("SELECT * FROM accounts WHERE id=? AND boutique_id=?", [$id, $boutiqueId])->fetch();
    if (!$row) fail('Compte introuvable', 404);
    return $row;
}
function finance_account_transaction($pl) {
    $b = body();
    $bt = require_boutique_owned($b['boutique_id'] ?? '', $pl['sub']);
    $acc = account_owned($b['account_id'] ?? '', $bt['id']);
    $type = $b['type'] ?? '';
    if (!in_array($type, ['in','out'], true)) fail('Type invalide');
    $amount = (float)($b['amount'] ?? 0);
    if ($amount <= 0) fail('Montant invalide');
    $delta = $type === 'in' ? $amount : -$amount;
    q("UPDATE accounts SET balance = balance + ? WHERE id=?", [$delta, $acc['id']]);
    q("INSERT INTO account_transactions (id,account_id,boutique_id,type,amount,note) VALUES (?,?,?,?,?,?)",
      [uid(), $acc['id'], $bt['id'], $type, $amount, trim($b['note'] ?? '')]);
    ok(q("SELECT * FROM accounts WHERE id=?", [$acc['id']])->fetch(), 'Mouvement enregistre');
}
function finance_account_transfer($pl) {
    $b = body();
    $bt = require_boutique_owned($b['boutique_id'] ?? '', $pl['sub']);
    $from = account_owned($b['from_account_id'] ?? '', $bt['id']);
    $to = account_owned($b['to_account_id'] ?? '', $bt['id']);
    $amount = (float)($b['amount'] ?? 0);
    if ($amount <= 0) fail('Montant invalide');
    if ($from['id'] === $to['id']) fail('Choisissez deux comptes differents');
    $note = trim($b['note'] ?? '').' (transfert '.$from['name'].' -> '.$to['name'].')';
    $pdo = db(); $pdo->beginTransaction();
    try {
        q("UPDATE accounts SET balance = balance - ? WHERE id=?", [$amount, $from['id']]);
        q("UPDATE accounts SET balance = balance + ? WHERE id=?", [$amount, $to['id']]);
        q("INSERT INTO account_transactions (id,account_id,boutique_id,type,amount,note) VALUES (?,?,?,?,?,?)",
          [uid(), $from['id'], $bt['id'], 'out', $amount, $note]);
        q("INSERT INTO account_transactions (id,account_id,boutique_id,type,amount,note) VALUES (?,?,?,?,?,?)",
          [uid(), $to['id'], $bt['id'], 'in', $amount, $note]);
        $pdo->commit();
    } catch (Exception $e) { $pdo->rollBack(); fail('Transfert impossible', 500); }
    ok(null, 'Transfert effectue');
}

function finance_delivery_fees($pl) {
    $bt = require_boutique_owned($_GET['boutique_id'] ?? '', $pl['sub']);
    $period = $_GET['period'] ?? '30d';
    $rows = q("SELECT * FROM delivery_fees_paid WHERE boutique_id=? AND ".period_clause($period,'created_at')."
               ORDER BY created_at DESC", [$bt['id']])->fetchAll();
    $totalMonth = (float)q("SELECT COALESCE(SUM(amount),0) s FROM delivery_fees_paid
                             WHERE boutique_id=? AND created_at >= date_trunc('month', NOW())", [$bt['id']])->fetch()['s'];
    $total = (float)q("SELECT COALESCE(SUM(amount),0) s FROM delivery_fees_paid WHERE boutique_id=?", [$bt['id']])->fetch()['s'];
    ok(['rows'=>$rows, 'total_month'=>$totalMonth, 'total_all'=>$total, 'count'=>count($rows)]);
}
function finance_delivery_fee_create($pl) {
    $b = body();
    $bt = require_boutique_owned($b['boutique_id'] ?? '', $pl['sub']);
    $amount = (float)($b['amount'] ?? 0);
    if ($amount <= 0) fail('Montant invalide');
    $id = uid();
    q("INSERT INTO delivery_fees_paid (id,boutique_id,order_id,amount,note,account_id,paid_at)
       VALUES (?,?,?,?,?,?,COALESCE(?,CURRENT_DATE))",
      [$id, $bt['id'], $b['order_id'] ?? null, $amount, trim($b['note'] ?? ''), $b['account_id'] ?? null, $b['paid_at'] ?? null]);
    if (!empty($b['account_id'])) {
        account_owned($b['account_id'], $bt['id']);
        q("UPDATE accounts SET balance = balance - ? WHERE id=?", [$amount, $b['account_id']]);
        q("INSERT INTO account_transactions (id,account_id,boutique_id,type,amount,note) VALUES (?,?,?,?,?,?)",
          [uid(), $b['account_id'], $bt['id'], 'out', $amount, 'Frais de livraison']);
    }
    ok(q("SELECT * FROM delivery_fees_paid WHERE id=?", [$id])->fetch(), 'Frais enregistre', 201);
}

function finance_expenses($pl) {
    $bt = require_boutique_owned($_GET['boutique_id'] ?? '', $pl['sub']);
    $period = $_GET['period'] ?? '30d';
    ok(q("SELECT * FROM expenses WHERE boutique_id=? AND ".period_clause($period,'created_at')."
          ORDER BY created_at DESC", [$bt['id']])->fetchAll());
}
function finance_expense_create($pl) {
    $b = body();
    $bt = require_boutique_owned($b['boutique_id'] ?? '', $pl['sub']);
    $label = trim($b['label'] ?? '');
    $amount = (float)($b['amount'] ?? 0);
    if ($label === '' || $amount <= 0) fail('Libelle et montant requis');
    $id = uid();
    q("INSERT INTO expenses (id,boutique_id,label,category,amount,account_id,expense_date)
       VALUES (?,?,?,?,?,?,COALESCE(?,CURRENT_DATE))",
      [$id, $bt['id'], $label, trim($b['category'] ?? ''), $amount, $b['account_id'] ?? null, $b['expense_date'] ?? null]);
    if (!empty($b['account_id'])) {
        account_owned($b['account_id'], $bt['id']);
        q("UPDATE accounts SET balance = balance - ? WHERE id=?", [$amount, $b['account_id']]);
        q("INSERT INTO account_transactions (id,account_id,boutique_id,type,amount,note) VALUES (?,?,?,?,?,?)",
          [uid(), $b['account_id'], $bt['id'], 'out', $amount, 'Depense: '.$label]);
    }
    ok(q("SELECT * FROM expenses WHERE id=?", [$id])->fetch(), 'Depense enregistree', 201);
}

function finance_detail($pl) {
    $bt = require_boutique_owned($_GET['boutique_id'] ?? '', $pl['sub']);
    $period = $_GET['period'] ?? '30d';
    $pc = period_clause($period);
    $orders = q("SELECT * FROM orders WHERE boutique_id=? AND status='delivered' AND $pc ORDER BY delivered_at DESC", [$bt['id']])->fetchAll();
    $rows = [];
    $totalRevenue = 0; $totalCost = 0;
    foreach ($orders as $o) {
        $cost = (float)q("SELECT COALESCE(SUM(unit_cost*qty),0) s FROM order_items WHERE order_id=?", [$o['id']])->fetch()['s'];
        $margin = (float)$o['total'] - $cost;
        $totalRevenue += (float)$o['total']; $totalCost += $cost;
        $rows[] = ['ref'=>$o['ref'], 'customer_name'=>$o['customer_name'], 'total'=>$o['total'], 'cost'=>$cost, 'margin'=>$margin, 'delivered_at'=>$o['delivered_at']];
    }
    ok(['rows'=>$rows, 'total_revenue'=>$totalRevenue, 'total_cost'=>$totalCost, 'total_margin'=>$totalRevenue-$totalCost]);
}

function finance_ads($pl) {
    $bt = require_boutique_owned($_GET['boutique_id'] ?? '', $pl['sub']);
    $period = $_GET['period'] ?? '30d';
    $pcAd = period_clause($period, 'created_at');
    $pcOrder = period_clause($period);
    $depenseTotale = (float)q("SELECT COALESCE(SUM(amount),0) s FROM ad_expenses WHERE boutique_id=? AND $pcAd", [$bt['id']])->fetch()['s'];

    $byProduct = q("SELECT ae.product_id, p.name AS product_name, COALESCE(SUM(ae.amount),0) AS spend
                    FROM ad_expenses ae LEFT JOIN products p ON p.id = ae.product_id
                    WHERE ae.boutique_id=? AND ae.product_id IS NOT NULL AND $pcAd
                    GROUP BY ae.product_id, p.name", [$bt['id']])->fetchAll();
    foreach ($byProduct as &$row) {
        $revenu = (float)q("SELECT COALESCE(SUM(oi.unit_price*oi.qty),0) s FROM order_items oi
                             JOIN orders o ON o.id = oi.order_id
                             WHERE o.boutique_id=? AND o.status='delivered' AND oi.product_id=? AND $pcOrder",
                            [$bt['id'], $row['product_id']])->fetch()['s'];
        $row['revenue'] = $revenu;
        $row['roas'] = $row['spend'] > 0 ? round($revenu / $row['spend'], 2) : null;
    }

    $byCampaign = q("SELECT campaign_name, COALESCE(SUM(amount),0) AS spend
                     FROM ad_expenses WHERE boutique_id=? AND campaign_name IS NOT NULL AND campaign_name<>'' AND $pcAd
                     GROUP BY campaign_name", [$bt['id']])->fetchAll();
    foreach ($byCampaign as &$row) {
        $revenu = (float)q("SELECT COALESCE(SUM(total),0) s FROM orders
                             WHERE boutique_id=? AND status='delivered' AND utm_campaign=? AND $pcOrder",
                            [$bt['id'], $row['campaign_name']])->fetch()['s'];
        $row['revenue'] = $revenu;
        $row['roas'] = $row['spend'] > 0 ? round($revenu / $row['spend'], 2) : null;
    }

    $revenuAttribueTotal = array_sum(array_column($byProduct, 'revenue')) + array_sum(array_column($byCampaign, 'revenue'));
    $roasGlobal = $depenseTotale > 0 ? round($revenuAttribueTotal / $depenseTotale, 2) : null;

    $recent = q("SELECT * FROM ad_expenses WHERE boutique_id=? AND $pcAd ORDER BY created_at DESC LIMIT 50", [$bt['id']])->fetchAll();

    ok([
        'depense_totale'=>$depenseTotale, 'revenu_attribue'=>$revenuAttribueTotal, 'roas_global'=>$roasGlobal,
        'by_product'=>$byProduct, 'by_campaign'=>$byCampaign, 'recent'=>$recent,
    ]);
}
function finance_ad_expense_create($pl) {
    $b = body();
    $bt = require_boutique_owned($b['boutique_id'] ?? '', $pl['sub']);
    $amount = (float)($b['amount'] ?? 0);
    if ($amount <= 0) fail('Montant invalide');
    $id = uid();
    q("INSERT INTO ad_expenses (id,boutique_id,campaign_name,product_id,amount,spend_date)
       VALUES (?,?,?,?,?,COALESCE(?,CURRENT_DATE))",
      [$id, $bt['id'], trim($b['campaign_name'] ?? ''), $b['product_id'] ?? null, $amount, $b['spend_date'] ?? null]);
    ok(q("SELECT * FROM ad_expenses WHERE id=?", [$id])->fetch(), 'Depense publicitaire enregistree', 201);
}

// ============================================================
// ANALYTIQUE — rapports de ventes et activite en direct
// ============================================================
function route_analytics($action) {
    $pl = owner_auth();
    switch ($action) {
        case 'report': analytics_report($pl); break;
        case 'live':   analytics_live($pl); break;
        default: fail('Action inconnue', 404);
    }
}

function analytics_report($pl) {
    $bt = require_boutique_owned($_GET['boutique_id'] ?? '', $pl['sub']);
    $period = $_GET['period'] ?? '30d';
    $pc = period_clause($period);

    $kpi = q("SELECT COALESCE(SUM(total),0) ventes_brutes, COUNT(*) commandes
              FROM orders WHERE boutique_id=? AND status<>'cancelled' AND $pc", [$bt['id']])->fetch();
    $ventesBrutes = (float)$kpi['ventes_brutes'];
    $commandes = (int)$kpi['commandes'];
    $panierMoyen = $commandes > 0 ? round($ventesBrutes / $commandes, 2) : 0;
    $livrees = (int)q("SELECT COUNT(*) c FROM orders WHERE boutique_id=? AND status='delivered' AND $pc", [$bt['id']])->fetch()['c'];
    $retours = (float)q("SELECT COALESCE(SUM(total),0) s FROM orders WHERE boutique_id=? AND status='refused' AND $pc", [$bt['id']])->fetch()['s'];
    $fraisLivraisonClients = (float)q("SELECT COALESCE(SUM(delivery_fee_charged),0) s FROM orders WHERE boutique_id=? AND status<>'cancelled' AND $pc", [$bt['id']])->fetch()['s'];
    $ventesNettes = $ventesBrutes - $retours;

    $salesSeries = q("SELECT DATE(created_at) d, COALESCE(SUM(total),0) ventes,
                       COALESCE(SUM(CASE WHEN status IN ".ENCAISSE_STATUSES." THEN total ELSE 0 END),0) encaissements
                       FROM orders WHERE boutique_id=? AND status<>'cancelled' AND $pc
                       GROUP BY DATE(created_at) ORDER BY d", [$bt['id']])->fetchAll();

    $visitSeries = q("SELECT DATE(created_at) d, COUNT(*) vues, COUNT(DISTINCT session_id) uniques
                       FROM visits WHERE boutique_id=? AND ".period_clause($period,'created_at')."
                       GROUP BY DATE(created_at) ORDER BY d", [$bt['id']])->fetchAll();

    $bestSellers = q("SELECT oi.product_id, oi.product_name, SUM(oi.qty) qty, SUM(oi.unit_price*oi.qty) revenue
                       FROM order_items oi JOIN orders o ON o.id=oi.order_id
                       WHERE o.boutique_id=? AND o.status<>'cancelled' AND $pc
                       GROUP BY oi.product_id, oi.product_name ORDER BY qty DESC LIMIT 10", [$bt['id']])->fetchAll();

    $utm = q("SELECT utm_source, utm_campaign, COUNT(*) commandes, COALESCE(SUM(total),0) ventes
              FROM orders WHERE boutique_id=? AND (utm_source<>'' OR utm_campaign<>'') AND $pc
              GROUP BY utm_source, utm_campaign", [$bt['id']])->fetchAll();

    ok([
        'ventes_brutes'=>$ventesBrutes, 'commandes'=>$commandes, 'panier_moyen'=>$panierMoyen, 'livrees'=>$livrees,
        'decomposition'=>[
            'ventes_brutes'=>$ventesBrutes, 'remises'=>0, 'retours'=>$retours, 'ventes_nettes'=>$ventesNettes,
            'frais_livraison'=>$fraisLivraisonClients, 'taxes'=>0, 'total'=>$ventesNettes+$fraisLivraisonClients,
        ],
        'sales_series'=>$salesSeries, 'visit_series'=>$visitSeries, 'best_sellers'=>$bestSellers, 'utm'=>$utm,
    ]);
}

function analytics_live($pl) {
    $bt = require_boutique_owned($_GET['boutique_id'] ?? '', $pl['sub']);
    $today = "DATE(created_at) = CURRENT_DATE";
    $cmdToday = (int)q("SELECT COUNT(*) c FROM orders WHERE boutique_id=? AND $today", [$bt['id']])->fetch()['c'];
    $revToday = (float)q("SELECT COALESCE(SUM(total),0) s FROM orders WHERE boutique_id=? AND status IN ".ENCAISSE_STATUSES." AND $today", [$bt['id']])->fetch()['s'];
    $panierMoyen = $cmdToday > 0 ? round($revToday / $cmdToday, 2) : 0;
    $recent = q("SELECT * FROM orders WHERE boutique_id=? ORDER BY created_at DESC LIMIT 10", [$bt['id']])->fetchAll();
    $activity = q("SELECT * FROM activity_log WHERE boutique_id=? ORDER BY created_at DESC LIMIT 20", [$bt['id']])->fetchAll();
    ok(['commandes_aujourdhui'=>$cmdToday, 'revenus_aujourdhui'=>$revToday, 'panier_moyen'=>$panierMoyen,
        'commandes_recentes'=>$recent, 'activite'=>$activity, 'server_time'=>date('c')]);
}

// ============================================================
// MARKETING — abonnes newsletter et messages de contact captes sur la
// vitrine publique
// ============================================================
function route_marketing($action) {
    $pl = owner_auth();
    switch ($action) {
        case 'newsletter':     marketing_newsletter($pl); break;
        case 'messages':       marketing_messages($pl); break;
        case 'message_mark_read': marketing_message_mark_read($pl); break;
        default: fail('Action inconnue', 404);
    }
}
function marketing_newsletter($pl) {
    $bt = require_boutique_owned($_GET['boutique_id'] ?? '', $pl['sub']);
    ok(q("SELECT * FROM newsletter_subscribers WHERE boutique_id=? ORDER BY created_at DESC", [$bt['id']])->fetchAll());
}
function marketing_messages($pl) {
    $bt = require_boutique_owned($_GET['boutique_id'] ?? '', $pl['sub']);
    ok(q("SELECT * FROM contact_messages WHERE boutique_id=? ORDER BY created_at DESC", [$bt['id']])->fetchAll());
}
function marketing_message_mark_read($pl) {
    $b = body();
    $bt = require_boutique_owned($b['boutique_id'] ?? '', $pl['sub']);
    $row = q("SELECT id FROM contact_messages WHERE id=? AND boutique_id=?", [$b['id'] ?? '', $bt['id']])->fetch();
    if (!$row) fail('Introuvable', 404);
    q("UPDATE contact_messages SET is_read=1 WHERE id=?", [$row['id']]);
    ok(null, 'Marque comme lu');
}
