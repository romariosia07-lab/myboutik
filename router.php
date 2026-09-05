<?php
// Routeur pour le serveur PHP integre (developpement local : php -S ... router.php)
// et pour tout hebergeur qui lance directement "php -S" (ex: Render avec un
// buildpack PHP generique). Sert les fichiers statiques existants tels
// quels, et redirige tout le reste vers index.php (front controller de
// l'API) pour que $_SERVER['REQUEST_URI'] reste intact et exploitable par
// le routeur module/action de index.php.
$path = urldecode(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));
$file = __DIR__.$path;
if ($path !== '/' && is_file($file)) {
    return false; // laisse le serveur integre servir le fichier tel quel
}
require __DIR__.'/index.php';
