<?php
// Privileges needed by the webUI user -
// GRANT SELECT, INSERT, UPDATE, DELETE ON `[dbName]`.* TO '[dbUser]'@'[dbHost]';
$config['dbHost'] = '';
$config['dbName'] = '';
$config['dbUser'] = '';
$config['dbPass'] = '';
$config['dsn'] = 'mysql:dbname='.$config['dbName'].';host='.$config['dbHost'];
?>
