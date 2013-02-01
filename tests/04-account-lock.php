<?php
/*
 * Account lock check test
 *
 * $Id$
 */

require_once '01-connect.php';

echo "ID for locking account test : ";
$id = trim (fgets (STDIN));

$info = $ad->user ($id, $ad->rdn, true);

print_r ($info);

echo <<<EOF

 *
 * {$id} locking test
 *


EOF;

if ( $ad->is_account_locked ($info) == true ) {
	echo "'{$id}' account is locked\n";
} else {
	echo "'{$id}' account is unlocked\n";
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim: set filetype=php noet sw=4 ts=4 fdm=marker:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
?>
