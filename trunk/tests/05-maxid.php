<?php
/*
 * Active Directory Connection test
 *
 * $Id$
 */

require_once '01-connect.php';

echo <<<EOF

 ** For this tests, ur AD must set UNIX ATTRIBUTE


EOF;

$r = $ad->maxid ($c->link);

print_r ($r);

$ad->close ($c);

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
