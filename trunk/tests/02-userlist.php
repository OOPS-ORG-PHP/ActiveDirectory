<?php
/*
 * Get Active Directory User list test
 *
 * $Id$
 */


require_once '01-connect.php';

$ent = $ad->userlist ('ou=RegularWorker,ou=Users,' . $ad->rdn);
#$ent = $ad->userlist ();

if ( ! $ent )
	printf ("Error: %s\n", $ad->error);
else
	print_r ($ent);

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
