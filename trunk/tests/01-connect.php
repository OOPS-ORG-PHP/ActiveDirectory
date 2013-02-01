<?php
/*
 * Active Directory Connection test
 *
 * $Id$
 */

/*
 * Common codes
 */
$cwd = getcwd ();
$ccwd = basename ($cwd);

if ( $ccwd == 'tests' )
	chdir ('../');

require_once 'ActiveDirectory.php';

$ad = new ActiveDirectory;

if ( ! file_exists ('./tests/test-config.php') ) {
	echo "Do you want to connect SSL?\n";
	echo "You can input certificate path : ";
	$certi = trim (fgets (STDIN));

	if ( $certi && ! file_exists ($certi) )
		$certi = '';

	echo "What is your Active Directory Domain? (xxx@domain) : ";
	$ad->domain = trim (fgets (STDIN));

	echo "What is your RDN(Relative Distinguished Names)? : ";
	$ad->rdn = trim (fgets (STDIN));

	echo "Connect Host : ";
	$host = trim (fgets (STDIN));
	echo "Login Account : ";
	$user = trim (fgets (STDIN));
	echo "Login Password : ";
	system('stty -echo');
	$pass = trim (fgets (STDIN));
	system('stty echo');
	echo "\n";

	$template = <<<EOF
<?php
\$certi = '{$certi}';
\$ad->domain = '{$ad->domain}';
\$ad->rdn    = '{$ad->rdn}';
\$host       = '{$host}';
\$user       = '{$user}';
\$pass       = '{$pass}';
?>
EOF;
	file_put_contents ('tests/test-config.php', $template);
} else {
	require_once 'tests/test-config.php';
}

$c = $ad->connect ($user, $pass, $host, null, $certi);

if ( $c->status !== false ) {
	if ( preg_match ('/01-/', $_SERVER['SCRIPT_FILENAME']) ) {
		echo "Success bind\n";
		print_r ($c);
	}
} else {
	fprintf (STDERR, "Error: %s\n", $c->error);
	exit (1);
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
