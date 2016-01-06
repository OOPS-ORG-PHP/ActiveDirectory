<?php
/**
 * Project: ActiveDirectory :: Control Active Directory with ldap or ldaps
 * File:    ActiveDirectory.php
 *
 * Copyright (c) 2016, JoungKyun.Kim <http://oops.org>
 *
 * LICENSE: BSD
 *
 * ActiveDirectory pear package support to control Microsoft Active Directory
 * with ldap or ldaps protocol.
 *
 * @category   System
 * @package    ActiveDirectory
 * @author     JoungKyun.Kim <http://oops.org>
 * @copyright  (c) 2016 JoungKyun.Kim
 * @license    BSD License
 * @version    $Id$
 * @link       http://pear.oops.org/package/ActiveDirectory
 * @filesource
 */


/**
 * ActiveDirectory_Common :: Common APIs
 * @package ActiveDirectory
 */
Class ActiveDirectory_Common
{
	// {{{ properties
	const UNIXDEF = 11644473600;
	// }}}

	// {{{ (void) ActiveDirectory_Common::convert_to_unixtime (&$sec)
	/**
	 * NT timestamp를 UNIX timestamp로 변환
	 *
	 * @access  public
	 * @param   int      NT timestamp
	 */
	public
	function convert_to_unixtime (&$sec) {
		$sec = (integer) (($sec / 10000000) - self::UNIXDEF);
	}
	// }}}

	// {{{ (void) ActiveDirectory_Common::convert_to_nttime (&$sec, $oztime = false)
	/**
	 * UNIX timestamp를 NT timestamp로 변환
	 *
	 * @access  public
	 * @param   int     Unix timestamp
	 */
	public
	function convert_to_nttime (&$sec, $oztime = false) {
		if ( $oztime !== false )
			$sec = date ('YmdHis', $sec) . '.0Z';
		else
			$sec = ($sec + self::UNIXDEF) * 10000000;
	}
	// }}}

	// {{{ (void) ActiveDirectory_Common::convert_to_0Ztime (&$sec)
	/**
	 * UNIX timestamp를 NT 0Z 표현으로 변환
	 *
	 * @access  public
	 * @param   int     Unix timestamp
	 */
	public
	function convert_to_0Ztime (&$time) {
		$this->convert_to_nttime ($time, true);
	}
	// }}}

	// {{{ (void) ActiveDirectory_Common::convert_to_unixtime_from_0Ztime (&$sec)
	/**
	 * NT 0Z 표현을 UNIX teimstamp로 변환
	 *
	 * @access  public
	 * @return  void
	 * @param   string  0Z time
	 */
	public
	function convert_to_unixtime_from_0Ztime (&$time) {
		$time = mktime (
			substr ($time, 8, 2),
			substr ($time, 10, 2),
			substr ($time, 12, 2),
			substr ($time, 4, 2),
			substr ($time, 6, 2),
			substr ($time, 0, 4)
		);
	}
	// }}}

	// {{{ (void) ActiveDirectory_Common::set_array (&$v) {
	/**
	 * 주어진 변수가 array가 아니면 array로 선언한다.
	 *
	 * @access protected
	 * @return void
	 */
	protected
	function set_array (&$v) {
		if ( ! $v || ! is_array ($v) )
			$v = array ();
	}
	// }}}

	// {{{ (void) ActiveDirectory_Common::fix_charset (&$v) {
	/**
	 * 변수 값의 문자셋 처리
	 *
	 * @access protected
	 * @return void
	 */
	protected
	function fix_charset (&$v) {
		if ( $this->charset == 'utf-8' )
			return;

		if ( is_resource ($v) || is_numeric ($v) )
			return;

		if ( is_array ($v) || is_object ($v) ) {
			$types = gettype ($v);
			foreach ( $v as $k => $val ) {
				$this->fix_charset ($val);
				if ( $types == 'object' )
					$v->$k = $val;
				else
					$v[$k] = $val;
			}
			return;
		}

		if ( preg_match ('/[^\x00-\x7f]/', $v) )
			$v = iconv ('utf-8', $this->charset, $v);
	}
	// }}}
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
