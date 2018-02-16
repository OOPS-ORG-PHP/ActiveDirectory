<?php
/**
 * Project: ActiveDirectory :: Control Active Directory with ldap or ldaps
 * File:    ActiveDirectory.php
 *
 * Copyright (c) 2018, JoungKyun.Kim <http://oops.org>
 *
 * LICENSE: BSD
 *
 * ActiveDirectory pear package support to control Microsoft Active Directory
 * with ldap or ldaps protocol.
 *
 * @category   System
 * @package    ActiveDirectory
 * @author     JoungKyun.Kim <http://oops.org>
 * @copyright  (c) 2018 JoungKyun.Kim
 * @license    BSD License
 * @link       http://pear.oops.org/package/ActiveDirectory
 * @filesource
 */

/**
 * import LDAP_API class
 */
require_once 'ActiveDirectory/Common.php';

/**
 * ActiveDirectory_API :: Active Directory Internal API
 * @package ActiveDirectory
 */
Class ActiveDirectory_API extends ActiveDirectory_Common
{
	// {{{ properties
	/**
	 * Set pagenation value
	 * @access  private
	 * @var     integer
	 */
	private $pagesize = 1000;

	/**
	 * Unix attribute entry
	 * @access  private
	 * @var     array
	 */
	private $unix_attr = array (
		'uid', 'uidnumber', 'gidnumber', 'loginshell', 'mssfu30name',
		'mssfu30nisdomain', 'unixhomedirectory', 'unixuserpassword'
	);
	// }}}

	// {{{ (boolean) ActiveDirectory_API::auth ($rdn, $pass)
	/**
	 * bind 암호를 인증
	 *
	 * @access  protected
	 * @return  boolean
	 * @param   string   bind DN
	 * @param   string   bind 암호
	 */
	protected
	function auth ($rdn, $pass, $link = null) {
		$link = $link ? $link : $this->link;
		if ( ! is_resource ($link) )
			return ActiveDirectory::AD_FAILURE;

		return @ldap_bind ($link, $rdn, $pass);
	}
	// }}}

	// {{{ (mixed) ActiveDirectory_API::search_api ($rdn, $filter = null, $attr = null)
	/**
	 * Entry를 검색
	 *
	 * 기본적으로 Active Directory는 검색 결과를 1000개로 제한을 한다. 1000개
	 * 이상의 검색 결과를 가져야 한다면 PHP 5.4 이상을 사용하거나 또는 5.3 이하
	 * 버전에서는 ldap extnesion에 pagenation page를 해 줘야한다.
	 *
	 * 이 API를 PHP 5.3 이하 버전에서 pagenation 패치가 되지 않은 상태에서
	 * 실행하면 최대 1000개의 결과를 반환한다.
	 *
	 * @access  protected
	 * @return  object|array|false
	 * @param   string   Bind DN
	 * @param   string   검색 필터
	 * @param   array    반환할 속성
	 */
	protected
	function search_api ($rdn, $filter = null, $attr = null, $link = null) {
		$filter = $filter ? $filter : '(objectclass=*)';
		$attr   = is_array ($attr) ? $attr : array ();
		$link   = $link ? $link : $this->link;
		$rdn    = $rdn  ? $rdn  : $this->rdn;

		# filter에 euc-kr(또는 cp949)가 있으면 utf8로 변환한다
		# Need KSC5601 pear package
		# If you use local character set except euc-kr,
		# this code changes to iconv
		if ( $this->ksc->is_utf8 ($filter) === false )
			$filter = $this->ksc->utf8 ($filter);

		if ( function_exists ('ldap_control_paged_results') ) {
			#
			# Support from PHP 5.4 or ldap pagenation patch
			#
			$cookie = '';
			$ent = array ();

			$i = 0;
			do {
				ldap_control_paged_results ($link, $this->pagesize, true, $cookie);

				if ( ($entries = @ldap_search ($link, $rdn, $filter, $attr, 0, 0, 30)) === false ) {
					ActiveDirectory::$error = ldap_error ($link);
					return false;
				}

				#ldap_sort ($link, $entries, 'sn');
				$ent = ldap_get_entries ($link, $entries);

				if ( is_array ($ent) && $ent['count'] != 0 ) {
					$this->search_merge ($r, $ent);
				}

				ldap_control_paged_results_response ($link, $entries, $cookie);
				$i++;
			} while ( $cookie !== null && $cookie != '' );
		} else {

			if ( ($entries = @ldap_search ($link, $rdn, $filter, $attr, 0, 0, 30)) === false ) {
				ActiveDirectory::$error = ldap_error ($link);
				return false;
			}

			ldap_sort ($link, $entries, 'sn');

			$ent = ldap_get_entries ($link, $entries);

			if ( ! is_array ($ent) || $ent['count'] == 0 ) {
				ActiveDirectory::$error = sprintf ("%s condition don't exists", $filter);
				return false;
			}

			$this->search_merge ($r, $ent);
		}

		if ( count ($r) == 1 )
			return $r[0];

		return $r;
	}
	// }}}

	// {{{ (void) ActiveDirectory_API::search_merge (&$r, $ent)
	/**
	 * 검색 결과를 merge.
	 *
	 * @access  private
	 * @return  void
	 * @param   array  결과값을 저장할 배열
	 *          array  merge할 배열 데이터
	 */
	private
	function search_merge (&$r, $ent) {
		if ( ! is_array ($r) )
			$r = array ();

		if ( $ent['count'] == 0 )
			return;

		$ignore_pattern = '/^(object|msexchmailboxguid|msexchmailboxsecuritydescriptor|count|usercerti|logonhours|userparameters|replicationsignature|msmqsigncertifi|msmqdigests)/i';
		$keyno = count ($r);

		$this->fix_charset ($ent);

		foreach ( $ent as $key => $value ) {
			if ( $key === 'count' )
				continue;

			if ( ! is_array ($value) )
				$value = array ();

			$key += $keyno;

			foreach ($value as $k => $v) {
				if ( is_numeric ($k) || preg_match ($ignore_pattern, $k) )
					continue;

				if ( $v['count'] == 1 ) {
					if ( preg_match ('/0Z$/', $v[0]) )
						$this->convert_to_unixtime_from_0Ztime ($v[0]);

					$r[$key]->$k = $v[0];
				} else
					$r[$key]->$k = $v;
			}

			$this->convert_to_unixtime ($r[$key]->badpasswordtime);
			$this->convert_to_unixtime ($r[$key]->lastlogon);
			$this->convert_to_unixtime ($r[$key]->pwdlastset);
			$this->convert_to_unixtime ($r[$key]->accountexpires);
			$this->convert_to_unixtime ($r[$key]->lastlogontimestamp);

			if ( $r[$key]->member['count'] )
				$member = $r[$key]->member;
			else
				$member = $r[$key]->memberof;

			for ( $i = 0; $i<$member['count']; $i++ )
				$r[$key]->members[$i] = preg_replace ('/(CN=|,.*)/i', '', $member[$i]);

		}
	}
	// }}}

	// {{{ (string) ActiveDirectory_API::make_nt_password ($pass)
	/**
	 * UTF-16 기반의 Active Directory 암호를 생성
	 *
	 * @access protected
	 * @return string
	 * @param  string 암호 문자열
	 */
	protected
	function make_nt_password ($pass) {
		$pass = sprintf ('"%s"', $pass);
		$passlen = strlen ($pass);

		for ( $i=0; $i<$passlen; $i++ )
			$newpass .= $pass[$i] . "\000";

		return $newpass;
	}
	// }}}

	// {{{ (boolean) ActiveDirectory_API::set_unix_attributes ($account, $type = 'add') {
	/**
	 * Unix attributte를 활성/수정/비활성 한다.
	 *
	 * 제어하는 Unix attribute는 다음과 같다.
	 *
	 * <ol>
	 *     <li>uid</li>
	 *     <li>uidnumber</li>
	 *     <li>gidnumber</li>
	 *     <li>mssfu30name</li>
	 *     <li>mssfu30nisdomain</li>
	 *     <li>loginshell</li>
	 *     <li>unixhomedirectory</li>
	 *     <li>unixuserpassword</li>
	 * </ol>
	 *
	 * 삭제시, uid, unixuserpassword, mssfu30name 은 남아 있는다.
	 *
	 * @access protected
	 * @return boolean
	 * @param  object|string 계정 속성 또는 계정 이름
	 * @param array  Unix Attribute 값
	 * @param string 활성/비활성/수정 (add/replace/remove)
	 */
	protected
	function set_unix_attributes ($id, $attr, $type = 'add') {
		if ( ! is_object ($account) )
			$account = $this->user ($account);

		if ( $account === false || ! is_object ($account) )
			return false;

		$this->set_array ($attr);

		$is_unix = $this->is_unix_attribute ($account);
		$r = true;

		switch ($type) {
			case 'add' :
				if ( $is_unix )
					return true;

				$buf = $this->maxid ();
				$uidnumber = $buf->uid;
				$gidnumber = $buf->gid;

				if ( ! $attr->pass )
					$attr->unixuserpassword = 'ABCD!efgh12345$67890';
				else {
					if ( ! preg_match ('/^\$1\$/', $attr->unixuserpassword) )
						$attr->unixuserpassword = crypt ($attr->unixuserpassword);
				}

				if ( ! $attr->loginshell )
					$attr->loginshell = '/bin/bash';

				if ( ! $attr->mssfu30name )
					$attr->mssfu30name = $account->cn;

				if ( ! $attr->mssfu30nisdomain )
					$attr->mssfu30nisdomain = $this->domain;

				if ( ! $attr->unixhomedirectory )
					$attr->unixhomedirectory = '/home/AD/' . $account->cn;

				$value = array (
					'uid'               => $account->cn,
					'uidnumber'         => ++$uidnumber,
					'gidnumber'         => $gidnumber,
					'loginshell'        => $attr->shell,
					'mssfu30name'       => $attr->mssfu30name,
					'mssfu30nisdomain'  => $attr->mssfu30nisdomain,
					'unixhomedirectory' => $attr->unixhomedirectory,
					'unixuserpassword'  => $attr->unixuserpassword,
				);

				$addvar = array ();
				foreach ( $value as $k => $v ) {
					if ( ! isset ($account->$k) )
						$addvar[$k] = $value[$k];
				}

				$r = $this->exec ($account->distinguishedname, $addvar, 'add');
				break;
			case 'replace' :
				if ( ! $is_unix )
					return $this->set_unix_attirbutes ($account, $attr);

				if ( $attr->unixuserpassword ) {
					if ( ! preg_match ('/^\$1\$/', $attr->unixuserpassword) )
						$attr->unixuserpassword = crypt ($attr->unixuserpassword);
				}

				$attrkey = array ('unixuserpassword', 'loginshell', 'unixhomedirectory');
				foreach ( $attrkey as $key ) {
					$act = $account->$key ? 'replace' : 'add';
					$this->exec (
						$account->distinguishedname,
						array ($key => $attr->$key),
						$act
					);
				}

				break;
			default :
				if ( ! $is_unix )
					return true;

				$entries = array (
					'uid', 'uidnumber', 'gidnumber', 'loginshell', 'mssfu30name',
					'mssfu30nisdomain', 'unixhomedirectory', 'unixuserpassword'
				);

				foreach ( $entryies as $key ) {
					if ( $account->$key )
						$value[$key] = $account->$ey;
				}

				if ( is_array ($value) && count ($value) > 0 )
					$r = $this->exec ($account->distinguishedname, $value, 'del');
		}

		if ( $r === false ) {
			ActiveDirectory::$error = ActiveDirectory::$error .
				' (' . $account->cn . ' - ' . $account->distinguishedname . ')';
		}

		return $r;
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
