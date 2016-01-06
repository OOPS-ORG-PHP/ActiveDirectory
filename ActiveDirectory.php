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
 * import KSC5601 class
 * http://pear.oops.org/docs/li_KSC5601.html
 * http://pear.oops.org/package/KSC5601
 */
require_once 'KSC5601.php';

/**
 * import ActiveDirectory_API class
 */
require_once 'ActiveDirectory/API.php';

/**
 * Main Class that control Active Directory
 * @package ActiveDirectory
 */
Class ActiveDirectory extends ActiveDirectory_API
{
	// {{{ properties
	/**
	 * KSC5601 object
	 * @access protected
	 * @var    object
	 */
	protected $ksc = null;

	/**
	 * Ldap bind resource
	 * @access protected
	 * @var    resource
	 */
	protected $link = null;

	/**
	 * Set default Active Directory Domain name
	 * @access  public
	 * @var     string
	 */
	public $domain = null;

	/**
	 * Set default distinguished name
	 * @access  public
	 * @var     string
	 */
	public $rdn = null;

	/**
	 * 출력 문자열. 이 값은 iconv 변경을 위해 지정한다.
	 * @access  public
	 * @var     stinrg
	 */
	public $charset = null;

	/**
	 * ActiveDirectory의 local character set 을 지정한다.
	 * @access  public
	 * @var     string
	 *
	 */
	public $adcharset = 'cp949';

	/**
	 * Set Ldap error messages
	 * @access  public
	 * @var     string
	 */
	static public $error;
	// }}}

	// {{{ (boolean) ActiveDirectory::__construct (void)
	/**
	 * @access  public
	 * @return  void
	 */
	public
	function __construct () {
		putenv ('LDAPTLS_REQCERT=never');

		if ( php_sapi_name () == 'cli' ) {
			$char = strtolower (getenv ('LANG'));

			if ( preg_match ('/euc-?kr/', $char) )
				$this->charset = 'cp949'; // euc-kr
			else
				$this->charset = 'utf-8';
		} else
			$this->charset = 'utf-8';


		$this->ksc = new KSC5601;
	}
	// }}}

	// {{{ (object) ActiveDirectory::connect ($account, $pass, $host, $port = null, $certi = null)
	/**
	 * Active Directory 에 접속을 하고, 접속한 계정의 정보를 반환한다.
	 *
	 * @access  public
	 * @return  object|false   {status, error, info}
	 * @param   string   Active Directory account 이름
	 * @param   string   Account 암호
	 * @param   string   접속할 호스트
	 * @param   integer  Ldap 포트
	 * @param   string   Ldaps 연결에 필요한 서버 인증서
	 */
	public
	function connect ($account, $pass, $host, $port = null, $certi = null) {
		if ( $certi != null && ! file_exists ($certi) )
			$certi = null;

		if ( ! is_numeric ($port) )
			$port = null;

		if ( $port === null )
			$port = $certi ? 636 : 389;

		$proto = $certi ? 'ldaps' : 'ldap';
		$host = sprintf ('%s://%s', $proto, $host);

		if ( $certi )
			putenv ('LDAPTLS_CACERT=' . $certi);

		$this->link = ldap_connect ($host, $port);

		ldap_set_option($this->link, LDAP_OPT_PROTOCOL_VERSION, 3);
		ldap_set_option($this->link, LDAP_OPT_REFERRALS, 0);

		if ( $this->domain )
			$dn = sprintf ('%s@%s', $account, $this->domain);
		else
			$dn = sprintf ('cn=%s,%s', $account, $this->rdn);

		$r = (object) array (
			'status' => false,
			'error'  => null,
			'info'   => null
		);

		if ( ($r->status = $this->auth ($dn, $pass, $this->link)) === false ) {
			$r->error = ldap_error ($this->link);
		} else {
			$r->info = $this->user ($account, $this->rdn);

			if ( $r->info === false ) {
				$r->status = false;
				$r->error = self::$error;
				@ldap_unbind ($this->link);
			}
		}

		return $r;
	}
	// }}}

	// {{{ (object) ActiveDirectory::user ($user, $rdn = null, $full = false)
	/**
	 * 지정한 계정의 속성을 반환.
	 *
	 * @return object|false
	 * @param  string   Account 이름
	 * @param  string   bind DN
	 * @param  bool     true로 지정을 하면 전체 속성을 반환 (기본값 false)
	 */
	public
	function user ($user, $rdn = null, $full = false) {
		$rdn = $rdn ? $rdn : $this->rdn;

		$r->error = self::$error = null;
		$filter = sprintf ('(samaccountname=%s)', $user);

		if ( $full )
			return $this->search ($rdn, $filter);

		return $this->search_ex ($rdn, $filter);
	}
	// }}}

	// {{{ (array) ActiveDirectory::userlist ($rdn = null)
	/**
	 * Active Directory에 있는 전체 사용자 계정 리스트를 반환
	 *
	 * @access  public
	 * @return  array|false
	 * @param   string   Bind dn
	 */
	public
	function userlist ($rdn = null) {
		$rdn = $rdn ? $rdn : $this->rdn;

		$filter = '(&(objectCategory=person)(objectClass=user))';
		$entries = $this->search ($rdn, $filter);

		if ( $entries === false )
			return false;

		$i = 0;
		foreach ( $entries as $v )
			$r[$i++] = $v->cn;

		sort ($r);

		return $r;
	}
	// }}}

	// {{{ (array) ActiveDirectory::grouplist ($rdn = null)
	/**
	 * Active Directory에 있는 전체 그룹 리스트를 반환
	 *
	 * @access  public
	 * @return  array|false
	 * @param   string   Bind DN
	 */
	public
	function grouplist ($rdn = null) {
		$rdn = $rdn ? $rdn : $this->rdn;

		#$filter = '(grouptype=*)';
		$filter = '(objectCategory=group)';
		$entries = $this->search ($rdn, $filter);

		if ( $entries === false )
			return false;

		$i = 0;
		foreach ( $entries as $v )
			$r[$i++] = $v->cn;

		sort ($r);

		return $r;
	}
	// }}}

	// {{{ (boolean) ActiveDirectory::is_account_lock ($obj)
	/**
	 * 주어진 계정이 lock이 걸려있는지 여부를 확인
	 *
	 * lockout account (lockouttime>=1)
	 * disabled account (userAccountControl:1.2.840.113556.1.4.803:=2)
	 *   -> userAccountControl value is 512 or 66048 enabled account
	 *   -> userAccountControl value is 514 or 66050 disabled account
	 *
	 * @access  public
	 * @return  boolean
	 * @param   object   ActiveDirectory::user mehtod의 결과값
	 */
	function is_account_locked ($obj) {
		if ( ! is_object ($obj) )
			return false;

		if ( $obj->lockouttime && $obj->lockouttime != 0 )
			return true;

		if ( $obj->useraccountcontrol == 514 || $obj->useraccountcontrol == 66050 )
			return true;

		return false;
	}
	// }}}

	// {{{ (object) ActiveDirectory::maxid ($rdn = null)
	/**
	 * 현재 Active Directory의 UID/GID 최대값을 가져온다.
	 *
	 * Unix Attribute가 활성화 되어 있지 않으면 0을 반환한다.
	 *
	 * @access public
	 * @return object
	 * @param  string   bind DN
	 */
	public
	function maxid ($rdn = null) {
		$rdn = $rdn ? $rdn : $this->rdn;
		$ret = new StdClass;

		$ret->uid = 0;
		$ret->gid = 0;

		$r = $this->search_api ($rdn, null, array ('uid', 'uidnumber', 'gidnumber'));

		foreach ( $r as $v ) {
			$ret->uid = ( isset ($v->uidnumber) && $v->uidnumber > $ret->uid ) ? $v->uidnumber : $ret->uid;
			$ret->gid = ( isset ($v->gidnumber) && $v->gidnumber > $ret->gid ) ? $v->gidnumber : $ret->gid;
		}

		return $ret;
	}
	// }}}

	// {{{ (object) ActiveDirectory::search ($rdn, $filter = null)
	/**
	 * Entry를 검색
	 *
	 * 결과 값이 1 entry일 경우에는 object로 반환을 하며, 1개 이상일 경우에는
	 * 모든 entry를 배열로 반환한다.
	 *
	 * @access  public
	 * @return  object|array|false
	 * @param   string   bind DN
	 * @param   filter   ldap 필터
	 */
	public
	function search ($rdn = null, $filter = null) {
		$rdn = $rdn ? $rdn : $this->rdn;
		return $this->search_api ($rdn, $filter);
	}
	// }}}

	// {{{ (object) ActiveDirectory::search_ex ($rdn, $filter = null, $attr = null)
	/**
	 * Entry를 검색
	 *
	 * ActiveDirectory::search 와의 차이점은 4번째 인자로 반환할 속성을
	 * 지정할 수 있다. 지정하지 않을 경우 다음의 속성을 반환한다.
	 *
	 * 'cn', 'sn', 'givenname', 'displayname', 'distinguishedname',
	 * 'department', 'title', 'description', 'company',
	 * 'mail', 'ipphone', 'mobile', 'memberof', 'member',
	 * 'mssfu30name', 'uidnumber', 'gidnumber', 'unixhomedirectory', 'loginshell',
	 * 'whencreated', 'whenchanged', 'lastlogontimestamp', 'lastlogon',
	 * 'pwdlastset', 'badpasswordtime', 'accountexpires', 'lockouttime',
	 * 'useraccountcontrol', 'samaccountname'
	 *
	 * @access  public
	 * @return  object|array|false
	 * @param   string   bind Dn
	 * @param   string   ldap 필터
	 * @param   array    반환할 속성
	 */
	public
	function search_ex ($rdn = null, $filter = null, $attr = null) {
		$rdn   = $rdn ? $rdn : $this->rdn;
		if ( ! $attr ) {
			$attr = array (
				'cn', 'sn', 'givenname', 'displayname', 'distinguishedname',
				'department', 'title', 'description', 'company',
				'mail', 'ipphone', 'mobile', 'memberof', 'member',
				'mssfu30name', 'uidnumber', 'gidnumber', 'unixhomedirectory', 'loginshell',
				'whencreated', 'whenchanged', 'lastlogontimestamp', 'lastlogon',
				'pwdlastset', 'badpasswordtime', 'accountexpires', 'lockouttime',
				'useraccountcontrol', 'samaccountname'
			);
		}

		return $this->search_api ($rdn, $filter, $attr);
	}
	// }}}

	// {{{ (boolean) ActiveDirectory::change_password ($account, $new_pass)
	/**
	 * Active Directory 계정의 암호를 변경한다. 이 method는 ldaps 프로토콜로
	 * 연결해야 동작한다.
	 *
	 * @access  public
	 * @return  boolean
	 * @param   string|object 계정 이름 또는 ActiveDirectory::user method의 결과
	 * @param   new_pass     변경할 암호
	 */
	public
	function change_password ($entry, $new_pass) {
		if ( ! trim ($new_pass) ) {
			self::$error = sprintf (
				"The given password is '%s'. " .
				"The password is only ascii character.",
				$new_pass
			);
			return false;
		}

		if ( ! is_array ($entry) ) {
			if ( ! trim ($entry) ) {
				self::$error = sprintf (
					"The given account name is '%s'. " .
					"The account name is only ascii character without white space.",
					$entry
				);
				return false;
			}
			$account = $entry;

			$entry = $this->user ($entry);
			#$entry = $this->search_ex ($this->rdn, "samaccountname={$account}");
			if ( $entry === false )
				return false;
		}

		$data['unicodePwd'] = $this->make_nt_passwd ($new_pass);

		/*
		 * 패스워드 변경은.. UTF8 로 보내면.. 또 안된다..
		 * MS 왜이러는 거야..
		 * 2012 에서도 그런지는 확인 필요! (2008 R2 까지는 확인)
		 *
		 * LDAP protocol 3 에서는 어떤지 확인 안됨. protocol3은 무조건
		 * UTF-8을 사용하는 것이 표준인데..
		if ( $this->ksc->is_utf8 ($entry->distinguishedname, true) )
			$entry->distinguishedname = $this->ksc->utf8 ($entry->distinguishednamem, UHC);
		 */

		$r = $this->exec ($entry->distinguishedname, $data, 'replace');
		#if ( ($r = @ldap_mod_replace ($this->link, $entry->distinguishedname, $data)) === false )
		#	self::$error = ldap_error ($this->link);

		if ( $r === true ) {
			if ( $this->is_unix_attribute )
				$this->change_unix_password ($entry, $new_pass);
		}

		return $r;
	}
	// }}}

	/*
	 * UNIX Attribute method
	 */

	// {{{ (boolean) ActiveDirectory::is_unix_attribute (&$r)
	/**
	 * 해당 유저의 UNIX attribute가 활성화 되어 있는지 여부를 확인
	 *
	 * @access public
	 * @return bool
	 * @param  string|object 계정 또는 계정 속성
	 */
	public
	function is_unix_attribute (&$r) {
        if ( ! is_object ($r) ) {
			if ( ! is_string ($r) )
				return false;

			if ( ($res = $this->user ($r, $this->rdn)) === false )
				return false;

			if ( is_object ($res) || ! isset ($res->samaccountname) )
				return false;

            $r = $res;
            unset ($res);
        }

        if ( $r->uid && $r->mssfu30name && $r->loginshell )
            return true;

        return false;
	}
	// }}}

	// {{{ (boolean) ActiveDirectory::enable_unix_attribute ($account, $attr)
	/**
	 * 계정의 unix attribyte를 활성화 한다.
	 *
	 * ActiveDirectory::user method의 결과값을 파라미터로 넘긴다.
	 *
	 * @access public
	 * @return boolean
	 * @param  object  계정 속성
	 * @param  array   unix attribute 값<br>
	 *    설정 가능한 배열 멤버는 다음과 같다. (괄호안은 지정하지 않았을 경우의
	 *    기본값이다.)
	 *    <p>
	 *    <ul>
	 *        <li>mssfu30name (CN attribute)</li>
	 *        <li>mssfu30nisdomain (ActiveDirectory::$domain)</li>
	 *        <li>loginshell (/bin/bash)</li>
	 *        <li>unixhomedirectory (/home/AD/USERNAME)</li>
	 *        <li>unixuserpassword (Gabage data)</li>
	 *    </ul>
	 */
	public
	function enable_unix_attribute ($account, $attr = null) {
		return $this->set_unix_attribute ($account, $attr, 'add');
	}
	// }}}

	// {{{ (boolean) ActiveDirectory::disable_unix_attribute ($account)
	/**
	 * 계정의 unix attribyte를 비활성화 한다.
	 *
	 * @access public
	 * @return boolean
	 * @param  object  계정 속성 또는 계정 이름
	 */
	public
	function disable_unix_attribute ($account) {
		return $this->set_unix_attribute ($account, null, 'remove');
	}
	// }}}

	// {{{ (boolean) ActiveDirectory::change_unix_password ($account, $pass = null)
	/**
	 * Unix Attribute 속성의 암호를 변경한다.
	 *
	 * @access public
	 * @return bool
	 * @param  string 계정 이름
	 * @param  string 변경할 암호
	 */
	public
	function change_unix_password ($account, $pass = null) {
		if ( ! $pass )
			return false;

		$attr['unixuserpassword'] = $pass;
		return $this->set_unix_attribute ($account, $attr, 'replace');
	}
	// }}}

	// {{{ (void) ActiveDirectory::close ($link = null) 
	/**
	 * Disconnect Active Directory
	 * @access  public
	 * @return  void
	 * @param   resource  (optional) ldap link
	 */
	public
	function close (&$r) {
		if ( is_resource ($r) )
			ldap_unbind ($r);
		else if ( is_object ($r) ) {
			if ( is_resource ($r->link) )
				ldap_unbind ($r->link);

			$r->status = false;
			$r->link   = false;
			$r->error  = null;
			$r->info   = null;
		} else {
			if ( is_resource ($r) )
				ldap_unbind ($r);
		}
	}
	// }}}

	/*
	 * Ldap Execute
	 */

	// {{{ (boolean) ActiveDirectory::exec ($link, $dn, $attrs, $mode='add')
	/**
	 * LDAP 추가/수정/삭제 실행을 한다.
	 *
	 * @access public
	 * @return boolean
	 * @param  resrouce
	 * @param  string   Bind DN
	 * @param  array    실행할 키/값
	 */
	public
	function exec ($dn, $attrs, $mode = 'add', $link = null) {
		$link = $link ? $link : $this->link;

		if ( ! is_array ($attrs) ) {
			ActiveDirectory::$error = 'Entry is must set with Array';
			return false;
		}

		if ( ! count ($attrs) ) {
			ActiveDirectory::$error = 'Entry is empty';
			return false;
		}

		$mode = strtolower ($mode);
		if ( ! preg_match ('/^(add|del|replace)$/', $mode) ) {
			ActiveDirectory::$error = 'Invalid mode';
			return false;
		}

		$funcname = 'ldap_mod_' . $mode;

		if ( ($r = @$funcname ($link, $dn, $attrs)) === false )
			ActiveDirectory::$error = ldap_error ($link);

		return $r;
	}
	// }}}


	// {{{ (boolean) ActiveDirectory::__construct (void)
	/**
	 * @access  public
	 * @return  void
	 */
	public function __destruct () {
		if ( is_resource ($this->link) )
			ldap_unbind ($this->link);
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
