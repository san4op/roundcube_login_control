<?php
/**
 * Roundcube Plugin Login Control
 * Plugin to add whitelist and blacklist for login.
 *
 * @version 1.3
 * @author Alexander Pushkin
 * @copyright Copyright (c) 2017, Alexander Pushkin
 * @link https://github.com/san4op/roundcube_login_control
 * @license GNU General Public License, version 3
 */

define('IPADDR_REGEXP', '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-2]?[0-9]|3[0-2]))?$');

class login_control extends rcube_plugin
{
	private $rc;
	private $mode = 'whitelist';
	private $list = array();
	private $username;
	private $ipaddr;

	public function init()
	{
		$this->rc = rcube::get_instance();
		$this->username = $this->rc->user->get_username();
		$this->ipaddr = rcube_utils::remote_addr();

		// load config
		$this->load_config();
		$this->mode = $this->rc->config->get('login_control_mode', 'whitelist');
		$this->list = $this->rc->config->get('login_control_list', array());

		if ($this->mode != 'whitelist' && $this->mode != 'blacklist') {
			$this->mode = 'whitelist';
		}

		// load localization
		$this->add_texts('localization/');

		// include scripts
		if ($this->rc->task != 'login' && $this->rc->task != 'logout') {
			$this->include_script('login_control.js');
		}

		// add hooks
		$this->add_hook('ready', array($this, 'page_ready'));
		$this->add_hook('authenticate', array($this, 'user_login'));
		$this->add_hook('session_destroy', array($this, 'user_logout'));
	}

	public function page_ready($args)
	{
		if (!$this->check($this->username)) {
			$this->rc->write_log('userlogins', sprintf("Login Control: access denied for %s from %s.", $this->username, $this->ipaddr));

			$_SESSION['login_control.access_restricted'] = '1';

			if ($this->rc->output->ajax_call) {
				$this->rc->output->command('plugin.access_restricted');
			} else {
				header('Location: '.$this->rc->url(array('task' => 'logout'), false, false, true));
			}
		}

		return $args;
	}

	public function user_login($args)
	{
		if (!$this->check($args['user'])) {
			$this->rc->write_log('userlogins', sprintf("Login Control: access denied for %s from %s.", $args['user'], $this->ipaddr));

			$args['abort'] = true;
			$args['error'] = $this->gettext(array('name' => 'access_restricted', 'vars' => array('ipaddr' => $this->ipaddr)));
		}

		return $args;
	}

	public function user_logout($args)
	{
		if ($_SESSION['login_control.access_restricted'] == '1') {
			unset($_SESSION['login_control.access_restricted']);

			if (!$this->check($this->username)) {
				$this->rc->output->show_message($this->gettext(array('name' => 'access_restricted', 'vars' => array('ipaddr' => $this->ipaddr))), 'warning', null, true, 600);
			}
		}

		return $args;
	}

	/**
	 * Check if given username in white/blacklist
	 * @param string $username Username to check
	 * @return boolean For non-blocked users return True, otherwise False
	 */
	private function check($username)
	{
		if (empty($username) || !is_string($username)) {
			return true;
		}

		if (isset($this->list['*']) && !empty($this->list['*']) || isset($this->list[$username]) && !empty($this->list[$username])) {
			$found = false;

			// get global list
			$user_list = (isset($this->list['*']) ? $this->list['*'] : array());

			// check format of list
			if (!is_string($user_list) && !is_array($user_list)) {
				rcmail::raise_error(array(
					'code' => 600, 'type' => 'php',
					'line' => __LINE__, 'file' => __FILE__,
					'message' => 'Login Control plugin: Invalid format of list of IP addresses for all users, must be string or array.'), true, false);
				$user_list = array();
			}

			// check and append a list for user specified
			if (isset($this->list[$username])) {
				// check format of list
				if (!is_string($this->list[$username]) && !is_array($this->list[$username])) {
					rcmail::raise_error(array(
						'code' => 600, 'type' => 'php',
						'line' => __LINE__, 'file' => __FILE__,
						'message' => 'Login Control plugin: Invalid format of list of IP addresses for '.$username.', must be string or array.'), true, false);
					$this->list[$username] = array();
				}

				// append a list
				$user_list = array_merge((is_string($user_list) ? array($user_list) : $user_list), (is_string($this->list[$username]) ? array($this->list[$username]) : $this->list[$username]));
			}

			// for string format
			if (is_string($user_list)) {
				if (preg_match('/'.IPADDR_REGEXP.'/', $user_list) && $this->ip_in_range($this->ipaddr, $user_list)) {
					$found = true;
				}
			}

			// for array format
			elseif (is_array($user_list)) {
				for ($i=0,$a=count($user_list); $i<$a; $i++) {
					if (!is_string($user_list[$i])) {
						rcmail::raise_error(array(
							'code' => 600, 'type' => 'php',
							'line' => __LINE__, 'file' => __FILE__,
							'message' => 'Login Control plugin: Invalid format of list of IP addresses, must be string.'), true, false);
						break;
					}
					if (preg_match('/'.IPADDR_REGEXP.'/', $user_list[$i]) && $this->ip_in_range($this->ipaddr, $user_list[$i])) {
						$found = true;
						break;
					}
				}
			}

			return ($this->mode == 'blacklist' ? !$found : $found);
		}

		return true;
	}

	/**
	 * Check if a given ip is in a network
	 * @param  string $ip    IP to check in IPV4 format eg. 127.0.0.1
	 * @param  string $range IP/CIDR netmask eg. 127.0.0.0/24, also 127.0.0.1 is accepted and /32 assumed
	 * @return boolean true if the ip is in this range / false if not.
	 * @source https://gist.github.com/tott/7684443
	 */
	private function ip_in_range($ip, $range)
	{
		if (strpos($range, '/') == false) {
			$range .= '/32';
		}
		// $range is in IP/CIDR format eg 127.0.0.1/24
		list($range, $netmask) = explode('/', $range, 2);
		$range_decimal = ip2long($range);
		$ip_decimal = ip2long($ip);
		$wildcard_decimal = pow(2, (32 - $netmask)) - 1;
		$netmask_decimal = ~ $wildcard_decimal;
		return (($ip_decimal & $netmask_decimal) == ($range_decimal & $netmask_decimal));
	}
}

?>