<?php
/**
 * Login Restriction
 *
 * Plugin to restrict login for users by IPs.
 *
 * @date 2017-02-28
 * @version 1.1
 * @author Alexander Pushkin
 * @url https://github.com/san4op/roundcube_login_restriction
 * @licence GNU GPLv3
 */

define('IPADDR_REGEXP', '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-2]?[0-9]|3[0-2]))?$');

class login_restriction extends rcube_plugin
{
	private $rcmail;
	private $mode = 'whitelist';
	private $list = array();

	function init()
	{
		$this->rcmail = rcube::get_instance();
		$this->mode = $this->rcmail->config->get('login_restriction_mode', 'whitelist');
		$this->list = $this->rcmail->config->get('login_restriction_list', array());

		if ($this->mode != 'whitelist' && $this->mode != 'blacklist') {
			$this->mode = 'whitelist';
		}

		$this->add_texts('localization/', true);

		$this->add_hook('refresh', array($this, 'refresh'));

		if ($this->rcmail->task == 'login') {
			$this->add_hook('authenticate', array($this, 'authenticate'));
		}

		if ($this->rcmail->task == 'logout') {
			$this->add_hook('logout_after', array($this, 'logout_after'));
		}

		if (!preg_match('/^(login|logout)$/i', $this->rcmail->task)) {
			$this->include_script('login_restriction.min.js');
		}
	}

	function refresh($args)
	{
		$username = $this->rcmail->user->get_username();

		if (!empty($username) && !$this->check($username)) {
			$this->rcmail->session->write('access_restricted', '1');
			$this->rcmail->write_log('userlogins', sprintf("Login Restriction: access denied for %s from %s.", $username, rcube_utils::remote_addr()));
			$this->rcmail->output->command('plugin.access_restricted');
		}
	}

	function authenticate($args)
	{
		if (!$this->check($args['user'])) {
			$this->rcmail->write_log('userlogins', sprintf("Login Restriction: access denied for %s from %s.", $args['user'], rcube_utils::remote_addr()));
			$args['abort'] = true;
			$args['error'] = $this->gettext('access_restricted');
		}

		return $args;
	}

	function logout_after($args)
	{
		if ($this->rcmail->session->read('access_restricted') == '1') {
			$this->rcmail->session->destroy('access_restricted');
			if (!$this->check($args['user'])) {
				$this->rcmail->output->show_message($this->gettext('access_restricted'), 'warning');
			}
		}
	}

	private function check($username)
	{
		if (empty($username) || !is_string($username)) {
			return true;
		}

		if (isset($this->list[$username]) && !empty($this->list[$username])) {
			$found = false;
			$user_ip = rcube_utils::remote_addr();
			$user_list =& $this->list[$username];

			if (is_string($user_list)) {
				if (preg_match('/'.IPADDR_REGEXP.'/', $user_list) && $this->ip_in_range($user_ip, $user_list)) {
					$found = true;
				}
			}
			elseif (is_array($user_list)) {
				for ($i=0,$a=count($user_list); $i<$a; $i++) {
					if (preg_match('/'.IPADDR_REGEXP.'/', $user_list[$i]) && $this->ip_in_range($user_ip, $user_list[$i])) {
						$found = true;
						break;
					}
				}
			}

			if ($this->mode == 'whitelist') {
				return $found;
			}
			elseif ($this->mode == 'blacklist') {
				return !$found;
			}
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