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

if (window.rcmail) {
	rcmail.addEventListener('plugin.access_restricted', function(response) {
		rcmail.command('switch-task', 'logout');
	});
}