/**
 * Login Control plugin script
 *
 * @version 1.2
 * @author Alexander Pushkin
 * @url https://github.com/san4op/roundcube_login_control
 * @licence GNU GPLv3
 */

rcmail.addEventListener('plugin.access_restricted', function(response){
	rcmail.command('logout');
});
