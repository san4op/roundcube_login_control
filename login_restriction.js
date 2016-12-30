/**
 * Login Restriction plugin script
 *
 * @version 1.0
 * @author Alexander Pushkin
 * @url https://github.com/san4op/login_restriction
 * @licence GNU GPLv3
 */

rcmail.addEventListener('plugin.access_restricted', function(response){
	rcmail.command('logout');
});
