Login Control (Roundcube Webmail Plugin)
==========

Plugin to add whitelist and blacklist for login.

Configuration Options
---------------------

Set the following options directly in Roundcube's config file (example):
```php
$config['login_control_mode'] = 'whitelist';
$config['login_control_list'] = array(
	'user1@domain.com' => array(
		'192.0.2.74',
		'192.0.2.212',
		'198.51.100.12/30',
	),
	'user2@domain.com' => array(
		'198.51.100.1',
		'198.51.100.1',
		'198.51.100.12/30',
	),
);
```

Translation
-----------

https://www.transifex.com/san4op/roundcube-login-control-plugin/
