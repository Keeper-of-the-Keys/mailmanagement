<?php

/*****
 * if REMOTE_USER
 * 1 - check if master manager account
 *     Select count() from `system_info` where `key` like 'super_user%' and `value` = :email
 * 2 - check if exists in virtual_users + create
 *     mail_parts = explode(REMOTE_USER, '@')
 *     domain = mail_parts[1]
 *     Select `domain_id`, `backend_type`, `backend_uri`, `ldap_bind_dn`, `ldap_bind_password`, `ldap_base_dn`, `ldap_sync_cron` from `virtual_domains` where `name` = :domain
 *     Select count() from `virtual_users` where `email` = :email
 *     Insert into `virtual_users` set `email` = :email, `domain_id` = :domain_id, `password_usage_report` = 0, `forward_to_secondary` = 0
 * 3 - display user interface for creating app password
 * 4 - if master manager add appropriate options
 * 5 - if domain manager add appropriate options
 * else
 * 1 - login against virtual_users with OTP mail (and primary password?)
 * 2 - steps 3-5 of previous
 *
 * Features to be implemented:
 * 1. App passwords
 *    - Displays list of existing application passwords + usage stats + option to delete/regenerate
 *    - Option to add new password, requires as input application/device name output: username-devicename-XXXXXXXXXXXX where X are random chars and a random password.
 * 2. Domain management (add/delete/modify domains) - master manager
 * 3. User management
 * 4. Allowed sender management?
 * 5. Secondary mail, forward and password usage report
 *****/

include_once('functions.php');

if(isset($_GET['q']) && $_GET['q'] !== '' && $_GET['q'] !== NULL) {
	try {
		$query_parts = split_query($_GET['q']);
	} catch (Exception $e) {
		die('Caught exception: '.$e->getMessage()."\n");
	}
}

session_start();

/*****
 * The user code assumes Apache authentication (in my case - mod_auth_mellon using SAML) at this time,
 * it is possible to make this more modular in the future.
 *****/
if (isset($_SERVER['REMOTE_USER']) && $_SERVER['REMOTE_USER'] !== '' && $_SERVER['REMOTE_USER'] !== NULL) {

	try {
		$user_info = split_email($_SERVER['REMOTE_USER']);
	} catch (Exception $e) {
		die('Caught exception: '.$e->getMessage()."\n");
	}

} else if (isset($query_parts) && $query_parts['action'] === 'authenticate' && !empty($_POST['email'])) {

	try {
		$user_info = split_email($_POST['email']);
	} catch (Exception $e) {
		die('Caught exception: '.$e->getMessage()."\n");
	}

	include_once('db-functions.php');
	$domain_id = get_domain_id($user_info['domain']);

	if ($domain_id > 0) {
		$userDetails = get_userdata($user_info['email'], $domain_id);
	}

	if (!isset($userDetails) || $userDetails === false) {
		$isSuperuser = is_superuser($user_info['email']);
	}

	if ((!isset($userDetails) || $userDetails === false) && $isSuperuser['isSuperuser'] === 0) {
		die('No such mail.');
	}

	//session_start();
	$_SESSION['otp'] = generateRandomString(12);
	$_SESSION['expiry'] = time() + 300;
	$_SESSION['email'] = $user_info['email'];
	$_SESSION['verified'] = false;

	$message = "Your OTP to access the mail management system is (valid until: ". date('Y-m-d h:m:s', $_SESSION['expiry']) ." UTC):\n" . $_SESSION['otp'];
	mail($user_info['email'], "Mail Management OTP", $message);

	include_once('ui-functions.php');

	uiHeader('Enter OTP');
	formOTP();
	footer();
	die();

} else if (isset($query_parts) && $query_parts['action'] === 'verifyOTP') {

	//session_start();
	if ($_SESSION['expiry'] < time()) {
		session_destroy();
		header('Location: https://'.$_SERVER['SERVER_NAME']);
	}

	if (isset($_POST['otp']) && $_SESSION['otp'] !== $_POST['otp']) {
		include_once('ui-functions.php');

		uiHeader('Enter OTP');
		formOTP();
		footer();
		die();
	}

	if ($_SESSION['otp'] === $_POST['otp']) {
		$_SESSION['verified'] = true;
	}

} else if (isset($query_parts) && $query_parts['action'] === 'logout') {

	//session_start();
	session_destroy();
	header('Location: https://'.$_SERVER['SERVER_NAME']);

} else {
	//session_start();
	if (!isset($_SESSION['verified']) || $_SESSION['verified'] === false) {
		include_once('ui-functions.php');
		uiHeader('Authenticate');
		formAuthenticate('/authSAML');
		footer();
		die();
	}

}

if (!isset($user_info) && !isset($_SESSION)) {
	start_session();
}

if (!isset($user_info) && $_SESSION['verified'] === true) {

	try {
		$user_info = split_email($_SESSION['email']);
	} catch (Exception $e) {
		die('Caught exception: '.$e->getMessage()."\n");
	}

}

// Stop execution if data is missing
if (empty($user_info['username'])) {
	die('No username - can\'t continue.');
}
if (empty($user_info['domain'])) {
	die('No domain - can\'t continue.');
}

if (isset($query_parts) && $query_parts['action'] === 'authSAML') {
	header('Location: https://'.$_SERVER['SERVER_NAME']);
}

include_once('db-functions.php');

$isSuperuser = is_superuser($user_info['email']);

$domainData = get_domain_data($user_info['domain']);

if (empty($domainData['domain_id'])) {
	die('No valid domain found.');
}

if (is_array($domainData) && is_numeric($domainData['domain_id'])) {
	$userDetails = get_userdata($user_info['email'], $domainData['domain_id']);
} else {
	$userDetails = false;
}

// Auto create users who connect using SAML, other methods require the user to exist in the database or may be superusers with e-mails unrelated to the managed domains.
if (!$userDetails && isset($_SERVER['REMOTE_USER']) && !empty($domainData['domain_id'])) {
	create_user($user_info['email'], $domainData['domain_id']);
}

if (isset($query_parts)) {

	if ($query_parts['action'] === 'generate-password' && !empty($_POST['app-device-name'])) {
		$passName = $user_info['username'] . '-' . $_POST['app-device-name'] . '-' . generateRandomString(6) . '@' . $user_info['domain'];
		$password = generateRandomString(4).'-'.generateRandomString(4).'-'.generateRandomString(4).'-'.generateRandomString(4);
		$salt = generateRandomString(22);

		create_app_password($passName, crypt($password, '$6$'.$salt.'$'), $userDetails['user_id']);
	}

	if ($query_parts['action'] === 'regenerate-password' && is_numeric($query_parts['parameter'])) {
		$verifyPasswordOwnership = is_password_owner($userDetails['user_id'], $query_parts['parameter']);

		if ($verifyPasswordOwnership['isPasswordOwner']) {
			$password = generateRandomString(4).'-'.generateRandomString(4).'-'.generateRandomString(4).'-'.generateRandomString(4);
			$salt = generateRandomString(22);

			update_app_password(crypt($password, '$6$'.$salt.'$'), $query_parts['parameter']);

			$passName = $verifyPasswordOwnership['application_username'];
		}
	}

	if ($query_parts['action'] === 'delete-password' && is_numeric($query_parts['parameter'])) {
		$verifyPasswordOwnership = is_password_owner($userDetails['user_id'], $query_parts['parameter']);

		if ($verifyPasswordOwnership['isPasswordOwner']) {
			delete_app_password($query_parts['parameter']);
		}
		header('Location: https://'.$_SERVER['SERVER_NAME'].'/manage-passwords');
	}

	if ($query_parts['action'] === 'update-personal-settings') {

		if (isset($_POST['forward-email'])) {
			$_SESSION['update-personal-settings']['forward-email'] = true;
		} else {
			$_SESSION['update-personal-settings']['forward-email'] = false;
		}
		if (isset($_POST['password-usage-report'])) {
			$_SESSION['update-personal-settings']['password-usage-report'] = true;
		} else {
			$_SESSION['update-personal-settings']['password-usage-report'] = false;
		}
		if (isset($_POST['secondary-address']) && !empty(trim($_POST['secondary-address']))) {
			$_SESSION['update-personal-settings']['secondary-address'] = trim($_POST['secondary-address']);
		} else {
			$_SESSION['update-personal-settings']['secondary-address'] = '';
			$_SESSION['update-personal-settings']['forward-email'] = false;
		}
		if (	$userDetails['secondary_mail'] === $_SESSION['update-personal-settings']['secondary-address'] ||
			empty($_SESSION['update-personal-settings']['secondary-address'])) {
				update_userdata($user_info['email'], $domainData['domain_id'], $_SESSION['update-personal-settings']);
		} else {
			$_SESSION['verify-mail-otp'] = generateRandomString(12);
			$_SESSION['verify-mail-expiry'] = time() + 600;

			$message = 	"To verify that " . $user_info['email'] . " has access to this address please copy the following code back into the mail management system:\n".
					$_SESSION['verify-mail-otp'] . "\n".
					"This code is valid until " . date('Y-m-d h:m:s', $_SESSION['verify-mail-expiry']);

			mail($_SESSION['update-personal-settings']['secondary-address'], 'Confirm mail ownership OTP', $message);

			include_once('ui-functions.php');
			uiHeader('Verify secondary e-mail');
			tabMenu('personal-settings');
			formOTP('/update-personal-settings-otp');
			die(footer());
		}
		header('Location: https://'.$_SERVER['SERVER_NAME'].'/personal-settings');
	}
	if ($query_parts['action'] === 'update-personal-settings-otp') {
		if ($_SESSION['verify-mail-expiry'] < time()) {
			unset($_SESSION['verify-mail-expiry']);
			unset($_SESSION['verify-mail-otp']);
			header('Location: https://'.$_SERVER['SERVER_NAME'].'/personal-settings');
		}

		if (isset($_POST['otp']) && $_SESSION['verify-mail-otp'] !== $_POST['otp']) {
			include_once('ui-functions.php');
			uiHeader('Verify secondary e-mail');
			tabMenu('personal-settings');
			formOTP('/update-personal-settings-otp');
			die(footer());
		}

		if ($_SESSION['verify-mail-otp'] === $_POST['otp']) {
			update_userdata($user_info['email'], $domainData['domain_id'], $_SESSION['update-personal-settings']);
			unset($_SESSION['verify-mail-expiry']);
			unset($_SESSION['verify-mail-otp']);
		}

		header('Location: https://'.$_SERVER['SERVER_NAME'].'/personal-settings');
	}
} else {
	$query_parts['action'] = 'manage-passwords';
}

if (is_array($userDetails) && is_numeric($userDetails['user_id'])) {
	$userPasswords = get_user_passwords($userDetails['user_id']);
} else {
	$userPasswords = array();
}

include_once('ui-functions.php');

if (	$query_parts['action'] === 'manage-passwords' ||
	$query_parts['action'] === 'generate-password' ||
	$query_parts['action'] === 'regenerate-password' ) {

		uiHeader('Manage unique mail passwords');
		tabMenu('manage-passwords');
		if (!empty($passName) && !empty($password)) {
			showNewpassword($passName, $password);
		}
		formGeneratePassword();
		if (count($userPasswords) > 0) {
			listPasswords($userPasswords);
		}
} else if ($query_parts['action'] === 'personal-settings') {
	uiHeader('Change mail settings');
	tabMenu($query_parts['action']);
	formPersonalSettings($userDetails);
} else if ($query_parts['action'] === 'manage-my-senders') {
	uiHeader('Manage allowed sender addresses');
	tabMenu($query_parts['action']);
	//listCurrentlyAllowedAddresses($userDetails['user_id']);
	//formAddAllowedAddress($userDetails);
	debug_var($user_info, 'user_info');
	debug_var($userDetails, 'userDetails');
}
footer();

//debug_var($_SERVER, '_SERVER');
//debug_var($_GET, '_GET');
//debug_var($query_parts, 'query_parts');
//debug_var($isSuperuser, 'isSuperuser');
//debug_var($domainData, 'domainData');
//debug_var($createUser, 'createUser');
//debug_var($userPasswords, 'userPasswords');
?>
