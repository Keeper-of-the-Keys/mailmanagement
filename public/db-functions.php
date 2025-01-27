<?php
global $config;
include_once('config.php');

try {
	$dbh = new PDO($config['dsn'], $config['dbUser'], $config['dbPass'], array(PDO::ATTR_PERSISTENT => true));
	$dbh->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
} catch (PDOException $e) {
	die('Connection failed: ' . $e->getMessage());
}

function get_domain_id($domain) {
	global $dbh;
	$domainData = $dbh->prepare('select `domain_id` from `virtual_domains` where `domain` = :domain and `domain_id` > 0');
	$domainData->bindValue(':domain', $domain, PDO::PARAM_STR);
	$domainData->execute();

	handleError($domainData);

	$domainData = $domainData->fetch();

	if(is_array($domainData) && is_numeric($domainData['domain_id'])) {
		return $domainData['domain_id'];
	}
	return false;
}

function get_domain_data($domain) {
	global $dbh;
	$domainData = $dbh->prepare('select `domain_id`, `backend_type`, `backend_uri`, `ldap_bind_dn`, `ldap_bind_password`, `ldap_base_dn`, `ldap_sync_cron` from `virtual_domains` where `domain` = :domain and `domain_id` > 0');
	$domainData->bindValue(':domain', $domain, PDO::PARAM_STR);
	$domainData->execute();

	handleError($domainData);

	return $domainData->fetch();
}

function get_userdata($email, $domain_id) {
	global $dbh;
	$userDetails = $dbh->prepare('Select `user_id`, `secondary_mail`, `forward_to_secondary`, `password_usage_report` from `virtual_users` where `email` = :email and `domain_id` = :domain_id');
	$userDetails->bindValue(':email', $email, PDO::PARAM_STR);
	$userDetails->bindValue(':domain_id', $domain_id, PDO::PARAM_INT);
	$userDetails->execute();

	handleError($userDetails);

	return $userDetails->fetch();
}

function update_userdata($email, $domain_id, $settings) {
	global $dbh;

	if (!is_array($settings)) {
		return -1;
	}

	$updateUserDetails = $dbh->prepare('update `virtual_users` set `secondary_mail` = :secondary_mail, `forward_to_secondary` = :forward, `password_usage_report` = :usage where `email` = :email and `domain_id` = :domain_id');
	$updateUserDetails->bindValue(':secondary_mail', $settings['secondary-address'], PDO::PARAM_STR);
	$updateUserDetails->bindValue(':forward', $settings['forward-email'], PDO::PARAM_BOOL);
	$updateUserDetails->bindValue(':usage', $settings['password-usage-report'], PDO::PARAM_BOOL);
	$updateUserDetails->bindValue(':email', $email, PDO::PARAM_STR);
	$updateUserDetails->bindValue(':domain_id', $domain_id, PDO::PARAM_INT);
	$updateUserDetails->execute();

	handleError($updateUserDetails);

	return 0;
}

function create_user($email, $domain_id) {
	global $dbh;
	$createUser = $dbh->prepare('insert into `virtual_users` set `email` = :email, `domain_id` = :domain_id, `password_usage_report` = 0, `forward_to_secondary` = 0');
	$createUser->bindValue(':email', $email, PDO::PARAM_STR);
	$createUser->bindValue(':domain_id', $domain_id, PDO::PARAM_INT);
	$createUser->execute();

	handleError($createUser);

	header('Location: https://'.$_SERVER['SERVER_NAME']);
}

function is_superuser($email) {
	global $dbh;
	$isSuperuser = $dbh->prepare('select exists(select * from `system_info` where `key` like "super_user%" and `value` = :email) as isSuperuser');
	$isSuperuser->bindValue(':email', $email, PDO::PARAM_STR);
	$isSuperuser->execute();

	handleError($isSuperuser);

	return $isSuperuser->fetch();
}

function create_app_password($passName, $hash, $user_id) {
	global $dbh;
	$createAppPass = $dbh->prepare('insert into `virtual_application_passwords` set `user_id` = :user_id, `application_username` = :user, `application_password` = :pass');
	$createAppPass->bindValue(':user', $passName, PDO::PARAM_STR);
	$createAppPass->bindValue(':pass', $hash, PDO::PARAM_STR);
	$createAppPass->bindValue(':user_id', $user_id, PDO::PARAM_INT);
	$createAppPass->execute();
}

function update_app_password($hash, $pass_id) {
	global $dbh;
	$updateAppPass = $dbh->prepare('update `virtual_application_passwords` set `application_password` = :pass, `password_changed` = now() where `password_id` = :pass_id');
	$updateAppPass->bindValue(':pass', $hash, PDO::PARAM_STR);
	$updateAppPass->bindValue(':pass_id', $pass_id, PDO::PARAM_INT);
	$updateAppPass->execute();
}

function delete_app_password($pass_id) {
	global $dbh;
	$deleteAppPass = $dbh->prepare('delete from `virtual_application_passwords` where `password_id` = :pass_id');
	$deleteAppPass->bindValue(':pass_id', $pass_id, PDO::PARAM_INT);
	$deleteAppPass->execute();
}

function get_user_passwords($user_id) {
	global $dbh;
	$userPasswords = $dbh->prepare('select `application_username`, `password_id` from `virtual_application_passwords` where `user_id` = :user_id');
	$userPasswords->bindValue(':user_id', $user_id, PDO::PARAM_INT);
	$userPasswords->execute();

	handleError($userPasswords);

	return $userPasswords->fetchAll();
}

function is_password_owner($user_id, $pass_id) {
	global $dbh;
	$verifyPasswordOwnership = $dbh->prepare('select count(*) as `isPasswordOwner`, `application_username` from `virtual_application_passwords` where `user_id` = :user_id and `password_id` = :pass_id');
	$verifyPasswordOwnership->bindValue(':user_id', $user_id, PDO::PARAM_INT);
	$verifyPasswordOwnership->bindValue(':pass_id', $pass_id, PDO::PARAM_INT);
	$verifyPasswordOwnership->execute();

	handleError($verifyPasswordOwnership);

	return $verifyPasswordOwnership->fetch();
}

function handleError($pdoObject) {
	if($pdoObject->errorCode() != '00000') {
		die(print_r($pdoObject->errorInfo()));
		return false;
	} else {
		return true;
	}
}

?>

