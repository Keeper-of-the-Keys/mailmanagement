<?php
function uiHeader($title) {?>
<html>
<head>
	<title><?= $title;?></title>
	<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-KK94CHFLLe+nY2dmCWGMq91rCGa5gtU4mk92HdvYe+M/SXH301p5ILy+dN9+nJOZ" crossorigin="anonymous">
</head>
<body>
<div class="w-75 p-3 mx-auto" style="background-color: #eee;">
<?php
}

function footer() {?>
</div>
</body>
</html>
<?php
}

function tabMenu($action) {
/*
 * Normal user
 * 1. Generate/regenerate/remove app password - DONE
 * 2. Set forward/secondary address?
 * 3. Set allowed sender address?
 * 4. Set report yes/no
 * Domain admin (MySQL)
 * Domain admin (LDAP)
 * Super admin
 * 5. List/add/remove domains
 * 6. List/add/remove superadmins
 */
?>
	<ul class="nav nav-tabs">
		<li class="nav-item">
			<a class="nav-link <?= $action == 'manage-passwords' ? 'active' : '';?>" href="/manage-passwords">Password Management</a>
		</li>
		<li class="nav-item">
			<a class="nav-link <?= $action == 'manage-my-senders' ? 'active' : '';?>" href="/manage-my-senders">My allowed sender addresses</a>
		</li>
		<li class="nav-item"><a class="nav-link <?= $action == 'personal-settings' ? 'active' : '';?>" href="/personal-settings">Personal Settings</a></li>
<?php	if(isset($_SESSION) && !isset($_SERVER['REMOTE_USER'])) {?>
		<li class="nav-item"><a class="nav-link" href='/logout'>Logout</a></li>
<?php	}?>
	</ul>
<?php
}
function listDomains($domainList) {
	if (empty($domainList)) {?>
		<a href=''>No domains, add domain.</a>
<?php	}
}

function formAuthenticate($SAMLPath = '') {?>
	<form action='/authenticate' method='post'>
		<label for='email' class='form-label'>e-mail address:</label>
		<input id='email' class='form-control' type='text' name='email' />
		<input class='btn btn-primary' type='submit' value='Send One Time Password' />
	</form>
<?php	if (!empty($SAMLPath)) {?>
	<a href='<?=$SAMLPath;?>'>SSO</a>
<?php	}
}

function formOTP($action = '/verifyOTP') {?>
	<form action='<?= $action; ?>' method='post'>
		<label for='otp' class='form-label'>OTP Code:</label>
		<input id='otp' class='form-control' type='text' name='otp' />
		<input class='btn btn-primary' type='submit' value='Verify One Time Password' />
	</form>
<?php
}

function formAddEditDomain($domainInfo = '') {

	if (!empty($domainInfo)) {
		uiHeader('Edit domain '.$domainInfo['name']);
	} else {
		uiHeader('Add domain');
	}
?>
	<form action='' method='post'>
		<label for='domainname' class='form-label'>Domain name:</label>
		<input id='domainname' class='form-control' type='text' name='' />

		<div class='text-center'>
			<input class='btn btn-primary' type='submit' value='Save Changes' />
		</div>
	</form>
<?php
}

function formGeneratePassword() {?>
	<form action='/generate-password' method='post'>
		<label for='app-device-name' class='form-label'>Application or device name</label>
		<input id='app-device-name' class='form-control' type='text' name='app-device-name' />
<?php /*	<label for='comment' class='form-label'></label>
		<input id='comment' class='form-control' type='text' name='comment' />*/?>

		<div class='text-center'>
			<input class='btn btn-primary' type='submit' value='Generate password' />
		</div>
	</form>
<?php
}

function listPasswords($passwordList) {?>
	<ul>
<?php
	foreach ($passwordList as $row) {?>
    <li>
		<?= htmlspecialchars($row['application_username']); ?> -
		<a href='/regenerate-password/<?= $row['password_id']; ?>'>Regenerate</a>
		<a href='/delete-password/<?= $row['password_id']; ?>'>Delete</a>
	</li>
<?php
	}?>
	</ul>
<?php
}

function showNewPassword($passName, $password) {?>
	<div>
		<strong>Username:</strong> <?= htmlspecialchars($passName); ?><br />
		<strong>Password:</strong> <?= $password; ?>
	</div>
<?php
}

function formPersonalSettings($user_details) {?>
	<form action='/update-personal-settings' method='post'>
		<input id='forward-email' name='forward-email' type='checkbox' class='form-check-input' <?=$user_details['forward_to_secondary'] ? 'checked' : '' ;?> />
		<label for='forward-email' class='form-label'>Forward e-mails to secondary address</label>
		<br />
		<label for='secondary-address' class='form-label'>Secondary address</label>
		<input id='secondary-address' name='secondary-address' value='<?=$user_details['secondary_mail'];?>' type='text' class='form-control' />
		<br />
		<input id='password-usage-report' name='password-usage-report' type='checkbox' class='form-check-input' <?=$user_details['password_usage_report'] ? 'checked' : '' ;?> />
		<label for='password-usage-report' class='form-label'>Password usage reports</label>
		<div class='text-center'>
			<input class='btn btn-primary' type='submit' value='Update settings' />
		</div>
	</form>
<?php
}

function table($header, $contents) {
	if (!is_array($header) || !is_array($contents)) {
		return -1;
	}
?>
<table>
	<caption></caption>
	<thead>
		<tr>
			<th></th>
		</tr>
	</thead>
	<tbody>
		<tr>
			<td></td>
		</tr>
	</tbody>
</table>
<?php

}
?>
