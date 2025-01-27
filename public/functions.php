<?php
/*****
 * Split input string into parts based
 *
 * Inputs:
 * - string
 * - delimiting character
 *
 * Output:
 * - explode(delimiter, string)
 * - if empty string: array()
 *****/
function sl_explode($delimiter, $string) {
	if($string !== '' && $string !== NULL) {
		return explode($delimiter, $string);
	} else {
		return array();
	}
}

/*****
 * Function to split e-mail address into username and domain part.
 * Primarily meant for settings where the username is provided as an e-mail address.
 *
 * Please note this function assumes simple e-mail formats - user@domain
 * user+uniqid@domain will use user+uniqid as the username.
 *
 * Inputs:
 * - e-mail address
 *
 * Returns:
 * - array('username' => e-mail[0], 'domain' => email[1])
 *
 * Errors:
 * - Throws an error if the input string splits into more than 2 parts.
 *****/
function split_email($email) {
	$parts = sl_explode('@', $email);

	if(count($parts) == 2) {
		return array(	'username'	=> $parts[0],
				'domain'	=> $parts[1],
				'email'		=> $email,
			   );
	} else {
		throw new Exception('Failed to parse e-mail address count: '.count($parts));
	}
}

/*****
 * Function to process the query string.
 * Assumes formats:
 * - operation/superlink
 * - superlink
 *
 * Inputs:
 * - query string (_GET['q'])
 *
 * Returns:
 * - array('operation' => query[0], 'superlink' => query[1]
 * - array('superlink' => query)
 *
 * If the query string has more parts they will be ignored.
 * Errors:
 * - Throws an exception if count is out of supported range (less than 1)
 *
 * Please note this function does *not* evaluate if 'operation' is a valid value.
 *****/
function split_query($query) {
	$parts = sl_explode('/', $query);

	$parts = array_filter($parts, 'strlen');

	$count = count($parts);
	if ($count == 1) {
		return array('action' => $parts[0]);
	} else if ($count >= 2) {
		return array(	'action' => $parts[0],
				'parameter' => $parts[1],
			   );
	} else {
		throw new Exception('The query array is empty, how did you get here?');
	}
}
/*****
 * Function for simple debugging of variables.
 *****/
function debug_var($var, $title = '') {
	if ($title !== '') {
		echo '<h3>'.$title.'</h3>';
	}
	echo '<pre>';
	var_dump($var);
	echo '</pre>';
}

function generateRandomString($length = 10) {
	$characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
	$charactersLength = strlen($characters);
	$randomString = '';
	for ($i = 0; $i < $length; $i++) {
	        $randomString .= $characters[random_int(0, $charactersLength - 1)];
	}
	return $randomString;
}
?>
