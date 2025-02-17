# Introduction
This project was started when I realized that I would not be able to only use OAuth2 from my mail own server on non-web clients, the reason for this being explained on the [thunderbird wiki](https://wiki.mozilla.org/Thunderbird:Autoconfiguration:ConfigFileFormat#OAuth2).

Thus instead of allowing **"the"** username and password to be stored in those clients this project allows the user to generate a per-app username/password pair that only works for the mail servers while his/her real username/password remain unused.

The project leverages SAML2 provided by apache mod_mellon or an OTP sent to the e-mail of the user to identify the user and allow access.

As of June 2024 the main functionality provided by this system is the ability to create these "app passwords" while some other settings can also be done.

This ties in with a lua script that currently exists as a template in a role in my [ansible collection servers](https://github.com/Keeper-of-the-Keys/ansible-collection-servers/blob/master/roles/mailserver/templates/dovecot-auth-lua.j2) as well as the mail server setup procedure there.

# Future plans
- Maybe leverage htmx for the UI
- Allow other mail-related settings to be done
- Add logging and logging summary e-mails
