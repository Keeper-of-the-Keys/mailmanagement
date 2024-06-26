# Introduction
This project was started when I realized that I would not be able to only use OAuth2 from my mail server since some of the clients that I use either don't support it or only support it for the big players.

Thus instead of allowing "the" username and password to be stored in those clients this project allows the user to generat a per-app username/password pair that only works for the mail servers while his/her real username/password remain unused.

The project leverages SAML2 provided by apache mod_mellon or an OTP sent to the e-mail of the user to identify the user and allow access.

As of June 2024 the main functionality provided by this system is the ability to create these "app passwords" while some other settings can also be done.

This ties in with a lua script that currently exists as a template in my (as yet unpublished) ansible collection as well as the mail server setup procedure there.

# Future plans
- Maybe leverage htmx for the UI
- Allow other mail-related settings to be done
- Add logging and logging summary e-mails
