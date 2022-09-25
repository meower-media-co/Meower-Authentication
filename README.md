# NOTICE
This is still in very early development and will be changed regularly!

# Beta 6 Authentication Server
This is the beta 6 Meower authentication server. It is meant to act as the root authentication server for main REST API and CloudLink servers to be able to authenticate users without having to know their sensitive user data.

It will also be used for OAuth2, emails, and third party server authentication.

It uses SQLite to store data, this is so it can be lightweight and self contained.