# ctf-sso
### A new single-sign on for CTF

ctf-sso is a crude single sign-on system that automates logging into CTF web services.

It is written in Ruby and uses Sinatra.

It works by passing your authentication information in exactly the same way a user would (but on the server side) and captures tokens, session ids, and cookies in order to forward them back to the client. 
