Firecat
=======

Cool callback shell project forked from Bishop Fox

This code should ideally be a generic shell you can upload to a server and point at
or otherwise execute to get a clean callback through an ingress filter rather than downloading some sketch webshell.

upload to PHP server in webroot -> direct reference -> PHP wrapper -> self-unarchive -> self-exec -> callback
Potentially, a JSP wrapper could be swappable for optimal plug-n-pwn? Need to research
Maybe even a JS wrapper could be leveraged similarly? Need to research

Finally, this would also be useful in situations where a consultant has an unstable or feature-poor shell, in which case
this would allow them a slightly-less-unusable shell. It's no readline, that's for sure.

Forked for code cleanup, C practice with networking, and portability

TODOs
-----
* Fix that GOTO
* Fix WIN32 error string table avoidance
* Create two self-expanding archives (DOS, UNIX) which set up and call home
* Do some googling regarding the wrappers
