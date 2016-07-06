Changes
=======

V0.5.4
------
- refactor: treating response as we read the imap server responses for a better reading
- doc
- removing tests from package
- publish on pypi
- added coverall

V0.5.3
------
- fix aioimaplib bug when receiving chunked fetch data
- do not abort when receiving unsollicited data from server

V0.5.2
------
- build CI environment
- license GPL v3.0

V0.5.1
------
- added APPEND command
- fix usernames can have '@' for mockimapserver
- server can handle SEARCH with CHARSET opt parameter (but ignores it)

V0.5
----
- added 11 new imap commands
- added imap command synchronizing
- refactor
- documentation

V0.1
----
- init project with mockimapserver
- project files
- 11 imap commands