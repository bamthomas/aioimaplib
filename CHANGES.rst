Changes
=======

V0.5.17
-------
- tests : mail_from parameter from Mail.create should handle mail@host, <mail@host>, Name <mail@host>

V0.5.16
-------
- tests : added better encoding handling and message building in Mail.create 

V0.5.15
-------
- tests : added message_id as Mail.create parameter for testing 

V0.5.14
-------
- tests : extract Mail.create_binary for convenience

V0.5.13
-------
- fix : trailing whitespace bug causing "BAD Could not parse command" using gmail/IDLE
- fix : stop adding a space for the prefix 'UID ' -> 'UID'

V0.5.12
-------
- fix : issue #12 Not properly buffering newlines for incomplete lines
- fix : imapserver with status of an inexistant mailbox
- fix : remove offset problem with strip() modifying length of read data
- fix : remove 'unknown data received' logs if line is empty

V0.5.11
-------
- remove hard coded logging config
- doc : added logging settings

V0.5.10
-------
- added rfc5032 'within' function to server and tests for aiolib (it is only YOUNGER/OLDER arguments)

V0.5.9
------
-  pushing continuation in the queue when idled

V0.5.8
------
- added a stop waiting server push function to interupt yield from queue.get

V0.5.7
------
- server send still here every IDLE_STILL_HERE_PERIOD_SECONDS to client when idle
- fix when server was lauched with main, loop is already running

V0.5.6
------
- fix doc
- fix imapserver main (needs a asyncio.loop.run_forever())

V0.5.5
------
- fix issues with coroutines in uid command
- documentation
- remove PARTIAL, PROXYAUTH, SETANNOTATION and GETANNOTATION commands

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
