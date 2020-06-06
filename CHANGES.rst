Changes
=======

V0.7.17
-------
[aiolib] fix loading issue when importing aioimaplib with python 3.7


V0.7.16
-------
merge from darkrain42
[aiolib] fix interaction between idle loop and server keepalive
[aiolib] fix cert verification on debian buster
[test] fix imapserver literal handling on Python 3.6.5+
[test] tests: Replace calls to asyncio.async with asyncio.ensure_future


V0.7.15
-------
[aiolib] replace 'async' by is_async for python 3.7 cf #42
[aiolib] Add ID command
[aiolib] Add NAMESPACE command

V0.7.14
-------
[fix] when there is ::1 as localhost in /etc/hosts in a docker container
[test] tests with SSL
[aiolib] quote password properly in IMAP dialog

V0.7.13
-------
[aiolib] adds a connection lost callback
[test] imapserver : added APPENDUID response for APPEND cmd
[test][fix] imapserver append should add to the connected user mb
[test] imapserver : more accurate building of message headers (using python email module)

V0.7.12
-------
[aiolib] fix issue #24
[aiolib] fix issue #27

V0.7.11
-------
[aiolib] adds rfc6851 move

V0.7.10
-------
[aiolib] adds IMAP4.has_capability function

V0.7.9
------
[aiolib] adds uncomplete fetch command with uncomplete line
[aiolib] adds uncomplete fetch command BODY without literal
[aiolib] adds rfc4315 uidplus : expunge with uids
[test] handles uidset better in imap server
[test] refactor testing IMAP4ClientProtocol.data_received instead of _handle_responses

V0.7.8
------
[aiolib] idle : added an idle_waiter for an event based idle loop

V0.7.7
------
[aiolib] do not filter exists line for examine command
[aiolib] idle : wait for the end of data frame before pushing into the queue
[test] imapserver enhancements : accepts sequence sets/returns UID when fetch by uid

V0.7.6
------
- [aiolib] idle : added loop methods

V0.7.5
------
- [aiolib][fix] it's up to the user to send idle DONE

V0.7.4
------
- [aiolib] timeout for idle of 29 minutes + timeout of wait_server_push doesn't raise TimeoutException

V0.7.3
------
- [aiolib] added timeout for wait_server_push of 29 minutes
- [aiolib] Remove imap's Continuation from server when connection is idled. Provide imapserver.wait_state to wait for idle in tests
- [test][refactor] Replace WithIMapServer inheritance by mixin combinations between ClockTestCase/TestCase and WithIMapServer
- [test] Allow to send a html email
- [fix] handling untagged responses with noop async command


V0.7.2
------
- [fix] bug when incomplete literal occured before a tagged status line
- [tests] imapserver search with uid range
- [tests] better fetch request handling
- [log] Limit partials' log to 100 characters
- [build] Add tests' requires in setup.py

V0.7.1
------
- [refactor] adding incomplete line before calling _handle_responses

V0.7.0
------
- [fix] generalization of literal treatment
- do not filter exists line for 'select' command (breaks the API). To retrieve unread mails with select, use
   aioimaplib.extract_exists((yield from imap_client.select()) instead of 'yield from imap_client.select()[0]'

V0.6.2
------
- [fix] added '$' and ';' for fetch message with litteral regexp 

V0.6.1
------
- [fix] issue #17 "Error fetch uid param"

V0.6.0
------
- moved timeout handling at the Command level and not IMAP4 client for fetch as proposed by @cyberlis in https://github.com/bamthomas/aioimaplib/pull/16

V0.5.20
-------
- fix : issue #15 https://github.com/bamthomas/aioimaplib/issues/15 This will break the API for FETCH with emails BODY : now the first line is the server FETCH server response line. The messages are between 1 and end of Response.lines list.

V0.5.19
-------
- tests : [revert] add_charset to much intrusive when running a test suite 

V0.5.18
-------
- tests : body text was not base64 encoded even if the header said so

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
