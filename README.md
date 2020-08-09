# basalisk
Freeze spam in its tracks


### Purpose

This is the content filtering component for the Unified moderation network.

The current state is a small service which just responds based on a static config.


### Long term

It's designed to be horizontally scalable,
notify downstream of configuration changes to allow optional caching,
and just generally do it's one thing well.

### Build details

Requires hyperscan, wheel won't build without it.
There's more to this that I need to document and script for deployment later. (TODO)
