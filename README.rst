Lua HTTP client library for HAProxy
===================================

This is a pure Lua HTTP 1.1 library for HAProxy. It should work on any modern
HAProxy version (1.7+)

The library is loosely modeled after Python's Requests Library using the same
attribute names and similar calling conventions for "HTTP verb" methods (where
we use Lua specific named parameter support)

In addition to client side, the library also supports server side request
parsing, where we utilize HAProxy Lua API for all heavy lifting (i.e. HAProxy
handles client side connections, parses the headers and gives us access to
request body).
