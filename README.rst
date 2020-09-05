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

Usage
-----

After downloading this library, you will need to move it into your Lua package
package path, to be able to use if from your script. In later HAProxy versions,
there is ``lua-prepend-path`` directive which can make your life easier.

Basic usage for parsing client requests, constructing responses, or sending
custom requests to external servers is demonstrated bellow. You can use this in
your own Lua actions or services:

.. code-block:: lua

  local require('http')

  local function main(applet)

      -- 1) Parse client side request and print received headers

      local req = http.request.parse(applet)
      for k, v in req:get_headers() do
          core.Debug(k .. ": " .. v)
      end

      -- You can also parse submitted form data
      local form, err = req:parse_multipart()

      -- 2) Send request to external server (please note there is no DNS
         support in Lua on HAProxy

      local res, err = http.get{
          url="http://1.2.3.4",
          headers{host="example.net", ["x-test"] = {"a", "b"}}
      }

      if res then
          for k, v in res:get_headers() do
              core.Debug(k .. ": " .. v)
          end
      else
        core.Debug(err)
      end


      -- 3) Send response to client side
      http.response.create{status_code=200, content="Hello World"}:send(applet)

  end

  core.register_service("test", "http", main)
