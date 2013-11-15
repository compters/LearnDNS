# Learn DNS #
A simple Haskell DNS server to learn about DNS, currently takes a map of hosts / IPs to construct its answers. Neither standards compliant nor production ready, purely a learning exercise. 

If you want a good Haskell DNS server then take a look at Kazu Yamamoto's DNS library <https://github.com/kazu-yamamoto/dns>. I used this as a reference whilst building and took a couple of data structures, but his approach uses conduit and I believe provides more complete functionality. 

Build with a <http://www.ietf.org/rfc/rfc1035.txt>

# Todo #
  * Respond with something other than A records
  * Multiple resolver types
  * Basic DNS client

