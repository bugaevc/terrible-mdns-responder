# A terrible mDNS responder

* Written in unsafe C (buffer overflows everywhere)
* Only supports IPv4
* No proper support for multiple network interfaces
* Not portable
* Ignores most of the spec
* Will wreak havoc on your network

## OK, but why?

I wanted it to work on my Hurd box. Avahi doesn't. Neither does Apple's
mDNSResponder.

## History

Terrible mDNS responder derives from an earlier project of mine, the Bad
mDNS responder, which was not nearly as terrible: it was portable to a wide
range of systems, supported both IPv4 and IPv6, tried to support multiple
network interfaces properly, and so on.

Ultimately, Bad mDNS responder was a failure: it was bad enough for me not
to use it on my Linux boxes, and demanded too much from the network stack
to work on the Hurd. Which is why I decided to just rip most of the
complexity out, and make something that works well enough for my actual needs.

## License

Terrible mDNS responder is free software, available under the
GNU Affero General Public License version 3 or later.
