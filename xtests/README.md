# dog › xtests

This is dog’s extended test suite. It gets run using [Specsheet]. They run a complete end-to-end set of tests, covering network connections, DNS protocol parsing, command-line options, and error handling.

For completeness, this makes connections over the network. This means that the outcome of some of the tests is dependent on your own machine’s connectivity! It also means that your own IP address will be recorded as making the requests.

The tests have the following set of Specsheet tags:

- `live`: All tests that use the network.
- `isp`: Tests that use your computer’s default resolver.
- `google`: Tests that use the [public Google DNS resolver].
- `cloudflare`: Tests that use the [public Cloudflare DNS resolver].

[Specsheet]: https://specsheet.software/
[public Google DNS resolver]: https://developers.google.com/speed/public-dns
[public Cloudflare DNS resolver]: https://developers.cloudflare.com/1.1.1.1/
