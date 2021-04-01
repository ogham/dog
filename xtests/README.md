# dog › xtests

This is dog’s extended test suite. The checks herein form a complete end-to-end set of tests, covering things like network connections, DNS protocol parsing, command-line options, error handling, and edge case behaviour.

The checks are written as [Specsheet] documents, which you’ll need to have installed. For the JSON tests, you’ll also need [jq].

Because these tests make connections over the network, the outcome of the test suite will depend on your own machine‘s Internet connection! It also means that your own IP address will be recorded as making the requests.


### Test layout

The tests have been divided into four sections:

1. **live**, which uses both your computer’s default resolver and the [public Cloudflare DNS resolver] to access records that have been created using a public-facing DNS host. This checks that dog works using whatever software is between you and those nameservers on the Internet right now. Because these are _live_ records, the output will vary as things like the TTL vary, so we cannot assert on the _exact_ output; nevertheless, it’s a good check to see if the basic functionality is working.

2. **madns**, which sends requests to the [madns resolver]. This resolver has been pre-programmed with deliberately incorrect responses to see how dog handles edge cases in the DNS specification. These are not live records, so things like the TTLs of the responses are fixed, meaning the output should never change over time; however, it does not mean dog will hold up against the network infrastructure of the real world.

3. **options**, which runs dog using various command-line options and checks that the correct output is returned. These tests should not make network requests when behaving correctly.

4. **features**, which checks dog does the right thing when certain features have been enabled or disabled at compile-time. These tests also should not make network requests when behaving correctly.

All four categories of check are needed to ensure dog is working correctly.


### Tags

To run a subset of the checks, you can filter with the following tags:

- `cloudflare`: Tests that use the [public Cloudflare DNS resolver].
- `isp`: Tests that use your computer’s default resolver.
- `madns`: Tests that use the [madns resolver].
- `options`: Tests that check the command-line options.

You can also use a DNS record type as a tag to only run the checks for that particular type.

[Specsheet]: https://specsheet.software/
[jq]: https://stedolan.github.io/jq/
[public Cloudflare DNS resolver]: https://developers.cloudflare.com/1.1.1.1/
[madns resolver]: https://madns.binarystar.systems/
