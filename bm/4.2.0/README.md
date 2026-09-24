# Experimental BAP sensor 4.2.0

The Azul Android APK 7.4.1 contains Akamai BMP SDK 4.0.5. Its Java layer passes
`4.2.0` as the first sensor field to the native builder. This package adapts the
existing 4.2.1 generator to that version and to the field order visible in the
Java layer, including fields `-172`, `-180`, and a final `-115`.

This is a **candidate implementation**. A local test confirms this generator's
internal encryption and field order. An SDK-generated sensor collected from an
Android device has the same seven-part outer shape and `4.2.0` suffix, but its
encrypted payload is much larger (10,540 versus about 4,120 base64 characters)
and it has a 326-character sixth segment where this generator currently emits
an empty segment. The native builder's output and encryption have not been
reproduced. An Azul availability request with this generator's output received
HTTP 403, so this package must not be represented as accepted SDK 4.0.5 support.

Compatibility still needs a byte-level comparison of the native builder and a
successful endpoint test under equivalent session and network conditions.
