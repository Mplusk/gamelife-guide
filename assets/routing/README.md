# Hiddify routing data

The two `*-gamelife-direct.srs` sets contain Russian direct-route conditions with
the blocked-site and blocked-IP exclusions embedded in each file. A failed
initial download therefore does not create a broad direct-route fallback.

They are derived from [runetfreedom/russia-v2ray-rules-dat](https://github.com/runetfreedom/russia-v2ray-rules-dat),
which is distributed under GPL-3.0; see `LICENSE`. `build.py` is the source for
the transformation. The scheduled workflow reads all five upstream files from
one immutable revision, compiles both outputs with sing-box 1.12.0, tests them
with Hiddify core 5.9.15, and publishes only after all checks pass.

Hiddify 5.9.15 checks remote rule sets every 120 hours while connected. A rule
set is empty until its first successful download; a failed refresh retains its
last valid contents. Domain/IP classification and blocked-site coverage depend
on the source lists and on what connection metadata the client can observe.
