# HTTP -> SDS -> Datadog Logs

This soak tests HTTP source feeding into the Datadog logs source. SDS
is included.

## Method

Lading `http_gen` is used to generate log load into vector, `http_blackhole`
acts as a Datadog API sink.
