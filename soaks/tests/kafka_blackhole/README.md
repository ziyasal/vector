# Kafka -> Blackhole

This soak tests Kafka source feeding into the blackhole sink.
It is a straight pipe otherwise.

## Method

Lading `kafka_gen` is used to generate logs into Kafka topics
which are then consumed by vector. There is no sink outside of
vector.
