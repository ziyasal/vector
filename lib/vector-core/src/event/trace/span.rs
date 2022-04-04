use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A Span is the elementary traces building block, the following structure is directly inspired by the OpenTelemetry
/// data model: https://github.com/open-telemetry/opentelemetry-proto/blob/17c68a9/opentelemetry/proto/trace/v1/trace.proto#L122-L202
#[derive(Clone, Debug, Default, Deserialize, PartialEq, PartialOrd, Serialize)]
pub struct Span {
    /// Span parent id
    pub id: SpanId,
    /// Span kind
    pub kind: SpanKind,
    /// Span name
    pub name: String,
    /// Span start time
    pub start_time: DateTime<Utc>,
    /// Span end time
    pub end_time: DateTime<Utc>,
    // Span attributes
    /*pub attributes: crate::trace::EvictedHashMap,
    /// Span events
    pub events: crate::trace::EvictedQueue<Event>,
    /// Span Links
    pub links: crate::trace::EvictedQueue<Link>,
    /// Span status
    pub status: Status,
    /// Resource contains attributes representing an entity that produced this span.
    pub resource: Option<Arc<crate::Resource>>,
    /// Instrumentation library that produced this span
    pub instrumentation_lib: crate::InstrumentationLibrary,

    /// Exportable `SpanContext`
    pub context: SpanContext,*/
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, PartialOrd, Serialize)]
pub struct SpanId(pub(crate) u64);

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
pub enum SpanKind {
    Client,
    Server,
    Producer,
    Consumer,
    Internal,
}

impl Default for SpanKind {
    fn default() -> Self { SpanKind::Internal }
}
