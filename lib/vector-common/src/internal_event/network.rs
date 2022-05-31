use metrics::counter;
use tracing::trace;

use crate::internal_event::InternalEvent;

#[derive(Debug)]
pub struct NetworkBytesSent<'a> {
    pub byte_size: usize,
    pub protocol: &'a str,
}

impl<'a> InternalEvent for NetworkBytesSent<'a> {
    fn emit(self) {
        trace!(message = "Network bytes sent.", byte_size = %self.byte_size, protocol = %self.protocol);
        counter!("component_network_sent_bytes_total", self.byte_size as u64,
                 "protocol" => self.protocol.to_string());
    }

    fn name(&self) -> Option<&'static str> {
        Some("NetworkBytesSent")
    }
}

#[derive(Debug)]
pub struct NetworkBytesReceived<'a> {
    pub byte_size: usize,
    pub protocol: &'a str,
}

impl<'a> InternalEvent for NetworkBytesReceived<'a> {
    fn emit(self) {
        trace!(message = "Network bytes received.", byte_size = %self.byte_size, protocol = %self.protocol);
        counter!("component_network_received_bytes_total", self.byte_size as u64,
                 "protocol" => self.protocol.to_string());
    }

    fn name(&self) -> Option<&'static str> {
        Some("NetworkBytesReceived")
    }
}

#[derive(Debug)]
pub struct NetworkOutgoingConnectionEstablished<'a> {
    pub protocol: &'a str,
}

impl<'a> InternalEvent for NetworkOutgoingConnectionEstablished<'a> {
    fn emit(self) {
        trace!(message = "Outgoing connection established.", protocol = %self.protocol);
        counter!("component_network_sent_connections_total", 1, "protocol" => self.protocol.to_string());
    }

    fn name(&self) -> Option<&'static str> {
        Some("NetworkOutgoingConnectionEstablished")
    }
}

#[derive(Debug)]
pub struct NetworkIncomingConnectionAccepted<'a> {
    pub protocol: &'a str,
}

impl<'a> InternalEvent for NetworkIncomingConnectionAccepted<'a> {
    fn emit(self) {
        trace!(message = "Incoming connection accepted.", protocol = %self.protocol);
        counter!("component_network_received_connections_total", 1, "protocol" => self.protocol.to_string());
    }

    fn name(&self) -> Option<&'static str> {
        Some("NetworkIncomingConnectionAccepted")
    }
}
