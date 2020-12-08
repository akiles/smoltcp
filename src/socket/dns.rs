#![allow(dead_code, unused)]
use managed::ManagedSlice;

use socket::{PollAt, Socket, SocketHandle, SocketMeta};
use time::{Duration, Instant};
use wire::dns::{Flags, Opcode, Packet, Question, Record, Repr, Type};
use wire::{IpEndpoint, IpProtocol, IpRepr, Ipv4Address, UdpRepr};
use {Error, Result};

const DNS_PORT: u16 = 53;
const MAX_NAME_LEN: usize = 255;
const RETRANSMIT_DELAY: Duration = Duration { millis: 1000 };

/// State for an in-progress DNS query.
///
/// The only reason this struct is public is to allow the socket state
/// to be allocated externally.
#[derive(Debug)]
pub struct DnsQueryState {
    name: [u8; MAX_NAME_LEN],
    name_len: usize,
    retransmit_at: Option<Instant>, // if None, it has never been sent.
    delay: Duration,
}

/// A handle to an in-progress DNS query.
pub struct QueryHandle(usize);

/// A Domain Name System socket.
///
/// A UDP socket is bound to a specific endpoint, and owns transmit and receive
/// packet buffers.
#[derive(Debug)]
pub struct DnsSocket<'a> {
    pub(crate) meta: SocketMeta,

    queries: ManagedSlice<'a, Option<DnsQueryState>>,

    /// The time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    hop_limit: Option<u8>,

    // TEMPORARY rand implementation. TODO
    temp_rand: u16,
}

impl<'a> DnsSocket<'a> {
    /// Create a DNS socket with the given buffers.
    pub fn new<StatesT>(queries: StatesT) -> DnsSocket<'a>
    where
        StatesT: Into<ManagedSlice<'a, Option<DnsQueryState>>>,
    {
        DnsSocket {
            meta: SocketMeta::default(),
            queries: queries.into(),
            hop_limit: None,
            temp_rand: 57897,
        }
    }

    // TEMPORARY rand implementation.
    // TODO: a real rand.
    fn temp_rand(&mut self) -> u16 {
        self.temp_rand += 1;
        self.temp_rand
    }

    fn rand_port(&mut self) -> u16 {
        loop {
            let port = self.temp_rand();
            if port > 1024 {
                return port;
            }
        }
    }

    /// Return the socket handle.
    #[inline]
    pub fn handle(&self) -> SocketHandle {
        self.meta.handle
    }

    /// Return the time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ///
    /// See also the [set_hop_limit](#method.set_hop_limit) method
    pub fn hop_limit(&self) -> Option<u8> {
        self.hop_limit
    }

    /// Set the time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ///
    /// A socket without an explicitly set hop limit value uses the default [IANA recommended]
    /// value (64).
    ///
    /// # Panics
    ///
    /// This function panics if a hop limit value of 0 is given. See [RFC 1122 § 3.2.1.7].
    ///
    /// [IANA recommended]: https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
    /// [RFC 1122 § 3.2.1.7]: https://tools.ietf.org/html/rfc1122#section-3.2.1.7
    pub fn set_hop_limit(&mut self, hop_limit: Option<u8>) {
        // A host MUST NOT send a datagram with a hop limit value of 0
        if let Some(0) = hop_limit {
            panic!("the time-to-live value of a packet must not be zero")
        }

        self.hop_limit = hop_limit
    }

    fn find_free_query(&mut self) -> Result<QueryHandle> {
        for (i, q) in self.queries.iter().enumerate() {
            if q.is_none() {
                return Ok(QueryHandle(i));
            }
        }

        match self.queries {
            ManagedSlice::Borrowed(_) => Err(Error::Exhausted),
            #[cfg(any(feature = "std", feature = "alloc"))]
            ManagedSlice::Owned(ref mut queries) => {
                queries.push(None);
                let index = queries.len() - 1;
                Ok(QueryHandle(index))
            }
        }
    }

    pub fn query(&mut self, name: &[u8]) -> Result<QueryHandle> {
        if name.len() > MAX_NAME_LEN {
            return Err(Error::Truncated);
        }

        let handle = self.find_free_query()?;

        let mut name_buf = [0u8; MAX_NAME_LEN];
        name_buf[..name.len()].copy_from_slice(name);

        self.queries[handle.0] = Some(DnsQueryState {
            name: name_buf,
            name_len: name.len(),
            delay: RETRANSMIT_DELAY,
            retransmit_at: None,
        });
        Ok(handle)
    }

    pub(crate) fn accepts(&self, ip_repr: &IpRepr, repr: &UdpRepr) -> bool {
        repr.src_port == DNS_PORT
    }

    pub(crate) fn process(&mut self, ip_repr: &IpRepr, repr: &UdpRepr) -> Result<()> {
        debug_assert!(self.accepts(ip_repr, repr));

        let size = repr.payload.len();

        net_trace!("{}: receiving {} octets", self.meta.handle, size);
        Ok(())
    }

    pub(crate) fn dispatch<F>(&mut self, timestamp: Instant, emit: F) -> Result<()>
    where
        F: FnOnce((IpRepr, UdpRepr)) -> Result<()>,
    {
        let handle = self.handle();
        let hop_limit = self.hop_limit.unwrap_or(64);

        for q in self.queries.iter_mut().flatten() {
            if let Some(t) = q.retransmit_at {
                if t > timestamp {
                    // query is waiting for retransmit
                    continue;
                }
            }

            let name = &q.name[..q.name_len];

            let repr = Repr {
                transaction_id: 0x1234,
                flags: Flags::RECURSION_DESIRED,
                opcode: Opcode::Query,
                question: Question {
                    name,
                    type_: Type::A,
                },
            };

            let mut buf = [0u8; 512];
            let buf = &mut buf[..repr.buffer_len()];
            repr.emit(&mut Packet::new_unchecked(buf));

            let udp_repr = UdpRepr {
                src_port: 54321,
                dst_port: 53,
                payload: buf,
            };
            let ip_repr = IpRepr::Unspecified {
                src_addr: Ipv4Address::new(192, 168, 69, 1).into(),
                dst_addr: Ipv4Address::new(8, 8, 8, 8).into(),
                protocol: IpProtocol::Udp,
                payload_len: udp_repr.buffer_len(),
                hop_limit: hop_limit,
            };

            if let Err(e) = emit((ip_repr, udp_repr)) {
                net_trace!("DNS emit error {:?}", e);
                return Ok(());
            }

            q.retransmit_at = Some(timestamp + q.delay);

            return Ok(());
        }

        Ok(())
    }

    pub(crate) fn poll_at(&self) -> PollAt {
        self.queries
            .iter()
            .flatten()
            .map(|q| match q.retransmit_at {
                Some(t) => PollAt::Time(t),
                None => PollAt::Now,
            })
            .min()
            .unwrap_or(PollAt::Ingress)
    }
}

impl<'a, 'b> Into<Socket<'a, 'b>> for DnsSocket<'a> {
    fn into(self) -> Socket<'a, 'b> {
        Socket::Dns(self)
    }
}
