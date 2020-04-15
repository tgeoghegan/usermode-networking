# usermode-networking

Userspace implementation of network protocols in Rust. The objective is to implement UDP and TCP
client and server in userspace, using SOCK_RAW sockets. I'm doing this to learn more about Rust,
network protocols and also some low level networking details, such as the surprises of SOCK_RAW on
different Unixes.

So far, this is only supported on macOS (and probably only on my personal laptop), but I may attempt
to port it to Linux or one of the BSDs, so I can learn something about their SOCK_RAW
implementations, as well as about writing portable Rust.

Finally, this also serves as a body of code I can present to prospective employers since all the
professional work I've ever done is closed source.

## Running tests

The integration tests I've rigged up here use real SOCK_RAW sockets. That means that failing tests
can leave state behind in the kernel, that tests can't be run concurrently as they all share kernel
state, and that tests must be run under `sudo` in order to get raw IP packets.

This is obviously bad but for a hobby/educational project, I'm choosing not to
go to the trouble of writing a mock socket. To run tests safely:

	cargo test -- --test-threads 1

## `SOCK_RAW` on macOS

The objective is to implement just UDP and TCP (OSI L4), and not any lower-level protocols like IP
or Ethernet. Normally, a socket is created via `socket(2)` by passing type `SOCK_DGRAM` for UDP or
`SOCK_STREAM` for TCP, and then the details of the UDP or TCP protocols are handled in the kernel.
However, Unixes also allow passing `SOCK_RAW`<sup>[1](#sockraw)</sup>. A userspace program reading
from such a socket will get entire IP packets, including both the IP and L4 protocol
headers<sup>[2](#striphdr)</sup>. Perfect for our purposes! You can even still use `bind(2)` on such
a socket in order to only receive IP packets sent to a particular address, or to have the kernel use
the appropriate outgoing interface when sending<sup>[3](#bind)</sup>. Unfortunately, there are some
wrinkles we have to iron out.

The first issue is that you can't actually get TCP or UDP packets. Or more specifically, you can't
receive IP packets whose protocol number is already handled by the kernel. Let's take a quick look
at `xnu` sources to understand why. Note that everything I'm saying here is based on some
experiments I conducted on my laptop as well as reading of kernel sources on GitHub, so it's
entirely possible I've gotten some important details wrong. Having stated the necessary weasel
words, let's move on.

[`ip_input.c`][ip-input] handles incoming IP packets. The [`ip_init`][ip-init] function is
responsible for initializing all the handlers for protocols that can be transported over IP (and
there's quite a few; take a look at `/etc/protocols`). It stores the handlers in the `ipproto_x`
array, which is big enough to hold handlers for all possible protocols (which isn't that many; the
[IP header](https://tools.ietf.org/html/rfc791#page-11) reserves one byte for the protocol field, so
there's only 256 possible values), and initializes every member of that array to the protocol
handler for `AF_INET`, `SOCK_RAW`, `IPPROTO_RAW`. The intent is that if the kernel doesn't
specifically know how to handle a packet, it'll see if anyone in userspace is interested in it.
`ip_init` then walks [the protocol handlers defined in the kernel][proto-handlers] and slots them
into `ipproto_x` at the index corresponding to their protocol number. Later on, when a packet is
received, it eventually makes its way to [`ip_proto_dispatch_in`][proto-dispatch] to be dispatched
to the appropriate protocol handler, based on the protocol value in the incoming IP packet. This is
why our `SOCK_RAW` socket never gets to see UDP or TCP traffic: the kernel provides its own handlers
for TCP (6) and UDP (17), and the packets will go there. I haven't tested on any BSDs, but
apparently [this is also true there](https://sock-raw.org/papers/sock_raw), which we can corroborate
by looking at the [FreeBSD kernel'simplementation][freebsd] of this same logic.

Fortunately there's a workaround for this: examining `/etc/protocols`, we find an entry explaining
that protocol numbers 253 and 254 are meant for "[u]se for experimentation and testing (RFC3692)".
So, we can just create our `SOCK_RAW` socket with the protocol field set to either 253 or 254 and
the packets will make it to userspace as we expect. So we will use 253 for our fake UDP and 254 for
fake TCP. The drawback of this approach is that we won't be able to communicate with other UDP or
TCP implementations, since other systems won't recognize the IP protocol we're specifying.

Sadly the problems don't end there, at least not on macOS, where we encounter a further bug. Let's
take a look at a packet received over our socket:

	0000:   45 00 0f 00  c8 e8 00 00  40 fd 00 00  7f 00 00 01   E.......@.......
	0010:   7f 00 00 01  52 ef 13 0f  01 00 00 00  d0 1b ac e0   ....R...........
	0020:   fe 7f 00 00  00 00 00 00  00 00 00 00  00 00 00 00   ................

The first octet is the IP version (4) and the header length (5). So far so good. The next octet
istype of service, which we're not looking at. The next two bytes are the total length of the IP
packet, including the header, in network order. Before I dive into the problem, let's compare to the
same packet, captured during transmission using `tcpdump(1)`.

	13:01:44.444880 IP (tos 0x0, ttl 64, id 51432, offset 0, flags [none], proto unknown (253), length 35, bad cksum 0 (->b2f3)!)
	    localhost > localhost:  exptest-253 15
		0x0000:  4500 0023 c8e8 0000 40fd 0000 7f00 0001  E..#....@.......
		0x0010:  7f00 0001 52ef 130f 0100 0000 d01b ace0  ....R...........
		0x0020:  fe7f 00

First, note that `tcpdump` reports the packet length is 35, which is consistent with the
corresponding bytes in the packet (`0023`), but the packet we got in userspace has a different
value, namely `0f00`. First off, it seems the endianness has been flipped, but on top of that, the
value is wrong! In fact it's off by 0x14, or decimal 20, which suspiciously is the length of an IP
packet header. Let's dive back into `xnu` sources to get to the bottom of this. As discussed above,
incoming packets are handled in the `ip_input` function, and while that's a big, long, hairy
function crammed full of `#if`, we can pretty quickly find [a smoking gun][smoking-gun]:

		/*
		 * Convert fields to host representation.
		 */
	#if BYTE_ORDER != BIG_ENDIAN
		NTOHS(ip->ip_len);
	#endif

		if (ip->ip_len < hlen) {
			OSAddAtomic(1, &ipstat.ips_badlen);
			goto bad;
		}

	#if BYTE_ORDER != BIG_ENDIAN
		NTOHS(ip->ip_off);
	#endif

The `NTOHS` macro flips the endianness of its argument in-place. There's a few other places in the
function where the endianness of some fields gets flipped (say, to take a checksum over the network
representation of the packet), but they always get flipped back, except here. Scrolling down a
little farther, we find [where the length is being truncated][truncated], along with a hint to the
nature of the bug:

	/*
	 * Further protocols expect the packet length to be w/o the
	 * IP header.
	 */
	ip->ip_len -= hlen;

The comment suggests that the author was assuming that only other protocol handlers in the kernel
would ever be looking at the packet from this point onward, and so it didn't matter if the contents
of the IP header were mangled. Unfortunately this isn't true if the ultimate recipient is a
`SOCK_RAW` socket, because we really do want the real bytes off the wire. It's even more confusing
because all the other multi-byte fields in the packet are not flipped. The good news is that the
problem is deterministic and there isn't really any loss of information, so we can easily work
around this in userspace (see the comments in `IpPacket::from_bytes`).

I've reported the problem with the incorrect length and fragment offset fields to Apple
[via Feedback Assistant](https://feedbackassistant.apple.com/feedback/7647117). That said, I don't
know how they could fix this without breaking existing users of `SOCK_RAW`.

<a name="sockraw">1</a>: [Spec on OpenGroup][opengroup]. You can also get some documentation from
`ip(4)` on BSD and derivatives, or `ip(7)`, `raw(7)` and `packet(7)` on Linux (see also Linux's
`AF_PACKET` sockets, which provide even more robust support for this sort of thing).

<a name="striphdr">2</a>: Note that IP headers can be omitted on reads if `INP_STRIPHDR` is set via
setsockopt(2); similarly senders need not provide IP headers unless `INP_HDRINCL` is set.

<a name="bind">3</a>: The port number provided to `bind(2)` in the `sockaddr` structure will simply
be ignored, since ports are meaningless at the IP layer.

[ip-input]: https://github.com/apple/darwin-xnu/blob/master/bsd/netinet/ip_input.c
[ip-init]: https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet/ip_input.c#L457
[proto-handlers]: https://github.com/apple/darwin-xnu/blob/master/bsd/netinet/in_proto.c#L121
[proto-dispatch]: https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet/ip_input.c#L613
[freebsd]: https://github.com/freebsd/freebsd/blob/0c9a868e5f974ac3d58a8158413cf66ff85c6010/sys/netinet/p_input.c#L347
[smoking-gun]: https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet/ip_input.c#L2048
[truncated]: https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet/ip_input.c#L2379
[opengroup]: https://pubs.opengroup.org/onlinepubs/009695399/basedefs/sys/socket.h.html
