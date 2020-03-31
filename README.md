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
