FROM registry.access.redhat.com/ubi8 AS builder

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
RUN dnf install -y gcc openssl-devel

ENV PATH "$PATH:/root/.cargo/bin"

RUN mkdir /src
ADD . /src
WORKDIR /src
RUN cargo build --release
WORKDIR /

FROM registry.access.redhat.com/ubi8-minimal
COPY --from=builder /src/target/release/ditto-operator /

CMD ["/ditto-operator"]
