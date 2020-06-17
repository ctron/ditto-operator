FROM registry.access.redhat.com/ubi8 AS builder

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
RUN dnf install -y gcc openssl-devel

RUN mkdir /src
ADD . /src
WORKDIR /src
RUN source $HOME/.cargo/env && cargo build --release
WORKDIR /

FROM registry.access.redhat.com/ubi8-minimal
COPY --from=builder /src/target/release/ditto-operator /

CMD ["/ditto-operator"]