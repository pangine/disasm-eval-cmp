FROM pangine/llvmmc-resolver

USER root

# Install essential packages
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    sqlite3 \
    wget

WORKDIR /root/

# Install golang
RUN wget --progress=bar:force:noscroll https://dl.google.com/go/go1.14.4.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.14.4.linux-amd64.tar.gz && \
    rm go1.14.4.linux-amd64.tar.gz

USER ${USER}
WORKDIR ${USER_HOME}

ENV GOPATH="${USER_HOME}/go"
ENV PATH="${USER_HOME}/go/bin:/usr/local/go/bin:${PATH}"

# Install third-party go packages
RUN git config --global url.git@gitlab.com:.insteadOf https://gitlab.com/ && \
    go get -u github.com/pangine/disasm-eval-cmp/... && \
    echo "[2020-11-12]"
