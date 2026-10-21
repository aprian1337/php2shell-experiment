# ASAN-instrumented PHP 8.2.34 for UAF confirmation.
# Compiles from source with -fsanitize=address so the stall-window
# use-after-free in session.upload_progress produces a full sanitizer
# trace instead of a silent corruption.
FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential autoconf bison re2c pkg-config curl ca-certificates \
        libxml2-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src
RUN curl -fsSL -o php.tar.gz https://www.php.net/distributions/php-8.2.34.tar.gz \
    && tar xzf php.tar.gz \
    && rm php.tar.gz

WORKDIR /usr/src/php-8.2.34
# Minimal build: CLI + session is all the rfc1867 upload-progress path needs.
# -O1 keeps frames readable in sanitizer reports; -g adds debug symbols.
RUN ./configure \
        --prefix=/opt/php \
        --disable-all \
        --enable-cli \
        --enable-session \
        CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
        LDFLAGS="-fsanitize=address" \
    && make -j"$(nproc)" \
    && make install

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libxml2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /opt/php /opt/php
ENV PATH="/opt/php/bin:$PATH" \
    USE_ZEND_ALLOC=0 \
    ASAN_OPTIONS="detect_leaks=0:halt_on_error=0:abort_on_error=0:log_path=/tmp/asan"

WORKDIR /var/www/html
EXPOSE 18082
# Built-in server: single process, so one worker sees the whole stall window.
CMD ["php", "-S", "0.0.0.0:18082", "-t", "/var/www/html"]
