# Traces: PROMPT §1 Tier 2 (Fluentd aggregation), CONTRACT §1 (pinned base), §5 (gems), §8.8, §8.11, §8.13
# Build context = this directory:  docker build -t vendetta-stack/fluentd:${STACK_VERSION:-1.0.0} fluentd/
ARG FLUENTD_BASE=fluent/fluentd:v1.17-debian-1@sha256:d6114e87fb46d67fef988014cfeb9025df5d48984063dfde94c74cf4a1857440
FROM ${FLUENTD_BASE}

USER root
RUN echo 'gem: --no-document' > /etc/gemrc

# Plugins: Gemfile + Gemfile.lock (exact versions, no compiler needed) are installed system-wide from the pinned lock. Fluentd is NOT
# started with --gemfile (that mode re-resolves into plugins/vendor/bundle at runtime and needs a compiler); tests/validate.sh
# asserts the installed gem versions equal the lock instead.
COPY plugins/ /fluentd/plugins/
RUN set -eux; \
    cd /fluentd/plugins; \
    BUNDLE_FROZEN=true bundle install --jobs 2 --retry 3; \
    rm -rf /usr/local/bundle/cache /root/.bundle /tmp/* /var/tmp/*; \
    mkdir -p /fluentd/etc/conf.d /fluentd/etc/optional /fluentd/etc/edge /fluentd/etc/enabled.d \
             /var/log/fluentd /run/fluentd; \
    chown -R fluent:fluent /fluentd /var/log/fluentd /run/fluentd

COPY --chown=fluent:fluent fluent.conf /fluentd/etc/fluent.conf
COPY --chown=fluent:fluent conf.d/ /fluentd/etc/conf.d/
COPY --chown=fluent:fluent optional/ /fluentd/etc/optional/
COPY --chown=fluent:fluent edge/ /fluentd/etc/edge/
COPY --chmod=0755 entrypoint.sh /usr/local/bin/cs3-fluentd-entrypoint

ENV FLUENTD_CONF=fluent.conf \
    FLUENTD_ETC=/fluentd/etc \
    BUNDLE_GEMFILE=/fluentd/plugins/Gemfile

USER fluent
EXPOSE 24224 24231 24220
HEALTHCHECK --interval=15s --timeout=5s --start-period=45s --retries=4 \
  CMD ["ruby", "-rnet/http", "-e", "r = Net::HTTP.get_response(URI('http://127.0.0.1:24220/api/plugins.json')); exit(r.is_a?(Net::HTTPSuccess) ? 0 : 1)"]
ENTRYPOINT ["/usr/local/bin/cs3-fluentd-entrypoint"]
CMD ["fluentd"]
