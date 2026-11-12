# priv-audit fixture corpus: a clean distribution image, then seeded
# misconfigurations, with sshd -T as the reference for SSH settings.
# From the repository root:
#   docker build --build-arg BASE=debian:12-slim -f tests/fixtures/Dockerfile -t pa-fixture . && docker run --rm pa-fixture
ARG BASE=debian:12-slim
FROM ${BASE}
RUN if command -v apt-get >/dev/null; then \
      apt-get update && apt-get install -y --no-install-recommends python3 sudo openssh-server libcap2-bin && rm -rf /var/lib/apt/lists/*; \
    elif command -v microdnf >/dev/null; then microdnf install -y python3 sudo openssh-server libcap findutils shadow-utils && microdnf clean all; \
    elif command -v apk >/dev/null; then apk add --no-cache python3 sudo openssh-server libcap-utils shadow; fi; \
    ssh-keygen -A >/dev/null 2>&1; mkdir -p /run/sshd; useradd -m -u 1001 auditor 2>/dev/null || adduser -D -u 1001 auditor
COPY privaudit /opt/priv-audit/privaudit
COPY priv-audit.py /opt/priv-audit/priv-audit.py
COPY tests/fixtures/run_corpus.py /root/run_corpus.py
CMD ["python3", "-I", "/root/run_corpus.py"]
