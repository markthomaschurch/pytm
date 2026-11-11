# pytm-tools: pytm plus everything needed to turn a threat model into
# diagrams and reports (Graphviz, PlantUML, pandoc and LaTeX).
#
#   docker build -t pytm .
#   docker run --rm -v "$PWD":/work pytm            # every *_tm.py in $PWD
#   docker run --rm -v "$PWD":/work pytm help       # targets and options
#
# See README.md ("Using the Docker image").
FROM python:3.14-slim-trixie

ARG PLANTUML_VERSION=1.2026.2
# No checksum is published for the jar; this is the SHA-256 of the release
# asset, so a changed download fails the build.
ARG PLANTUML_SHA256=397fe169dd408b0f039e8b7be2a12c2d52d35a3399802921b8c84f29cf39e45a

# The container usually runs as the owner of /work (see the entrypoint),
# who has no home directory, so caches go to /tmp. TEXMFVAR holds
# LuaLaTeX's font cache, built below so runs don't rebuild it.
ENV PLANTUML_PATH=/usr/local/lib/plantuml.jar \
    HOME=/tmp \
    XDG_CACHE_HOME=/tmp/.cache \
    TEXMFVAR=/var/cache/texmf-var \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        make curl ca-certificates \
        graphviz librsvg2-bin \
        default-jre-headless \
        pandoc \
        texlive-latex-recommended texlive-latex-extra texlive-luatex \
        texlive-fonts-recommended lmodern \
        fontconfig fonts-liberation fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# Download PlantUML, check it, and fail the build if it can't render.
RUN curl -sSLf -o "$PLANTUML_PATH" \
        "https://github.com/plantuml/plantuml/releases/download/v${PLANTUML_VERSION}/plantuml-mit-${PLANTUML_VERSION}.jar" \
    && echo "${PLANTUML_SHA256}  ${PLANTUML_PATH}" | sha256sum -c - \
    && printf '@startuml\nA -> B\n@enduml\n' | java -Djava.awt.headless=true -jar "$PLANTUML_PATH" -tpng -pipe > /dev/null

# Build LuaLaTeX's font database once. It stays writable by any user, so
# a theme's own fonts can be added to it at run time.
RUN mkdir -p "$TEXMFVAR" \
    && luaotfload-tool --update > /dev/null \
    && chmod -R a+rwX "$TEXMFVAR"

WORKDIR /usr/src/pytm
COPY pyproject.toml README.md LICENSE ./
COPY pytm ./pytm
RUN pip install ".[jinja]" && cd / && rm -rf /usr/src/pytm

COPY docker/Makefile /usr/local/share/pytm/Makefile
COPY docker/entrypoint.sh /usr/local/bin/pytm-tools
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/pytm-tools"]
CMD ["all"]
