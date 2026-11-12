#!/bin/sh
# Entrypoint of the pytm Docker image: run the pytm Makefile in /work.
#
#   docker run --rm -v "$PWD":/work pytm [TARGET...] [VARIABLE=value...] [model.py...]
#
# Model files given as arguments are built instead of every *_tm.py.
# Run with "help" for the targets and variables.
set -eu

makefile=/usr/local/share/pytm/Makefile

if [ ! -d /work ] || [ -z "$(ls -A /work 2>/dev/null)" ]; then
    echo "Nothing in /work: mount your project there, e.g." >&2
    echo "  docker run --rm -v \"\$PWD\":/work pytm" >&2
    exit 1
fi

# Model files (*.py) given as arguments become MODELS=...
models=""
for arg in "$@"; do
    shift
    case "$arg" in
        *=*) set -- "$@" "$arg" ;;
        *.py) models="${models:+$models }$arg" ;;
        *) set -- "$@" "$arg" ;;
    esac
done
if [ -n "$models" ]; then
    set -- "$@" "MODELS=$models"
fi

# Write files as the owner of /work rather than root (unless started with
# --user, or /work belongs to root).
if [ "$(id -u)" = 0 ]; then
    owner=$(stat -c %u:%g /work)
    if [ "$owner" != 0:0 ]; then
        exec setpriv --reuid="${owner%:*}" --regid="${owner#*:}" --clear-groups \
            make --no-print-directory -f "$makefile" -C /work "$@"
    fi
fi
exec make --no-print-directory -f "$makefile" -C /work "$@"
