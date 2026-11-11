#!/bin/sh
# Smoke test of the pytm Docker image: build the example model, with and
# without a LuaLaTeX theme, and check what the image writes.
#
#   docker/test-image.sh [IMAGE]      (default: pytm)
set -eu

image="${1:-pytm}"
repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# Does any of the files (a glob's expansion) exist?
exists() {
    for f in "$@"; do
        [ -e "$f" ] && return 0
    done
    return 1
}

run() {
    docker run --rm -v "$work/project":/work "$@"
}

mkdir -p "$work/project"
cp "$repo/tm.py" "$work/project/sample_tm.py"

echo "== build every model"
run "$image"
out="$work/project/sample_tm"
for f in dfd.png seq.png report.md report.html report.pdf; do
    test -s "$out/$f" || fail "$f was not written"
done
for f in dfd.png seq.png; do
    head -c 8 "$out/$f" | od -An -c | grep -q 'P   N   G' || fail "$f is not a PNG"
done
head -c 5 "$out/report.pdf" | grep -q '%PDF-' || fail "report.pdf is not a PDF"
exists "$out"/thumbnails/report/legend-shape-*.png || fail "no legend images"
exists "$out"/thumbnails/report/actor-*.png || fail "no thumbnails"
grep -q "thumbnails/report/" "$out/report.md" || fail "report.md doesn't link thumbnails"
grep -q '<img src="data:image/png' "$out/report.html" || fail "report.html images not embedded"

echo "== files belong to the owner of the project, not root"
owner=$(stat -c %u:%g "$work/project")
for f in "$out" "$out/report.pdf" "$out/thumbnails"; do
    test "$(stat -c %u:%g "$f")" = "$owner" || fail "$f is owned by $(stat -c %u:%g "$f")"
done

echo "== nothing is rebuilt when the model hasn't changed"
run "$image" | grep -q "Nothing to be done" || fail "files were rebuilt"

echo "== a theme with LuaLaTeX"
mkdir -p "$work/theme"
printf 'standalone: true\nembed-resources: true\nmetadata:\n  title-prefix: themed\n' \
    > "$work/theme/html.yaml"
printf 'pdf-engine: lualatex\nvariables:\n  mainfont: DejaVu Serif\n' \
    > "$work/theme/pdf.yaml"
docker run --rm -v "$work/project":/work -v "$work/theme:$work/theme:ro" \
    "$image" OUT=themed THEME="$work/theme"
themed="$work/project/themed/sample_tm"
grep -q '<title>themed' "$themed/report.html" || fail "html.yaml was not applied"
# The theme picks LuaLaTeX (and a system font, which needs luaotfload's
# font database); the default would be pdflatex.
grep -aq 'LuaTeX' "$themed/report.pdf" || fail "report.pdf was not made by LuaLaTeX"

echo "== the old usage: [target] [model.py]"
cp "$repo/tm.py" "$work/project/tm.py"
run "$image" dfd tm.py
test -s "$work/project/tm/dfd.png" || fail "old usage didn't write tm/dfd.png"
test ! -e "$work/project/tm/seq.png" || fail "old usage built more than the target"

echo "== errors"
mkdir -p "$work/empty"
if docker run --rm -v "$work/empty":/work "$image" 2> "$work/err"; then
    fail "an empty /work did not fail"
fi
grep -q "Nothing in /work" "$work/err" || fail "unexpected message: $(cat "$work/err")"

echo "PASS"
