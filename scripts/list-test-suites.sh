#!/usr/bin/env bash
# list-test-suites.sh
#
# Enumerate every test-suite defined in any .cabal file under the current
# directory, resolve its main-is to a real source file, and report whether
# that file calls defaultMainStreaming (our shim) or upstream defaultMain.
#
# Output (tab-separated):
#   <suite-name>\t<package-dir>\t<main-path>\t<entry-point>
#
# entry-point is one of: STREAMING | upstream | unknown | MISSING

set -euo pipefail

ROOT="${1:-.}"

# Stage 1: find every (cabal-file, line, suite-name) triple, skipping
# build artefacts and other noise.
mapfile -t hits < <(
  grep -rEHin '^test-suite[[:space:]]+' \
    --include='*.cabal' \
    --exclude-dir=dist-newstyle \
    --exclude-dir=tasty-investigate \
    --exclude-dir=.git \
    --exclude-dir=node_modules \
    "$ROOT" 2>/dev/null || true
)

if [[ ${#hits[@]} -eq 0 ]]; then
  echo "No test-suite stanzas found under $ROOT" >&2
  exit 1
fi

# Stage 2: for each .cabal file, parse all its test-suite stanzas with awk,
# extracting suite name + main-is + hs-source-dirs.
# Then resolve the main-is against each hs-source-dir until a real file is
# found. Print one tab-separated row per resolved suite.
#
# We process each unique .cabal file once.
declare -A seen_cabal
for h in "${hits[@]}"; do
  cabal_file="${h%%:*}"
  if [[ -n "${seen_cabal[$cabal_file]:-}" ]]; then continue; fi
  seen_cabal[$cabal_file]=1

  pkg_dir="$(dirname "$cabal_file")"

  awk -v pkg_dir="$pkg_dir" '
    function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s }
    function lower(s) { return tolower(s) }

    function emit(    n, paths, i, p, found, abspath) {
      if (suite == "") return
      if (main_is == "") {
        print suite "\t" pkg_dir "\t" "MISSING" "\t" "MISSING"
        return
      }
      n = split(src_dirs, paths, /[[:space:],]+/)
      found = ""
      for (i = 1; i <= n; i++) {
        if (paths[i] == "") continue
        p = pkg_dir "/" paths[i] "/" main_is
        # use a portable file existence check
        if ((getline line < p) >= 0) {
          close(p)
          # getline returns -1 if file not openable. A 0/positive return
          # means it opened. But on an empty file it returns 0 too; check
          # explicitly with system.
        }
        if (system("test -f \"" p "\"") == 0) { found = p; break }
      }
      print suite "\t" pkg_dir "\t" (found != "" ? found : "MISSING") "\t" "PENDING"
    }

    # New top-level stanza header: lines starting at column 0 with a word
    # followed by whitespace. test-suite is what we care about; any other
    # top-level header (library, executable, common, etc.) closes the
    # current stanza.
    /^[a-zA-Z]/ {
      if (tolower($1) == "test-suite") {
        emit()
        suite = $2
        main_is = ""
        src_dirs = "."
        in_stanza = 1
        next
      } else if (in_stanza) {
        emit()
        suite = ""
        in_stanza = 0
      }
    }

    in_stanza && /^[[:space:]]+[Mm]ain-[Ii]s[[:space:]]*:/ {
      v = $0
      sub(/^[[:space:]]+[Mm]ain-[Ii]s[[:space:]]*:[[:space:]]*/, "", v)
      main_is = trim(v)
    }
    in_stanza && /^[[:space:]]+[Hh][Ss]-[Ss]ource-[Dd]irs[[:space:]]*:/ {
      v = $0
      sub(/^[[:space:]]+[Hh][Ss]-[Ss]ource-[Dd]irs[[:space:]]*:[[:space:]]*/, "", v)
      src_dirs = trim(v)
    }

    END { emit() }
  ' "$cabal_file"
done | while IFS=$'\t' read -r suite pkg_dir main_path _pending; do
  if [[ "$main_path" == "MISSING" ]]; then
    printf '%s\t%s\t%s\t%s\n' "$suite" "$pkg_dir" "MISSING" "unknown"
    continue
  fi
  if grep -qE 'defaultMainStreaming|Convex\.Tasty\.Streaming' "$main_path"; then
    entry="STREAMING"
  elif grep -qE '\bdefaultMain\b|defaultMainWithIngredients' "$main_path"; then
    entry="upstream"
  else
    entry="unknown"
  fi
  printf '%s\t%s\t%s\t%s\n' "$suite" "$pkg_dir" "$main_path" "$entry"
done
