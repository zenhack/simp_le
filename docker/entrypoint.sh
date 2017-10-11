#!/bin/sh

set -e

# following recommendations for a consistent interface:
# https://github.com/docker-library/official-images#consistency

# if the first argument given to the entrypoint script is an
# hyphenated flag, execute simp_le with this(those) flag(s),
# else default to run whatever the user wanted like "bash"

case "$1" in
    -*) exec simp_le "$@" ;;
    *) exec "$@" ;;
esac
