#!/bin/sh

# Usage: ./generate.sh /path/to/ed448goldilocks-code
#
# Generate all files from ed448goldilocks branch 'master'
# (available at <git://git.code.sf.net/p/ed448goldilocks/code>).
#
# Project is synced with upstream commit
# '807a7e67decbf8ccc10be862cdf9ae03653ffe70'.
#
# Notes about transformations applied:
#
# * only a subset of library files are used, cryptonite needing only x448
#   and ed448.  Some headers like point_255.h are still included but copied
#   empty, as the definitions are not necessary.  Only the simplest
#   architectures arch_32 and arch_ref64 are used to get the best
#   compatibility and generality over performance.
#
# * substitutions are performed in order to add a cryptonite_ prefix
#   to all external symbols
#
# * code related to SHAKE is replaced by cryptonite code, referenced from
#   a custom shake.h.  As a consequence, portable_endian.h is not needed.
#
# * aligned(32) attributes used for stack alignment are replaced by
#   aligned(16).  This removes warnings on OpenBSD with GCC 4.2.1, and makes
#   sure we get at least 16-byte alignment.  32-byte alignment is necessary
#   only for AVX2 and arch_x86_64, which we don't have.
#
# * visibility("hidden") attributes are removed, as this is not supported
#   on Windows/MinGW, and we have name mangling instead
#
# * function posix_memalign is defined in order to avoid a warning on
#   Windows/MinGW.  Hopefully it is not called.  This definition is put
#   inside portable_endian.h because this file is already included.
#
# * files decaf.c and decaf_tables.c are compiled to a single object file
#   decaf_all.o to avoid link failure on OpenBSD with --strip-unneeded
#   and old versions of binutils (see #186)

SRC_DIR="$1/src"
DEST_DIR="`dirname "$0"`"/..

ARCHITECTURES="arch_32 arch_ref64"

if [ ! -d "$SRC_DIR" ]; then
  echo "$0: invalid source directory: $1" && exit 1
fi

convert() {
  local FILE_NAME="`basename "$1"`"
  local REPL

  if [ "$FILE_NAME" = word.h ]; then
    REPL='__attribute__((aligned(32)))'
  else
    REPL='__attribute__((aligned(16)))'
  fi

  sed <"$1" >"$2/$FILE_NAME" \
    -e 's/ __attribute((visibility("hidden")))//g' \
    -e 's/ __attribute__((visibility("hidden")))//g' \
    -e 's/ __attribute__ ((visibility ("hidden")))//g' \
    -e "s/__attribute__((aligned(32)))/$REPL/g" \
    -e 's/decaf_/cryptonite_decaf_/g' \
    -e 's/DECAF_/CRYPTONITE_DECAF_/g' \
    -e 's/gf_/cryptonite_gf_/g' \
    -e 's/keccakf/cryptonite_keccakf/g' \
    -e 's/NO_CONTEXT_POINTS_HERE/CRYPTONITE_NO_CONTEXT_POINTS_HERE/g' \
    -e 's/P25519_SQRT_MINUS_ONE/CRYPTONITE_P25519_SQRT_MINUS_ONE/g'
}

convert "$SRC_DIR"/utils.c  "$DEST_DIR"

mkdir -p "$DEST_DIR"/include
convert "$SRC_DIR"/include/constant_time.h   "$DEST_DIR"/include
convert "$SRC_DIR"/include/field.h           "$DEST_DIR"/include
convert "$SRC_DIR"/include/word.h            "$DEST_DIR"/include

for ARCH in $ARCHITECTURES; do
  mkdir -p "$DEST_DIR"/include/$ARCH
  convert "$SRC_DIR"/include/$ARCH/arch_intrinsics.h "$DEST_DIR"/include/$ARCH
done

mkdir -p "$DEST_DIR"/include/decaf
convert "$SRC_DIR"/GENERATED/include/decaf.h           "$DEST_DIR"/include
convert "$SRC_DIR"/GENERATED/include/decaf/common.h    "$DEST_DIR"/include/decaf
convert "$SRC_DIR"/GENERATED/include/decaf/ed448.h     "$DEST_DIR"/include/decaf
convert "$SRC_DIR"/GENERATED/include/decaf/point_448.h "$DEST_DIR"/include/decaf

for CURVE in ed448goldilocks; do
  mkdir -p "$DEST_DIR"/$CURVE
  convert "$SRC_DIR"/GENERATED/c/$CURVE/decaf.c        "$DEST_DIR"/$CURVE
  convert "$SRC_DIR"/GENERATED/c/$CURVE/decaf_tables.c "$DEST_DIR"/$CURVE
  convert "$SRC_DIR"/GENERATED/c/$CURVE/eddsa.c        "$DEST_DIR"/$CURVE
  convert "$SRC_DIR"/GENERATED/c/$CURVE/scalar.c       "$DEST_DIR"/$CURVE

  cat > "$DEST_DIR"/$CURVE/decaf_all.c <<EOF
/* Combined to avoid link failure on OpenBSD with --strip-unneeded, see #186 */
#include "decaf.c"
#include "decaf_tables.c"
EOF
done

for FIELD in p448; do
  mkdir -p "$DEST_DIR"/$FIELD
  convert "$SRC_DIR"/$FIELD/f_arithmetic.c          "$DEST_DIR"/$FIELD
  convert "$SRC_DIR"/GENERATED/c/$FIELD/f_generic.c "$DEST_DIR"/$FIELD
  convert "$SRC_DIR"/GENERATED/c/$FIELD/f_field.h   "$DEST_DIR"/$FIELD

  for ARCH in $ARCHITECTURES; do
    mkdir -p "$DEST_DIR"/$FIELD/$ARCH
    convert "$SRC_DIR"/$FIELD/$ARCH/f_impl.h        "$DEST_DIR"/$FIELD/$ARCH
    convert "$SRC_DIR"/$FIELD/$ARCH/f_impl.c        "$DEST_DIR"/$FIELD/$ARCH
  done
done

for FILE in point_255.h sha512.h; do
  cat > "$DEST_DIR"/include/decaf/$FILE <<EOF
/* Not needed if 448-only */
EOF
done

cat >"$DEST_DIR"/include/portable_endian.h <<EOF
/* portable_endian.h not used */

#if defined(__MINGW32__)
// does not exist on MinGW, but unused anyway
extern int posix_memalign(void **, size_t, size_t);
#endif
EOF
