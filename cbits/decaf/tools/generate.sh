#!/bin/sh

# Usage: ./generate.sh /path/to/ed448goldilocks-code
#
# Generate all files from ed448goldilocks branch 'master'
# (available at <git://git.code.sf.net/p/ed448goldilocks/code>).
#
# Project is synced with upstream commit
# '0a6e96827595fa1a5a62d12ac83c3cc5dda6dd67', i.e. tag 'v0.9.2'.
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

SRC_DIR="$1/src"
DEST_DIR="`dirname "$0"`"/..

ARCHITECTURES="arch_32 arch_ref64"

if [ ! -d "$SRC_DIR" ]; then
  echo "$0: invalid source directory: $1" && exit 1
fi

convert() {
  local FILE_NAME="`basename "$1"`"
  sed <"$1" >"$2/$FILE_NAME" \
    -e 's/decaf_/cryptonite_decaf_/g' \
    -e 's/DECAF_/CRYPTONITE_DECAF_/g' \
    -e 's/gf_/cryptonite_gf_/g' \
    -e 's/keccakf/cryptonite_keccakf/g' \
    -e 's/NO_CONTEXT_POINTS_HERE/CRYPTONITE_NO_CONTEXT_POINTS_HERE/g' \
    -e 's/P25519_SQRT_MINUS_ONE/CRYPTONITE_P25519_SQRT_MINUS_ONE/g'
}

convert "$SRC_DIR"/shake.c  "$DEST_DIR"
convert "$SRC_DIR"/utils.c  "$DEST_DIR"

mkdir -p "$DEST_DIR"/include
convert "$SRC_DIR"/include/constant_time.h   "$DEST_DIR"/include
convert "$SRC_DIR"/include/field.h           "$DEST_DIR"/include
convert "$SRC_DIR"/include/keccak_internal.h "$DEST_DIR"/include
convert "$SRC_DIR"/include/portable_endian.h "$DEST_DIR"/include
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
convert "$SRC_DIR"/GENERATED/include/decaf/shake.h     "$DEST_DIR"/include/decaf

for CURVE in ed448goldilocks; do
  mkdir -p "$DEST_DIR"/$CURVE
  convert "$SRC_DIR"/GENERATED/c/$CURVE/decaf.c        "$DEST_DIR"/$CURVE
  convert "$SRC_DIR"/GENERATED/c/$CURVE/decaf_tables.c "$DEST_DIR"/$CURVE
  convert "$SRC_DIR"/GENERATED/c/$CURVE/eddsa.c        "$DEST_DIR"/$CURVE
  convert "$SRC_DIR"/GENERATED/c/$CURVE/scalar.c       "$DEST_DIR"/$CURVE
done

for FIELD in p448; do
  if [ $FIELD = p25519 ]; then
    CURVE=curve25519
  elif [ $FIELD = p448 ]; then
    CURVE=ed448goldilocks
  else
    echo "Invalid field: $FIELD" && exit 1
  fi

  mkdir -p "$DEST_DIR"/$FIELD
  convert "$SRC_DIR"/$FIELD/f_arithmetic.c          "$DEST_DIR"/$FIELD
  convert "$SRC_DIR"/GENERATED/c/$FIELD/f_generic.c "$DEST_DIR"/$FIELD

  for ARCH in $ARCHITECTURES; do
    mkdir -p "$DEST_DIR"/$FIELD/$ARCH
    convert "$SRC_DIR"/include/field.h              "$DEST_DIR"/$FIELD/$ARCH
    convert "$SRC_DIR"/GENERATED/c/$FIELD/f_field.h "$DEST_DIR"/$FIELD/$ARCH
    convert "$SRC_DIR"/$FIELD/$ARCH/f_impl.h        "$DEST_DIR"/$FIELD/$ARCH
    convert "$SRC_DIR"/$FIELD/$ARCH/f_impl.c        "$DEST_DIR"/$FIELD/$ARCH

    cat > "$DEST_DIR"/cryptonite_$FIELD\_$ARCH.c <<EOF
/*
  The Makefile in the original project uses variable include directories
  for each field, but Cabal does not support this.  The following trick
  preloads the field-dependent headers "f_field.h" and "f_impl.h" so that
  further includes of "field.h" have nothing to do later.
*/
#include "$FIELD/$ARCH/field.h"
#include "$FIELD/$ARCH/f_impl.c"

#include "$CURVE/decaf.c"
#include "$CURVE/decaf_tables.c"
#include "$CURVE/eddsa.c"
#include "$CURVE/scalar.c"
#include "$FIELD/f_arithmetic.c"
#include "$FIELD/f_generic.c"
EOF
  done
done

for FILE in point_255.h sha512.h; do
  cat > "$DEST_DIR"/include/decaf/$FILE <<EOF
/* Not needed if 448-only */
EOF
done
