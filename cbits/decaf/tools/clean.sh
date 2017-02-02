#!/bin/sh

# Usage: ./clean.sh
#
# Remove all files created by 'generate.sh'.

DEST_DIR="`dirname "$0"`"/..

rm    "$DEST_DIR"/*.c
rm    "$DEST_DIR"/include/constant_time.h
rm    "$DEST_DIR"/include/field.h
rm    "$DEST_DIR"/include/portable_endian.h
rm    "$DEST_DIR"/include/word.h
rm    "$DEST_DIR"/include/decaf.h
rm    "$DEST_DIR"/include/decaf/common.h
rm    "$DEST_DIR"/include/decaf/ed448.h
rm    "$DEST_DIR"/include/decaf/point_255.h
rm    "$DEST_DIR"/include/decaf/point_448.h
rm    "$DEST_DIR"/include/decaf/sha512.h
rm -r "$DEST_DIR"/include/arch_*
rm -r "$DEST_DIR"/ed448goldilocks
rm -r "$DEST_DIR"/p448
