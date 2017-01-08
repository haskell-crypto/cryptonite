/*
  The Makefile in the original project uses variable include directories
  for each field, but Cabal does not support this.  The following trick
  preloads the field-dependent headers "f_field.h" and "f_impl.h" so that
  further includes of "field.h" have nothing to do later.
*/
#include "p448/arch_ref64/field.h"
#include "p448/arch_ref64/f_impl.c"

#include "ed448goldilocks/decaf.c"
#include "ed448goldilocks/decaf_tables.c"
#include "ed448goldilocks/eddsa.c"
#include "ed448goldilocks/scalar.c"
#include "p448/f_arithmetic.c"
#include "p448/f_generic.c"
