#ifndef TESTS_CMOCKA_COMPAT_H
#define TESTS_CMOCKA_COMPAT_H

#include <cmocka.h>

/*
 * cmocka 2.0.0 added the type-safe mock/assert macros and deprecated the old
 * ones. Older versions, still shipped by CentOS and Alpine, only provide the
 * deprecated macros and do not ship cmocka_version.h, so map the new names
 * back to the old ones where the new macros are missing.
 */

#ifndef check_expected_int
#define check_expected_int check_expected
#endif

#ifndef expect_int_value
#define expect_int_value expect_value
#endif

#ifndef assert_int_in_range
#define assert_int_in_range assert_in_range
#endif

#ifndef assert_uint_in_range
#define assert_uint_in_range assert_in_range
#endif

#endif /* TESTS_CMOCKA_COMPAT_H */
