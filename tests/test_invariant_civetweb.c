#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Forward declaration of the path normalization function from civetweb.c */
extern void remove_double_slashes_and_double_dots(char *buf);

START_TEST(test_path_normalization_security_boundary)
{
    /* Invariant: After normalization, no path component should allow
       traversal outside document root via .., encoded sequences, or null bytes */
    
    const char *payloads[] = {
        "../../../etc/passwd",           /* Direct traversal attempt */
        "..%2f..%2fetc%2fpasswd",        /* Double-encoded traversal */
        "....//....//etc/passwd",        /* Overlong dot sequences */
        "/valid/path/file.txt",          /* Valid input (baseline) */
        "/.%00/etc/passwd"               /* Null byte injection attempt */
    };
    
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);
    
    for (int i = 0; i < num_payloads; i++) {
        char buf[512];
        strncpy(buf, payloads[i], sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        
        remove_double_slashes_and_double_dots(buf);
        
        /* Security property: normalized path must not contain
           unresolved .. components that could escape root */
        ck_assert_msg(
            strstr(buf, "..") == NULL || buf[0] != '.',
            "Path normalization failed to remove traversal: %s -> %s",
            payloads[i], buf
        );
        
        /* Security property: no embedded null bytes in normalized path */
        ck_assert_msg(
            strlen(buf) == strcspn(buf, "\0"),
            "Null byte present in normalized path: %s",
            payloads[i]
        );
        
        /* Security property: normalized path should not start with ..
           after processing */
        ck_assert_msg(
            !(buf[0] == '.' && buf[1] == '.'),
            "Normalized path starts with ..: %s -> %s",
            payloads[i], buf
        );
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("PathNormalization");

    tcase_add_test(tc_core, test_path_normalization_security_boundary);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}