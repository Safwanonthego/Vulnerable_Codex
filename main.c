#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

/*
 * Intentionally vulnerable test fixture.
 * For static-analysis testing only.
 * Do not use in production.
 */

char global_buffer[64];
char *global_pointer;

void unsafe_copy(const char *input)
{
    char buffer[16];

    /* CWE-120: Buffer Copy without Checking Size of Input */
    strcpy(buffer, input);

    printf("Copied: %s\n", buffer);
}

void unsafe_format(const char *input)
{
    /* CWE-134: Use of Externally-Controlled Format String */
    printf(input);
    printf("\n");
}

void unsafe_allocation(int size)
{
    /* CWE-789: Memory Allocation with Excessive Size Value */
    char *buffer = malloc(size);

    if (buffer != NULL) {
        memset(buffer, 0, size);
        free(buffer);
    }
}

void unsafe_integer_operation(int count)
{
    /* CWE-190: Integer Overflow or Wraparound */
    int allocation_size = count * 100;

    char *buffer = malloc(allocation_size);

    if (buffer != NULL) {
        free(buffer);
    }
}

void unsafe_environment(void)
{
    /* CWE-807: Reliance on Untrusted Inputs */
    char *path = getenv("PATH");

    if (path != NULL) {
        printf("Environment PATH: %s\n", path);
    }
}

void unsafe_file_operation(const char *filename)
{
    /*
     * CWE-362: Potential Race Condition
     * The file is checked before it is opened.
     */
    if (access(filename, F_OK) == 0) {
        FILE *file = fopen(filename, "r");

        if (file != NULL) {
            char buffer[128];

            if (fgets(buffer, sizeof(buffer), file) != NULL) {
                printf("%s", buffer);
            }

            fclose(file);
        }
    }
}

void unsafe_memory_management(void)
{
    /* CWE-476: NULL Pointer Dereference */
    int *ptr = malloc(sizeof(int));

    *ptr = 100;

    printf("Value: %d\n", *ptr);

    /* CWE-416: Use After Free */
    free(ptr);

    /* Intentionally accesses freed memory. */
    printf("Freed value: %d\n", *ptr);
}

void unsafe_memory_leak(void)
{
    /* CWE-401: Missing Release of Memory after Effective Lifetime */
    char *buffer = malloc(1024);

    if (buffer != NULL) {
        strcpy(buffer, "Allocated memory is never released");
        printf("%s\n", buffer);

        /* Intentionally missing free(buffer). */
    }
}

void unsafe_global_buffer(const char *input)
{
    /* CWE-120: Buffer Overflow */
    strcpy(global_buffer, input);

    global_pointer = global_buffer;

    printf("Global buffer: %s\n", global_pointer);
}

void unsafe_command_execution(const char *command)
{
    /*
     * CWE-78: Improper Neutralization of Special Elements
     * Used in an OS Command.
     *
     * Executes an externally supplied command.
     */
    system(command);
}

void unsafe_temp_file(void)
{
    /*
     * CWE-377: Insecure Temporary File
     * Uses a predictable filename.
     */
    FILE *file = fopen("/tmp/unsafe_test_file.txt", "w");

    if (file != NULL) {
        fprintf(file, "Temporary test data\n");
        fclose(file);
    }
}

void unsafe_file_permissions(const char *filename)
{
    /*
     * CWE-732: Incorrect Permission Assignment
     * Grants broad permissions.
     */
    chmod(filename, 0777);
}

void unsafe_input(void)
{
    char input[32];

    /*
     * CWE-120: Potential Buffer Overflow
     * scanf does not limit the input length here.
     */
    scanf("%s", input);

    printf("Input: %s\n", input);
}

int main(int argc, char *argv[])
{
    printf("Static Analysis Test Fixture\n");

    unsafe_environment();
    unsafe_memory_leak();
    unsafe_temp_file();

    if (argc > 1) {
        unsafe_copy(argv[1]);
        unsafe_format(argv[1]);
        unsafe_global_buffer(argv[1]);
        unsafe_command_execution(argv[1]);
    }

    if (argc > 2) {
        unsafe_file_operation(argv[2]);
        unsafe_file_permissions(argv[2]);
    }

    unsafe_allocation(128);
    unsafe_integer_operation(100);

    /*
     * These functions contain intentional memory-safety issues.
     * Call them only in an isolated testing environment.
     *
     * unsafe_memory_management();
     * unsafe_input();
     */

    return 0;
}
