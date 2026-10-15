<?php

/*
 * Intentionally Vulnerable PHP Test Fixture
 * Purpose: Static analysis and security testing.
 * Do not deploy this application to production.
 */

error_reporting(E_ALL);
ini_set('display_errors', '1');

/*
 * CWE-79: Cross-Site Scripting (XSS)
 * User-controlled input is printed without HTML escaping.
 */
function unsafe_xss(): void
{
    $name = $_GET['name'] ?? 'Guest';

    echo "<h1>Welcome, " . $name . "</h1>";
}

/*
 * CWE-89: SQL Injection
 * User input is concatenated into an SQL query.
 */
function unsafe_sql(): void
{
    $id = $_GET['id'] ?? '1';

    $db = new mysqli(
        'localhost',
        'test_user',
        'test_password',
        'test_database'
    );

    if ($db->connect_error) {
        die("Database connection failed");
    }

    $query = "SELECT * FROM users WHERE id = '$id'";

    $result = $db->query($query);

    if ($result) {
        while ($row = $result->fetch_assoc()) {
            print_r($row);
        }
    }

    $db->close();
}

/*
 * CWE-78: OS Command Injection
 * External input is passed to a shell command.
 */
function unsafe_command(): void
{
    $filename = $_GET['file'] ?? '';

    $command = "cat " . $filename;

    $output = shell_exec($command);

    echo "<pre>" . $output . "</pre>";
}

/*
 * CWE-22: Path Traversal
 * User-controlled input determines the file path.
 */
function unsafe_file_read(): void
{
    $filename = $_GET['path'] ?? '';

    $content = file_get_contents(
        __DIR__ . "/files/" . $filename
    );

    if ($content !== false) {
        echo $content;
    }
}

/*
 * CWE-98: Improper Control of Filename for
 * Include/Require Statement.
 */
function unsafe_include(): void
{
    $page = $_GET['page'] ?? 'home.php';

    include($page);
}

/*
 * CWE-327: Use of a Broken or Risky Cryptographic Algorithm.
 * MD5 is unsuitable for password hashing.
 */
function unsafe_password_hashing(): void
{
    $password = $_POST['password'] ?? '';

    $hash = md5($password);

    echo "Password hash: " . $hash;
}

/*
 * CWE-798: Use of Hard-coded Credentials.
 */
function unsafe_credentials(): void
{
    $username = "admin";
    $password = "Admin123!";

    echo "Configured account: " . $username;
}

/*
 * CWE-532: Insertion of Sensitive Information into Log File.
 */
function unsafe_logging(): void
{
    $password = $_POST['password'] ?? '';

    error_log("Login attempt with password: " . $password);
}

/*
 * CWE-209: Generation of Error Message Containing Sensitive
 * Information.
 */
function unsafe_error_message(): void
{
    try {
        throw new Exception("Database connection failed");
    } catch (Exception $e) {
        echo $e;
    }
}

/*
 * CWE-614: Sensitive Cookie Without Secure Attribute.
 */
function unsafe_cookie(): void
{
    setcookie(
        "session_token",
        "test-session-token",
        [
            'expires' => time() + 3600,
            'path' => '/',
            'httponly' => false,
            'secure' => false,
            'samesite' => 'Lax'
        ]
    );
}

/*
 * CWE-352: Cross-Site Request Forgery (CSRF).
 * State-changing operation without a CSRF token.
 */
function unsafe_state_change(): void
{
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $email = $_POST['email'] ?? '';

        echo "Email updated to: " . $email;
    }
}

/*
 * CWE-732: Incorrect Permission Assignment.
 * Creates a file with broadly accessible permissions.
 */
function unsafe_permissions(): void
{
    $filename = __DIR__ . "/test_output.txt";

    file_put_contents($filename, "Sensitive test data");

    chmod($filename, 0777);
}

/*
 * CWE-476: NULL Pointer / Invalid Value Handling.
 * Demonstrates unsafe assumptions about function results.
 */
function unsafe_array_access(): void
{
    $data = [];

    echo $data['user']['name'];
}

/*
 * CWE-20: Improper Input Validation.
 * Input is used without validating its expected format.
 */
function unsafe_input_validation(): void
{
    $age = $_GET['age'] ?? '';

    echo "Age: " . $age;
}

/*
 * CWE-362: Race Condition.
 * File existence is checked before a separate file operation.
 */
function unsafe_file_check(): void
{
    $filename = __DIR__ . "/test_data.txt";

    if (file_exists($filename)) {
        $content = file_get_contents($filename);

        echo $content;
    }
}

/*
 * CWE-601: Open Redirect.
 * A user-controlled URL is used as a redirect destination.
 */
function unsafe_redirect(): void
{
    $url = $_GET['redirect'] ?? '/';

    header("Location: " . $url);
    exit;
}

/*
 * CWE-770: Allocation of Resources Without Limits.
 * Reads a user-controlled amount of data into memory.
 */
function unsafe_resource_usage(): void
{
    $size = (int) ($_GET['size'] ?? 1024);

    $data = str_repeat('A', $size);

    echo "Generated data length: " . strlen($data);
}

/*
 * CWE-434: Unrestricted File Upload.
 * Uploaded file is saved without validating its type.
 */
function unsafe_upload(): void
{
    if (isset($_FILES['upload'])) {
        $destination = __DIR__ . "/uploads/" .
            $_FILES['upload']['name'];

        move_uploaded_file(
            $_FILES['upload']['tmp_name'],
            $destination
        );

        echo "Upload processed";
    }
}

/*
 * CWE-89 / CWE-79 / CWE-78 test entry points.
 * Functions are called only when explicitly requested.
 */
$test = $_GET['test'] ?? '';

switch ($test) {
    case 'xss':
        unsafe_xss();
        break;

    case 'sql':
        unsafe_sql();
        break;

    case 'command':
        unsafe_command();
        break;

    case 'file':
        unsafe_file_read();
        break;

    case 'include':
        unsafe_include();
        break;

    case 'hash':
        unsafe_password_hashing();
        break;

    case 'credentials':
        unsafe_credentials();
        break;

    case 'logging':
        unsafe_logging();
        break;

    case 'error':
        unsafe_error_message();
        break;

    case 'cookie':
        unsafe_cookie();
        break;

    case 'csrf':
        unsafe_state_change();
        break;

    case 'permissions':
        unsafe_permissions();
        break;

    case 'array':
        unsafe_array_access();
        break;

    case 'validation':
        unsafe_input_validation();
        break;

    case 'race':
        unsafe_file_check();
        break;

    case 'redirect':
        unsafe_redirect();
        break;

    case 'resource':
        unsafe_resource_usage();
        break;

    case 'upload':
        unsafe_upload();
        break;

    default:
        echo "PHP Static Analysis Test Fixture";
        echo "\nAvailable test cases: ";
        echo "xss, sql, command, file, include, hash, ";
        echo "credentials, logging, error, cookie, csrf, ";
        echo "permissions, array, validation, race, ";
        echo "redirect, resource, upload";
        break;
}
