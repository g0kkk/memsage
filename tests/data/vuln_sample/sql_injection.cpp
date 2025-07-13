#include <iostream>
#include <string>
#include <cstring>
#include <mysql/mysql.h>

// VULNERABILITY: SQL injection with string concatenation
void vulnerable_sql_query(const std::string& user_input) {
    MYSQL* conn = mysql_init(NULL);
    
    // VULNERABLE: Direct string concatenation
    std::string query = "SELECT * FROM users WHERE username = '" + user_input + "'";
    
    // Execute query without validation
    mysql_query(conn, query.c_str());
    
    std::cout << "Executed query: " << query << std::endl;
    mysql_close(conn);
}

// VULNERABILITY: SQL injection with sprintf
void vulnerable_sprintf_query(const char* user_input) {
    char query[256];
    
    // VULNERABLE: No input validation
    sprintf(query, "SELECT * FROM products WHERE name = '%s'", user_input);
    
    std::cout << "Query: " << query << std::endl;
}

// VULNERABILITY: SQL injection with multiple parameters
void vulnerable_multi_param_query(const std::string& username, const std::string& password) {
    // VULNERABLE: Multiple parameters without validation
    std::string query = "SELECT * FROM users WHERE username = '" + username + 
                       "' AND password = '" + password + "'";
    
    std::cout << "Multi-param query: " << query << std::endl;
}

// VULNERABILITY: SQL injection in INSERT statement
void vulnerable_insert_query(const std::string& name, const std::string& email) {
    // VULNERABLE: INSERT with string concatenation
    std::string query = "INSERT INTO users (name, email) VALUES ('" + name + "', '" + email + "')";
    
    std::cout << "Insert query: " << query << std::endl;
}

// VULNERABILITY: SQL injection in UPDATE statement
void vulnerable_update_query(const std::string& user_id, const std::string& new_value) {
    // VULNERABLE: UPDATE with string concatenation
    std::string query = "UPDATE users SET value = '" + new_value + "' WHERE id = " + user_id;
    
    std::cout << "Update query: " << query << std::endl;
}

// VULNERABILITY: SQL injection in DELETE statement
void vulnerable_delete_query(const std::string& user_id) {
    // VULNERABLE: DELETE with string concatenation
    std::string query = "DELETE FROM users WHERE id = " + user_id;
    
    std::cout << "Delete query: " << query << std::endl;
}

// VULNERABILITY: SQL injection with UNION attack
void vulnerable_union_query(const std::string& user_input) {
    // VULNERABLE: UNION attack possible
    std::string query = "SELECT name, email FROM users WHERE id = " + user_input;
    
    std::cout << "Union query: " << query << std::endl;
}

// VULNERABILITY: SQL injection with stacked queries
void vulnerable_stacked_query(const std::string& user_input) {
    // VULNERABLE: Multiple statements possible
    std::string query = "SELECT * FROM users WHERE id = " + user_input + "; DROP TABLE users;";
    
    std::cout << "Stacked query: " << query << std::endl;
}

// VULNERABILITY: SQL injection with time-based attack
void vulnerable_time_based_query(const std::string& user_input) {
    // VULNERABLE: Time-based attack possible
    std::string query = "SELECT * FROM users WHERE id = " + user_input + 
                       " AND (SELECT COUNT(*) FROM information_schema.tables) > 0";
    
    std::cout << "Time-based query: " << query << std::endl;
}

// VULNERABILITY: SQL injection with boolean-based attack
void vulnerable_boolean_based_query(const std::string& user_input) {
    // VULNERABLE: Boolean-based attack possible
    std::string query = "SELECT * FROM users WHERE id = " + user_input + 
                       " AND 1=1";
    
    std::cout << "Boolean-based query: " << query << std::endl;
}

int main() {
    std::cout << "Testing SQL injection vulnerabilities..." << std::endl;
    
    // Test cases with malicious input
    std::string malicious_input = "'; DROP TABLE users; --";
    std::string union_input = "1 UNION SELECT username, password FROM users";
    std::string stacked_input = "1; INSERT INTO users VALUES ('hacker', 'password')";
    
    vulnerable_sql_query(malicious_input);
    vulnerable_sprintf_query("'; DROP TABLE products; --");
    vulnerable_multi_param_query("admin", "'; DROP TABLE users; --");
    vulnerable_insert_query("'; DROP TABLE users; --", "hacker@evil.com");
    vulnerable_update_query("1", "'; DROP TABLE users; --");
    vulnerable_delete_query("1; DROP TABLE users; --");
    vulnerable_union_query(union_input);
    vulnerable_stacked_query(stacked_input);
    vulnerable_time_based_query("1 AND SLEEP(5)");
    vulnerable_boolean_based_query("1 AND 1=1");
    
    return 0;
} 