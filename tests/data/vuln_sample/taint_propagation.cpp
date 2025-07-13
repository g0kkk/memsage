#include <cstdio>
#include <cstring>
#include <cstdlib>

// Function that processes tainted input
void process_user_input(char* input) {
    char buffer[100];
    strcpy(buffer, input);  // Dangerous operation with tainted input
    printf("Processed: %s\n", buffer);
}

// Function that doesn't process tainted input safely
void safe_function(char* input) {
    printf("Safe display: %s\n", input);
}

// Function that processes tainted input and calls another function
void intermediate_function(char* data) {
    char temp_buffer[50];
    strcpy(temp_buffer, data);  // Taint propagation
    process_user_input(temp_buffer);  // Further taint propagation
}

// Function chain for taint propagation
void function_c(char* data) {
    char buffer[50];
    strcpy(buffer, data);  // Final sink
    printf("Function C: %s\n", buffer);
}

void function_b(char* data) {
    function_c(data);  // Pass tainted data
}

void function_a(char* data) {
    function_b(data);  // Pass tainted data
}

// Function with multiple tainted parameters
void multi_parameter_function(char* input1, char* input2, int size) {
    char buffer[200];
    sprintf(buffer, "%s-%s", input1, input2);  // Taint propagation with multiple sources
    printf("Combined: %s\n", buffer);
}

// Function that sanitizes input
void sanitize_and_process(char* input) {
    char sanitized[100];
    // Simple sanitization (in practice, this would be more robust)
    strncpy(sanitized, input, sizeof(sanitized) - 1);
    sanitized[sizeof(sanitized) - 1] = '\0';
    
    // Now process sanitized input
    printf("Sanitized: %s\n", sanitized);
}

int main() {
    char user_input[100];
    char second_input[100];
    int user_size;
    
    // Get tainted input
    printf("Enter first input: ");
    fgets(user_input, sizeof(user_input), stdin);  // Source
    
    printf("Enter second input: ");
    fgets(second_input, sizeof(second_input), stdin);  // Source
    
    printf("Enter size: ");
    scanf("%d", &user_size);  // Source
    
    // Test various taint propagation scenarios
    process_user_input(user_input);  // Direct taint propagation
    safe_function(user_input);       // Taint propagation to safe function
    intermediate_function(user_input);  // Multi-level taint propagation
    function_a(user_input);          // Chain taint propagation
    
    // Test multiple parameter taint propagation
    multi_parameter_function(user_input, second_input, user_size);
    
    // Test sanitization
    sanitize_and_process(user_input);
    
    return 0;
} 