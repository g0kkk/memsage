#include <iostream>
#include <cstring>
#include <cstdio>

// VULNERABILITY: Buffer overflow in strcpy
void vulnerable_strcpy() {
    char buffer[10];
    char source[] = "This string is too long for the buffer";
    
    // VULNERABLE: No bounds checking
    strcpy(buffer, source);  // Buffer overflow!
    
    std::cout << "Buffer: " << buffer << std::endl;
}

// VULNERABILITY: Buffer overflow in sprintf
void vulnerable_sprintf() {
    char buffer[20];
    char user_input[] = "Very long user input that exceeds buffer size";
    
    // VULNERABLE: No format string validation
    sprintf(buffer, "Input: %s", user_input);  // Buffer overflow!
    
    printf("Buffer: %s\n", buffer);
}

// VULNERABILITY: Array bounds violation
void vulnerable_array_access() {
    int array[5] = {1, 2, 3, 4, 5};
    
    // VULNERABLE: Accessing beyond array bounds
    for (int i = 0; i < 10; i++) {
        std::cout << "array[" << i << "] = " << array[i] << std::endl;  // Out of bounds!
    }
}

// VULNERABILITY: Stack overflow
void recursive_function(int n) {
    char large_buffer[10000];  // Large stack allocation
    
    // VULNERABLE: Deep recursion without bounds
    if (n > 0) {
        recursive_function(n - 1);  // Stack overflow potential!
    }
}

// VULNERABILITY: Integer overflow
void vulnerable_integer_operations() {
    int a = 2147483647;  // MAX_INT
    int b = 1;
    
    // VULNERABLE: Integer overflow
    int result = a + b;  // Overflow!
    
    std::cout << "Result: " << result << std::endl;
}

int main() {
    std::cout << "Testing buffer overflow vulnerabilities..." << std::endl;
    
    vulnerable_strcpy();
    vulnerable_sprintf();
    vulnerable_array_access();
    vulnerable_integer_operations();
    
    // Uncomment to test stack overflow
    // recursive_function(1000);
    
    return 0;
} 