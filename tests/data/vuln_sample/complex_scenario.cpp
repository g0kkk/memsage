#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <pthread.h>
#include <iostream>

// Global shared variables for race conditions
int global_shared = 0;
int shared_counter = 0;
pthread_mutex_t shared_mutex = PTHREAD_MUTEX_INITIALIZER;

// Thread function with race condition
void* thread_function(void* arg) {
    int thread_id = *(int*)arg;
    
    for (int i = 0; i < 100; i++) {
        global_shared++;  // Race condition
        shared_counter++;  // Race condition
    }
    
    return NULL;
}

// Function with multiple vulnerabilities
void process_data(char* input, int size) {
    // Integer overflow potential
    size_t buffer_size = size * sizeof(char);  // Could overflow
    char* buffer = (char*)malloc(buffer_size);
    
    if (buffer) {
        strcpy(buffer, input);  // Buffer overflow potential
        
        // Use the buffer
        printf("Processed: %s\n", buffer);
        
        free(buffer);
        free(buffer);  // Double free
    }
}

// Function with taint propagation and memory issues
void vulnerable_processing(char* user_input, int user_size) {
    // Taint propagation
    char* temp_buffer = (char*)malloc(user_size);
    
    if (temp_buffer) {
        strcpy(temp_buffer, user_input);  // Taint propagation
        
        // Process with potential integer overflow
        size_t new_size = user_size * 2;  // Could overflow
        char* expanded_buffer = (char*)malloc(new_size);
        
        if (expanded_buffer) {
            strcpy(expanded_buffer, temp_buffer);
            free(expanded_buffer);
        }
        
        free(temp_buffer);
        free(temp_buffer);  // Double free
    }
}

// Function with mixed vulnerabilities
void mixed_vulnerabilities(char* input1, char* input2, int size1, int size2) {
    // Integer overflow in size calculation
    size_t total_size = size1 * size2;  // Could overflow
    
    // Allocate buffer
    char* buffer = (char*)malloc(total_size);
    
    if (buffer) {
        // Taint propagation
        strcpy(buffer, input1);
        strcat(buffer, input2);
        
        // Use buffer
        printf("Combined: %s\n", buffer);
        
        free(buffer);
        free(buffer);  // Double free
    }
}

// Safe function for comparison
void safe_processing(char* input, int size) {
    if (size <= 0 || size > 1000) {
        printf("Invalid size\n");
        return;
    }
    
    char* buffer = (char*)malloc(size);
    
    if (buffer) {
        strncpy(buffer, input, size - 1);
        buffer[size - 1] = '\0';
        
        printf("Safe: %s\n", buffer);
        free(buffer);
    }
}

int main() {
    char user_input[100];
    char second_input[100];
    int user_size1, user_size2;
    
    // Get tainted input
    printf("Enter first input: ");
    fgets(user_input, sizeof(user_input), stdin);  // Source
    
    printf("Enter second input: ");
    fgets(second_input, sizeof(second_input), stdin);  // Source
    
    printf("Enter first size: ");
    scanf("%d", &user_size1);  // Source
    
    printf("Enter second size: ");
    scanf("%d", &user_size2);  // Source
    
    // Test various vulnerability combinations
    process_data(user_input, user_size1);
    vulnerable_processing(user_input, user_size1);
    mixed_vulnerabilities(user_input, second_input, user_size1, user_size2);
    
    // Test safe processing for comparison
    safe_processing(user_input, user_size1);
    
    // Test multithreaded race conditions
    pthread_t thread1, thread2;
    int thread_ids[2] = {1, 2};
    
    pthread_create(&thread1, NULL, thread_function, &thread_ids[0]);
    pthread_create(&thread2, NULL, thread_function, &thread_ids[1]);
    
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);
    
    return 0;
} 