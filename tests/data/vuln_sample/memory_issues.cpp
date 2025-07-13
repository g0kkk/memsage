#include <cstdlib>
#include <cstdio>
#include <cstring>

// Double-free vulnerability
void double_free_vulnerability() {
    int* ptr = (int*)malloc(100);
    
    if (ptr) {
        *ptr = 42;
        free(ptr);   // First free
        free(ptr);   // Double free - should be detected
    }
}

// Use-after-free vulnerability
void use_after_free_vulnerability() {
    int* ptr = (int*)malloc(100);
    
    if (ptr) {
        *ptr = 42;
        free(ptr);   // Free the memory
        *ptr = 100;  // Use after free - should be detected
    }
}

// Memory leak vulnerability
void memory_leak_vulnerability() {
    int* ptr1 = (int*)malloc(100);
    int* ptr2 = (int*)malloc(200);
    
    if (ptr1) {
        free(ptr1);  // Only free ptr1, ptr2 is leaked
    }
    // ptr2 is never freed - memory leak
}

// Complex memory management issue
void complex_memory_issue() {
    int* ptr = (int*)malloc(100);
    
    if (ptr) {
        free(ptr);
        ptr = (int*)malloc(50);  // Reallocate
        free(ptr);
        free(ptr);  // Double free after reallocation
    }
}

int main() {
    double_free_vulnerability();
    use_after_free_vulnerability();
    memory_leak_vulnerability();
    complex_memory_issue();
    return 0;
} 