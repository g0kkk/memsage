#include <cstdio>
#include <cstdlib>
#include <cstring>

// Integer overflow in size calculation
void vulnerable_size_calculation() {
    int user_count;
    int element_size;
    
    printf("Enter count: ");
    scanf("%d", &user_count);  // Tainted input
    
    printf("Enter element size: ");
    scanf("%d", &element_size);  // Tainted input
    
    // Potential integer overflow
    size_t total_size = user_count * element_size;  // Integer overflow here
    void* buffer = malloc(total_size);
    
    if (buffer) {
        memset(buffer, 0, total_size);
        free(buffer);
    }
}

// Integer overflow in array allocation
void vulnerable_array_allocation() {
    int count;
    int size;
    
    printf("Enter array count: ");
    fgets((char*)&count, sizeof(count), stdin);  // Tainted input
    
    printf("Enter element size: ");
    fgets((char*)&size, sizeof(size), stdin);    // Tainted input
    
    // Potential integer overflow
    int* array = (int*)malloc(count * size);  // Integer overflow here
    
    if (array) {
        free(array);
    }
}

int main() {
    vulnerable_size_calculation();
    vulnerable_array_allocation();
    return 0;
} 