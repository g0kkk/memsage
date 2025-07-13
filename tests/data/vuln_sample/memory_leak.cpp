#include <iostream>
#include <cstdlib>
#include <memory>
#include <vector> // Added for raw_pointer_in_container

// VULNERABILITY: Memory leak with new/delete
void memory_leak_new_delete() {
    int* ptr = new int[100];
    
    // VULNERABLE: Memory allocated but never freed
    // delete[] ptr;  // Missing cleanup!
    
    std::cout << "Memory allocated but not freed" << std::endl;
}

// VULNERABILITY: Memory leak with malloc/free
void memory_leak_malloc_free() {
    char* buffer = (char*)malloc(1024);
    
    // VULNERABLE: Memory allocated but never freed
    // free(buffer);  // Missing cleanup!
    
    std::cout << "Buffer allocated but not freed" << std::endl;
}

// VULNERABILITY: Double free
void double_free_vulnerability() {
    int* ptr = new int(42);
    
    delete ptr;  // First free
    delete ptr;  // VULNERABLE: Double free!
    
    std::cout << "Double free vulnerability" << std::endl;
}

// VULNERABILITY: Use after free
void use_after_free() {
    int* ptr = new int(100);
    
    delete ptr;  // Free the memory
    
    // VULNERABLE: Using freed memory
    *ptr = 200;  // Use after free!
    
    std::cout << "Use after free vulnerability" << std::endl;
}

// VULNERABILITY: Memory leak in exception
void memory_leak_exception() {
    int* ptr = new int[1000];
    
    try {
        throw std::runtime_error("Exception occurred");
    } catch (const std::exception& e) {
        // VULNERABLE: Memory not freed in exception handler
        std::cout << "Exception: " << e.what() << std::endl;
        // delete[] ptr;  // Missing cleanup!
    }
}

// VULNERABILITY: Circular reference with shared_ptr
class CircularRef {
public:
    std::shared_ptr<CircularRef> other;
    
    CircularRef() {
        std::cout << "CircularRef created" << std::endl;
    }
    
    ~CircularRef() {
        std::cout << "CircularRef destroyed" << std::endl;
    }
};

void circular_reference_leak() {
    auto obj1 = std::make_shared<CircularRef>();
    auto obj2 = std::make_shared<CircularRef>();
    
    // VULNERABLE: Circular reference prevents cleanup
    obj1->other = obj2;
    obj2->other = obj1;
    
    std::cout << "Circular reference created" << std::endl;
}

// VULNERABILITY: Raw pointer in smart pointer container
void raw_pointer_in_container() {
    std::vector<int*> ptr_vector;
    
    for (int i = 0; i < 10; i++) {
        ptr_vector.push_back(new int(i));  // VULNERABLE: Raw pointers
    }
    
    // VULNERABLE: No cleanup of raw pointers
    // for (auto ptr : ptr_vector) {
    //     delete ptr;
    // }
    
    std::cout << "Raw pointers in container not cleaned up" << std::endl;
}

int main() {
    std::cout << "Testing memory leak vulnerabilities..." << std::endl;
    
    memory_leak_new_delete();
    memory_leak_malloc_free();
    double_free_vulnerability();
    use_after_free();
    memory_leak_exception();
    circular_reference_leak();
    raw_pointer_in_container();
    
    return 0;
} 