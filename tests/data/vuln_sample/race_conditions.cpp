#include <pthread.h>
#include <iostream>
#include <cstdio>

// Global shared variables
int global_counter = 0;
int shared_flag = 0;
int shared_data[100];

// Race condition on shared variable
void* race_condition_thread(void* arg) {
    int thread_id = *(int*)arg;
    
    for (int i = 0; i < 1000; i++) {
        global_counter++;  // Race condition - should be detected
        shared_flag = thread_id;  // Race condition - should be detected
        shared_data[i % 100] = thread_id;  // Race condition - should be detected
    }
    
    return NULL;
}

// Properly protected shared variable access
pthread_mutex_t counter_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t flag_mutex = PTHREAD_MUTEX_INITIALIZER;

void* safe_thread(void* arg) {
    int thread_id = *(int*)arg;
    
    for (int i = 0; i < 1000; i++) {
        pthread_mutex_lock(&counter_mutex);
        global_counter++;  // Protected access
        pthread_mutex_unlock(&counter_mutex);
        
        pthread_mutex_lock(&flag_mutex);
        shared_flag = thread_id;  // Protected access
        pthread_mutex_unlock(&flag_mutex);
    }
    
    return NULL;
}

// Mixed protected and unprotected access
void* mixed_thread(void* arg) {
    int thread_id = *(int*)arg;
    
    for (int i = 0; i < 100; i++) {
        pthread_mutex_lock(&counter_mutex);
        global_counter++;  // Protected
        pthread_mutex_unlock(&counter_mutex);
        
        shared_data[i] = thread_id;  // Unprotected - race condition
    }
    
    return NULL;
}

int main() {
    pthread_t threads[4];
    int thread_ids[4] = {1, 2, 3, 4};
    
    // Test race conditions
    printf("Testing race conditions...\n");
    for (int i = 0; i < 4; i++) {
        pthread_create(&threads[i], NULL, race_condition_thread, &thread_ids[i]);
    }
    
    for (int i = 0; i < 4; i++) {
        pthread_join(threads[i], NULL);
    }
    
    // Test safe multithreading
    printf("Testing safe multithreading...\n");
    for (int i = 0; i < 4; i++) {
        pthread_create(&threads[i], NULL, safe_thread, &thread_ids[i]);
    }
    
    for (int i = 0; i < 4; i++) {
        pthread_join(threads[i], NULL);
    }
    
    // Test mixed scenario
    printf("Testing mixed scenario...\n");
    for (int i = 0; i < 4; i++) {
        pthread_create(&threads[i], NULL, mixed_thread, &thread_ids[i]);
    }
    
    for (int i = 0; i < 4; i++) {
        pthread_join(threads[i], NULL);
    }
    
    return 0;
} 