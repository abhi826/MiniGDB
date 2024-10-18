#include <iostream>

void displayNumber(int num) {
    std::cout << "Number: " << num << std::endl;
}

int main() {
    // Loop that calls displayNumber function inside the loop
    for (int i = 1; i <= 5; ++i) {
        displayNumber(i);  // Call the function inside the for loop
    }

    return 0;
}
