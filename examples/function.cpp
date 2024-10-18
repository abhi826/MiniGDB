//#include <iostream>

void foo() {
    int a = 2;
    //std::cout << "Function foo is called." << std::endl;
}

void bar() {
    int c = 3;
    //std::cout << "Function bar is called." << std::endl;
}

int main() {
    int n = 5;  // Line A

    if(n == 5)  // Line B
    {
        foo();  // Line C
    }
    else
    {
        bar();  // Line D
        --n;
    }

    return 0;
}
