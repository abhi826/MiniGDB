#include <iostream>

void a() {
    int foo = 1;
    std::cout<<"In a"<<std::endl;
}

void b() {
    int foo = 2;
    std::cout<<"In b"<<std::endl;
    a();
}

void c() {
    int foo = 3;
    std::cout<<"In c"<<std::endl;
    b();
}

void d() {
    int foo = 4;
    std::cout<<"In d"<<std::endl;
    c();
}

void e() {
    int foo = 5;
    std::cout<<"In e"<<std::endl;
    d();
}

void f() {
    int foo = 6;
    std::cout<<"In f"<<std::endl;
    e();
}

int main() {
    f();
}
