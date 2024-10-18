void a() {
    int foo = 1;
}

void b() {
    int foo = 2;
}

void c() {
    int foo = 3;
}

void d() {
    int foo = 4;
}

void e() {
    int foo = 5;
}

void f() {
    int foo = 6;
}

int main() {
    int count = 1;
    a();
    count = 2;
    b();
    count = 2;
    c();
    count = 4;
    d();
    count = 5;
    e();
    count = 6;
    f();
}