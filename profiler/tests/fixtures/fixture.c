/* Rebuild with: clang -target x86_64-linux-gnu -O0 -c fixture.c -o fixture.o */
int helper_one(int x) { return x + 1; }
int helper_two(int x) { return x * 2; }
int main_entry(int x) { return helper_one(x) + helper_two(x); }
