
int sum(int* arr, int num) {
    int i;
    int s = 0;
    for (i=0; i<num; i++) {
        s += arr[i];
    }
    return s;
}

int fib(n) {
    if (n < 2) return n;
    return fib(n-1)+fib(n-2);
}

int main() {
    int arr[10] = {1,2,3,4,5,6,7,8,9,10};
    fib(5);
    return sum(arr, 10);
}
