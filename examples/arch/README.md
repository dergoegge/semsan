# Finding architecture specific differences

```
$ uname -a
Linux brink-arm-fuzz 6.1.0-13-arm64 #1 SMP Debian 6.1.55-1 (2023-09-29) aarch64 GNU/Linux
$ CROSS_CC=x86_64-linux-gnu-gcc make
$ ls
arch-host arch-qemu ...
$ mkdir /tmp/seeds /tmp/solutions && echo "AAA" > /tmp/seeds/A
$ # "cargo build --release --features qemu_x86_64" produces "target/release/semsan-x86_64"
$ # which emulates the second executor under x86_64 user-mode qemu
$ target/release/semsan-x86_64 examples/arch/arch-host examples/arch/arch-qemu fuzz \
  --seeds /tmp/seeds/ --solutions /tmp/solutions
...
[UserStats #0] run time: 0h-0m-5s, clients: 1, corpus: 29, objectives: 0, executions: 56384, exec/sec: 9.668k, combined-coverage: 9/65599 (0%), stability: 2/6 (33%)
[Testcase #0] run time: 0h-0m-5s, clients: 1, corpus: 30, objectives: 0, executions: 56386, exec/sec: 9.668k, combined-coverage: 9/65599 (0%), stability: 2/6 (33%)
[UserStats #0] run time: 0h-0m-5s, clients: 1, corpus: 30, objectives: 0, executions: 56386, exec/sec: 9.668k, combined-coverage: 9/65599 (0%), stability: 2/6 (33%)
[Testcase #0] run time: 0h-0m-5s, clients: 1, corpus: 31, objectives: 0, executions: 56388, exec/sec: 9.668k, combined-coverage: 9/65599 (0%), stability: 2/6 (33%)
[UserStats #0] run time: 0h-0m-5s, clients: 1, corpus: 31, objectives: 0, executions: 56388, exec/sec: 9.668k, combined-coverage: 9/65599 (0%), stability: 2/6 (33%)
[Testcase #0] run time: 0h-0m-5s, clients: 1, corpus: 32, objectives: 0, executions: 56390, exec/sec: 9.668k, combined-coverage: 9/65599 (0%), stability: 2/6 (33%)
== ERROR: Semantic Difference
primary  : [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
secondary: [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
...
```


