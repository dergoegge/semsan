all:
	afl-g++-fast -fsanitize=fuzzer -O0 -o eval_order_gcc-O0 eval_order.cpp
	afl-clang-fast++ -fsanitize=fuzzer -O0 -o eval_order_clang-O0 eval_order.cpp
