*Note: This is still a work in progress.*

# Semantics Sanitizer

Many software projects have to ensure that the behaviour of some of their
components does not change when the software is modified. For example, the
behaviour for implementations of cryptographic primitives should **always**
remain the same, regardless of which version of the software is being used.

Simply not modifying software once it has reached maturity seems like a simple
solution to this problem. However, all software needs a bare minimum amount of
maintenance to ensure it can continue to run on old and new systems. In
pratice, most software regularly receives invasive changes, such as
refactoring, performance improvements and new features.

The problem is often exasturbated by the fact that modifying software is not
the only avenue for behavioural differences. The CPU architecture used to
execute the software on or the compiler used to create the binaries can also
affect program behaviour.

Semantics Sanitizer's primary goal is to ease continuous differential fuzzing
of the same piece of software across different revisions, architectures and
compilers.

## Design

SemSan is a coverage-guided fuzzer based on
[LibAFL](https://github.com/AFLplusplus/LibAFL) and consists of two executors,
one for each harness being differentially fuzzed (primary, secondary). Each
executor has an observer attached to it that collects an output value (which
charaterizes the semantics of the program under test) for each fuzz iteration.
For each input, the executors are run in sequence and the collected output
values are compared. Should the output values not match then a semantic
difference has been found.

Output values are collected through a shared memory region. Harnesses can
attach and write to the shared memory through the shared memory ID set by
SemSan on the `SEMSAN_CHARACTERIZATION_SHMEM_ID` environment variable. Note
that the shared memory is only 32 bytes in size and harnesses should only write
a hash (or otherwise short summary) to it.

SemSan loads the initial seeds from disk into memory and evolves the corpus in
memory, it is not persisted to disk. Inputs that trigger semantic differences
are written to disk.

At the moment, SemSan supports afl style fork server executors (for targets
compiled with `afl-clang-{fast,lto,fast++,lto++}` or `afl-{gcc,g++}-fast`) and
`libafl_qemu` executors (for emulating targets on different architectures). In
the future, the aim is to also support snapshot based executors (e.g.
full-system `libafl_qemu` or `nyx`).

## Usage

```
Usage: semsan [OPTIONS] <PRIMARY> <SECONDARY> <COMMAND>

Commands:
  fuzz      Differentially fuzz the primary and secondary harness
  minimize  Minimize a solution
  help      Print this message or the help of the given subcommand(s)

Arguments:
  <PRIMARY>    Path to the binary of the primary harness to fuzz
  <SECONDARY>  Path to the binary of the secondary harness to fuzz

Options:
      --debug-children
          Redirect the executors' std{out,err} to SemSan's std{out,err}. Useful for debugging solutions and harnesses.
      --timeout <TIMEOUT>
          Maximum amount of time a single input is allowed to run (in milliseconds per executor). [default: 1000]
      --comparator <COMPARATOR>
          Choose differential value comparator function [default: equal] [possible values: not-equal, equal, less-than, less-than-or-equal, greater-than, greater-than-or-equal]
      --solution-exit-code <SOLUTION_EXIT_CODE>
          Exit code for solutions [default: 71]
      --qemu-entry <QEMU_ENTRY>
          Symbol for the qemu entry breakpoint [default: LLVMFuzzerTestOneInput]
  -h, --help
          Print help
```

The `--qemu-entry` option is only available if SemSan was compiled for
emulation (e.g. `--features qemu_x86_64`).

### Fuzzing

```
Differentially fuzz the primary and secondary harness

Usage: semsan <PRIMARY> <SECONDARY> fuzz [OPTIONS] --seeds <SEEDS> --solutions <SOLUTIONS>

Options:
      --ignore-solutions
          Keep fuzzing even if a solution has already been found
      --foreign-corpus <FOREIGN_CORPUS>
          Foreign fuzzer corpus to pull in inputs from
      --foreign-sync-interval <FOREIGN_SYNC_INTERVAL>
          Interval for syncing the foreign fuzzer corpus (in seconds) [default: 10]
      --no-secondary-coverage
          Don't collect coverage feedback for the secondary executor
      --seeds <SEEDS>
          Seed corpus directory
      --solutions <SOLUTIONS>
          Directory in which solutions (differential finds) will be stored
  -h, --help
          Print help
```

### Minimizing Solutions

```
Minimize a solution

Usage: semsan <PRIMARY> <SECONDARY> minimize [OPTIONS] <SOLUTION> <SOLUTIONS>

Arguments:
  <SOLUTION>   Path to the solution to minimize
  <SOLUTIONS>  Directory storing minimized solutions

Options:
      --iterations <ITERATIONS>  Number of iterations to attempt minimization for [default: 128]
  -h, --help                     Print help
```

### Comparators

By default SemSan will check for equality when comparing the observed output
values but that is configurable with the `--comparator` option. Currently, the
only supported comparators are `not-equal`, `equal`, `less-than`,
`less-than-or-equal`, `greater-than` and `greater-than-or-equal`.

Using comparators other than `equal` can be useful when the harnesses under
test are allowed to behave differently to some extend.

### Ensembling with other engines

SemSan is not meant to be used in isolation as it is quite a primitive fuzzer
on its own (e.g. no input-to-state, no corpus persistence). It is highly
recommended to ensemble SemSan with state of the art coverage-guided fuzzers
such as [afl++](https://github.com/AFLplusplus/AFLplusplus),
[honggfuzz](https://github.com/google/honggfuzz) or
[libFuzzer](https://www.llvm.org/docs/LibFuzzer.html).

The `--foreign-corpus` option can be used for this purpose. It prompts SemSan
to regularly load new inputs from the passed directory into it's in memory
corpus. The frequency of syncing with the foreign corpus can be adjusted with
the `--foreign-sync-interval` option.

### Examples

See the [`examples/`](examples/) directory.

## Related Work

* [Finding Unstable Code via Compiler-Driven Differential
  Testing](https://shao-hua-li.github.io/assets/pdf/2023_asplos_compdiff.pdf)
* [LibAFL based fuzzer for differential fuzzing across
  architectures](https://github.com/dergoegge/libdimpl)
