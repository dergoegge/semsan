#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>
#include <unistd.h>

static uint8_t *diff_value = NULL;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  const char *shmid = getenv("SEMSAN_CHARACTERIZATION_SHMEM_ID");
  assert(shmid);
  diff_value = (uint8_t *)shmat(atoi(shmid), NULL, 0);
  assert(diff_value);
  memset(diff_value, 0, 32);
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > 0 && data[0] == 'y') {
    if (size > 1 && data[1] == 'e') {
      if (size > 2 && data[2] == 'e') {
        if (size > 4 && data[3] == 't') {
          // Signedness of "char" is undefined. Real life example:
          // https://github.com/ElementsProject/lightning/pull/7322.
          char value = (char)data[4];
          diff_value[0] = value >= 0 ? 1 : 2;
          return 0;
        }
      }
    }
  }
  return 0;
}

#ifdef QEMU
int main(int argc, char **argv) {
  LLVMFuzzerInitialize(&argc, &argv);
  uint8_t buf[1024 * 1024];
  LLVMFuzzerTestOneInput(buf, 1024 * 1024);
  return 0;
}
#endif
