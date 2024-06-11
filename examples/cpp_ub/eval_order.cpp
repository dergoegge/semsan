#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/shm.h>
#include <unistd.h>
#include <vector>

void fill_diff_value(uint8_t *value, uint8_t a, uint8_t b, uint8_t c) {
  value[0] = a;
  value[1] = b;
  value[2] = c;
}

static uint8_t *diff_value = nullptr;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  const char *shmid{std::getenv("SEMSAN_CHARACTERIZATION_SHMEM_ID")};
  assert(shmid);
  diff_value = (uint8_t *)shmat(std::stoi(shmid), nullptr, 0);
  assert(diff_value);
  std::memset(diff_value, 0, 32);
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *buffer,
                                      size_t buffer_len) {
  if (buffer_len > 0 && buffer[0] == 'a') {
    if (buffer_len > 1 && buffer[1] == 'b') {
      if (buffer_len > 2 && buffer[2] == 'c') {
        if (buffer_len > 3 && buffer[3] == 'd') {
          std::vector<uint8_t> values;
          for (int i = 4; i < buffer_len; ++i) {
            values.push_back(buffer[i]);
          }
          auto take_value = [&] {
            if (values.empty()) {
              return uint8_t{0};
            }

            auto value = values.back();
            values.pop_back();
            return value;
          };

          fill_diff_value(diff_value, take_value(), take_value(), take_value());
          return 1;
        }
      }
    }
  }

  return 0;
}
