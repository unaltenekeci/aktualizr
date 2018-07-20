#include "libuptiny/targets.h"

#include <iostream>

int main(int argc, char** argv) {
  (void) argc;
  (void) argv;

  uptane_parse_targets_init();

  char in_buf[16];
  uptane_targets_t targets;
  uint16_t feed_result;

  std::string buffer;
  std::string shadow_buffer;

  uint16_t libuptiny_result = 0;
  while(cin) {
    cin.read(in_buf, 16); // Always read fixed amount of bytes for reproducibility, randomized breakings deserve a separate test

    size_t len;
    if (cin) {
      len = 16;
    } else {
      len = cin.gcount();
    }

    buffer += std::string(in_buf, len);
    shadow_buffer += std::string(in_buf, len);

    if (buffer.length() >= 2048) {
      return 0; // we're not interested in input buffer overflows
    }

    if (shadow_buffer.length() >= 1024*1024) {
      return 0; // we're not interested in input buffer overflows
    }

    uptane_parse_targets_feed(buffer.c_str(), buffer.length(), &targets, &feed_result);

    if (feed_result == RESULT_ERROR || feed_result == RESULT_WRONG_HW_ID || feed_result == RESULT_VERSION_FAULED) {
      libuptiny_result = RESULT_ERROR; // exact failure cause is not that important
      break;
    }

    if (feed_result == RESULT_END_FOUND || feed_result == RESULT_END_NOT_FOUND || feed_result == RESULT_SIGNATURES_FAILED) {
      libuptiny_result == feed_result;
    }
  }

  if(libuptiny_result == 0) {
    libuptiny_result == RESULT_ERROR;
  }

  uint16_t test_result = test_parse_targets(shadow_buffer);

  if (libuptiny_result != test_result) {
    cerr << "libuptiny result " << libuptiny_result << " doesn't match test parser result " << test_result;
    abort();
  }
}
