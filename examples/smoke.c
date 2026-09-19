#include "../include/enigma.h"
#include <stdio.h>

int main(void) {

  int exit = 0;
  enigma_device *device;
  enigma_error error = {0};

  enigma_result res = enigma_open(&device, &error);
  if (res != ENIGMA_OK) {
    printf("Could not open device (%02x) - %s\n", res, error.message);
    return 1;
  }

  res = enigma_authenticate(device, "password", &error);
  if (res != ENIGMA_OK) {
    printf("Could not open device (%02x) - %s\n", res, error.message);
    exit = 1;
    goto cleanup;
  }

  uint32_t generated_key_id = 0;
  res =
      enigma_generate_key(device, enigma_key_type_aes, enigma_key_usage_encrypt,
                          256, "host-lib-test", &generated_key_id, &error);
  if (res != ENIGMA_OK) {
    printf("Could not generate key (%02x) - %s\n", res, error.message);
    exit = 1;
    goto cleanup;
  }
  printf("Generated key %08X\n", generated_key_id);

cleanup:
  res = enigma_lock(device, &error);
  if (res != ENIGMA_OK) {
    printf("Could not lock device (%02x) - %s\n", res, error.message);
    enigma_close(device, &error);
    return 1;
  }

  res = enigma_close(device, &error);
  if (res != ENIGMA_OK) {
    printf("Could not close device (%02x) - %s\n", res, error.message);
    return 1;
  }

  return exit;
}
