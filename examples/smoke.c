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

  uint8_t buffer[512];
  size_t pk_len = 0;
  res = enigma_export_public_key(device, 0x4B4D1001, buffer, sizeof(buffer),
                                 &pk_len, &error);
  if (res != ENIGMA_OK) {
    printf("Could not export public key (%02x) - %s\n", res, error.message);
    exit = 1;
    goto cleanup;
  }

  printf("Public Key Length: %lu\n", pk_len);
  for (size_t i = 0; i < pk_len; i++) {
    printf("%02X ", buffer[i]);
  }

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
