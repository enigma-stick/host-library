#include "../include/enigma.h"
#include <stdio.h>

#define KEY_ID 0x4B4D1006

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

  res = enigma_destroy_key(device, KEY_ID, &error);
  if (res != ENIGMA_OK) {
    printf("Could not destroy key (%02X) - %s\n", res, error.message);
    exit = 1;
    goto cleanup;
  }
  printf("Destroyed key\n");

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
