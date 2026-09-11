#include "../include/enigma.h"
#include <stdio.h>

int main(void) {

  enigma_device *device;
  enigma_error error = {0};

  enigma_result res = enigma_open(&device, &error);
  if (res != ENIGMA_OK) {
    printf("Could not open device (%02x) - %s\n", res, error.message);
    return 1;
  }

  enigma_status_info status = {0};
  res = enigma_status(device, &status, &error);
  if (res != ENIGMA_OK) {
    printf("Could not get device status (%02x) - %s\n", res, error.message);
    return 1;
  }

  printf("== Device status ==\n");
  printf("  Token: %u\n", status.token_state);
  printf("  Session: %u\n", status.session_state);

  res = enigma_close(device, &error);
  if (res != ENIGMA_OK) {
    printf("Could not close device (%02x) - %s\n", res, error.message);
    return 1;
  }

  return 0;
}
