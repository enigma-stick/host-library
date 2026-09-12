#ifndef LIB_ENIGMA_H
#define LIB_ENIGMA_H

#include <stdint.h>

/**
 * @brief Device handle
 */
typedef struct enigma_device enigma_device;

/**
 *  @brief Enigma error codes
 *
 *  Successful enigma API operations return ENIGMA_OK (=0). Otherwise, a stable
 *  error code will be returned.
 */
typedef int32_t enigma_result;
#define ENIGMA_OK 0x00
#define ENIGMA_INVALID_ARG 0x01
#define ENIGMA_DEVICE_NOT_FOUND 0x02
#define ENIGMA_MULTIPLE_DEVICES 0x03
#define ENIGMA_INCOMPATIBLE_DEVICE 0x04
#define ENIGMA_USB_ERROR 0x05
#define ENIGMA_PROTOCOL_ERROR 0x06
#define ENIGMA_DEVICE_ERROR 0x07
#define ENIGMA_INTERNAL_ERROR 0x08

/**
 *  @brief Rich library error information
 */
typedef struct {
  int32_t code;         /**< Library error category */
  uint32_t device_code; /**< Firmare error code */
  char message[256];    /**< NUL-terminated, possibly truncated error message */
} enigma_error;

/**
 *  @brief Enigma device status
 */
typedef struct {
  uint32_t token_state;   /**< Secure token state */
  uint32_t session_state; /**< Secure session state */
} enigma_status_info;

/**
 *  @brief Open a connection to the Enigma device
 *
 *  Secure a USB handle to the Enigma device to be able to read and write
 *  data frames over the wire. `out_device` is set to NULL before attempting
 *  to open the device.
 *
 *  @param[out] device Device handle
 *  @param[out] error NULL or error if device could not be opened
 *  @retval code Error code
 */
enigma_result enigma_open(enigma_device **device, enigma_error *error);

/**
 *  @brief Retrieve device status
 *
 *  Enigma status contains the glboal state of the token and session. The token
 *  status displays the initialization state of the crypto token. The session
 *  status is for whether or not the token has an open authenticated session.
 *
 *  @param[in] device Device handle
 *  @param[out] status Resulting status
 *  @param[out] error NULL or error if status could not be retrieved
 *  @retval code Error code
 */
enigma_result enigma_status(enigma_device *device, enigma_status_info *status,
                            enigma_error *error);

/**
 *  @brief Authenticate the device token
 *
 *  Authenticating the token unlocks it globally. Cryptographic operations
 *  require the token to be authenticated
 *
 *  @paran[in] device Device handle
 *  @param[in] pin Device authentication PIN
 *  @param[out] error NULL or error if status could not be retrieved
 *  @retval code Error code
 */
enigma_result enigma_authenticate(enigma_device *device, const char *pin,
                                  enigma_error *error);

/**
 *  @brief Close device
 *
 *  Close the USB connection and release the handle back to the kernel.
 *  The device handle may be null in this case, where nothing will actually
 *  happen, but no errors will result.
 *
 *  @param[in] device Device handle
 *  @param[out] error NULL or error if device could not be cleanly closed
 *  @retval code Error code
 *  @see enigma_open()
 */
enigma_result enigma_close(enigma_device *device, enigma_error *error);

#endif // LIB_ENIGMA_H
