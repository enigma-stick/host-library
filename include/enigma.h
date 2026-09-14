#ifndef LIB_ENIGMA_H
#define LIB_ENIGMA_H

#include <stddef.h>
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
#define ENIGMA_MALFORMED_OUTPUT 0x09
#define ENIGMA_BUFFER_TOO_SMALL 0x0A

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

typedef uint32_t enigma_key_type;
#define enigma_key_type_aes 0x01
#define enigma_key_type_rsa 0x02
#define enigma_key_type_ec 0x03
#define enigma_key_type_hmac 0x04

typedef uint32_t enigma_key_usage;
#define enigma_key_usage_encrypt 0x01
#define enigma_key_usage_sign 0x02
#define enigma_key_usage_derive 0x03

typedef struct {
  uint32_t id;
  enigma_key_type type;
  enigma_key_usage usage;
  uint16_t size;
  const char *label;
  uint32_t created_at;
} enigma_key_meta;

typedef struct {
  uint32_t count;
  const enigma_key_meta *keys;
} enigma_key_list;

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
 *  require the token to be authenticated. Authentication only works if the
 *  token is already locked.
 *
 *  @paran[in] device Device handle
 *  @param[in] pin Device authentication PIN
 *  @param[out] error NULL or error if status could not be retrieved
 *  @retval code Error code
 */
enigma_result enigma_authenticate(enigma_device *device, const char *pin,
                                  enigma_error *error);

/**
 *  @brief Lock the device token
 *
 *  Locking the token prevents cryptographic operations from taking place
 *  on the secure element and closes the open session on the ESP. Locking
 *  only works if the token is already authenticated.
 *
 *  @param[in] device Device handle
 *  @param[out] error NULL or error
 *  @retval code Error code
 */
enigma_result enigma_lock(enigma_device *device, enigma_error *error);

/**
 *  @brief Sign a message
 *
 *  Sign an arbitrary message with a SIGNING key. The firmware will reject
 *  a key that does not have appropriate key usage. The `signature` buffer
 *  is caller provided and must have enough capacity for the resulting
 *  signature, or the function will fail.
 *
 *  @param[in] device Device handle
 *  @param[in] key_id Signing key ID
 *  @param[in] message Message to be signed
 *  @param[in] message_len Message buffer capacity
 *  @param[out] signature Resulting signature buffer (caller provided)
 *  @param[out] signature_len Signature buffer length
 *  @param[out] error NULL or error
 *  @retval code Error code
 */
enigma_result enigma_sign(enigma_device *device, uint32_t key_id,
                          const uint8_t *message, size_t message_len,
                          uint8_t *signature, size_t *signature_len,
                          enigma_error *error);

/**
 *  @brief Get public key material
 *
 *  Keypairs are generated on the secure element but do not return the public
 *  key as part of that operation. The returned `public_key` is formatted to
 *  be SubjectPublicKeyInfo DER bytes.
 *
 *  Public key memory must be allocated by the caller, and the buffer size
 *  passed in via `capacity`. If not enough memory was allocated, the error
 *  code is ENIGMA_BUFFER_TOO_SMALL. When public_key = NULL and capacity = 0,
 *  the library will return the necessary bytes to allocate in `public_key_len`.
 *
 *  @param[in] device Device handle
 *  @param[in] key_id Target key ID
 *  @param[out] public_key Public key SPKI DER bytes
 *  @param[in] capacity Public key buffer size
 *  @param[out] public_key_len Public key byte count
 *  @param[out] error NULL or error
 *  @retval code Error code
 */
enigma_result enigma_export_public_key(enigma_device *device, uint32_t key_id,
                                       uint8_t *public_key, size_t capacity,
                                       size_t *public_key_len,
                                       enigma_error *error);

/**
 *  @brief List available crypto keys on the device
 *
 *  Get a list of key metadata structures that represent available crypto keys
 *  on the secure element. The `key_list` output is owned by the library and
 *  may be freed via `enigma_key_list_free`.
 *
 *  The device will filter on key type, usage, label, and ID. If the ID is
 *  provided, all other filters will be ignored, and the lookup will occur
 *  by ID only. This fact is enforced on the device firmware itself. Other
 *  filters are combined with AND logic. For example, providing type = EC and
 *  usage = SIGN will only give back keys that are both EC keys and have signing
 *  usage.
 *
 *  @param[in] device Device handle
 *  @param[in] filter_type Key type filter
 *  @param[in] filter_usage Key usage filter
 *  @param[in] filter_label Key label filter
 *  @param[in] filter_key_id Key ID filter
 *  @param[out] key_list List of key metadatas
 *  @param[out] error NULL or error
 *  @retval code Error code
 *  @see enigma_key_list_free()
 */
enigma_result enigma_list_keys(enigma_device *device,
                               const enigma_key_type *filter_type,
                               const enigma_key_usage *filter_usage,
                               const char *filter_label,
                               const uint32_t *filter_key_id,
                               enigma_key_list **key_list, enigma_error *error);

/**
 *  @brief Free library allocated key list
 *
 *  A key list returned by `enigma_list_keys` is owned by the library and must
 *  be free'd with this function.
 *
 *  @param[in] list Key list
 *  @see enigma_list_keys()
 */
void enigma_key_list_free(const enigma_key_list *list);

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
