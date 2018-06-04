/******************************************************************************
 *
 * Copyright 2018 Xaptum, Inc.
 * 
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 * 
 *        http://www.apache.org/licenses/LICENSE-2.0
 * 
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License
 *
 *****************************************************************************/

#include <tss2/tss2_tcti_device.h>
#include <tss2/tss2_tpm2_types.h>

#include "internal/tcti_common.h"
#include "internal/marshal.h"


#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#define DEFAULT_LOCALITY 3
#define SIMULATOR_SEND_COMMAND 8
#define SIMULATOR_SESSION_END 20
#define MAX_DEV_FILE_PATH_LENGTH 64
#define DEFAULT_DEV_FILE_PATH_LENGTH 9

static const char* DEFAULT_DEV_FILE_PATH = "/dev/tpm0";

enum _TCTI_DEVICE_STATE {
    _TCTI_DEVICE_STATE_READY,
    _TCTI_DEVICE_STATE_AWAITING_RESPONSE,
};

typedef struct {
    uint64_t magic;
    uint32_t version;
    TSS2_RC (*transmit)( TSS2_TCTI_CONTEXT *tctiContext, size_t size,
            uint8_t *command);
    TSS2_RC (*receive) (TSS2_TCTI_CONTEXT *tctiContext, size_t *size,
            uint8_t *response, int32_t timeout);
    TSS2_RC (*finalize) (TSS2_TCTI_CONTEXT *tctiContext);
    TSS2_RC (*cancel) (TSS2_TCTI_CONTEXT *tctiContext);
    TSS2_RC (*getPollHandles) (TSS2_TCTI_CONTEXT *tctiContext,
            TSS2_TCTI_POLL_HANDLE *handles, size_t *num_handles);
    TSS2_RC (*setLocality) (TSS2_TCTI_CONTEXT *tctiContext, uint8_t locality);

    char dev_file_path[MAX_DEV_FILE_PATH_LENGTH];
    FILE* file_ptr;
    enum _TCTI_DEVICE_STATE state;
} TSS2_TCTI_CONTEXT_OPAQUE_DEVICE;

#ifdef VERBOSE_LOGGING
#define TCTI_VERBOSE_LOGGING
#endif

static
TSS2_RC transmit_device(TSS2_TCTI_CONTEXT *tcti_context,
                        size_t size,
                        uint8_t *command);

static
TSS2_RC receive_device(TSS2_TCTI_CONTEXT *tcti_context,
                       size_t *size,
                       uint8_t *response,
                       int32_t timeout);

static
TSS2_RC finalize_device(TSS2_TCTI_CONTEXT *tcti_context);

static
TSS2_RC cancel_device(TSS2_TCTI_CONTEXT *tcti_context);

static
TSS2_RC
getPollHandles_device(TSS2_TCTI_CONTEXT *tcti_context,
                      TSS2_TCTI_POLL_HANDLE *handles,
                      size_t *num_handles);

static
TSS2_RC
setLocality_device(TSS2_TCTI_CONTEXT *tcti_context,
                   uint8_t locality);

static
TSS2_RC
send_all(FILE* file_ptr,
         uint8_t *in,
         size_t requested_length);

size_t
tss2_tcti_getsize_device()
{
    return sizeof(TSS2_TCTI_CONTEXT_OPAQUE_DEVICE);
}

TSS2_RC
tss2_tcti_init_device(const char *dev_file_path,
                      size_t dev_file_path_length,
                      TSS2_TCTI_CONTEXT *tcti_context)
{
    TSS2_TCTI_CONTEXT_OPAQUE_DEVICE *cast_context = (TSS2_TCTI_CONTEXT_OPAQUE_DEVICE*)tcti_context;

    assert(DEFAULT_DEV_FILE_PATH_LENGTH == strlen(DEFAULT_DEV_FILE_PATH));
    if (NULL == dev_file_path) {
        memcpy(cast_context->dev_file_path, DEFAULT_DEV_FILE_PATH, DEFAULT_DEV_FILE_PATH_LENGTH);
        cast_context->dev_file_path[DEFAULT_DEV_FILE_PATH_LENGTH] = 0;
    } else if (MAX_DEV_FILE_PATH_LENGTH < dev_file_path_length) {
        return TSS2_BASE_RC_INSUFFICIENT_BUFFER;
    } else {
        memcpy(cast_context->dev_file_path, dev_file_path, dev_file_path_length);
        cast_context->dev_file_path[dev_file_path_length] = 0;
    }

    cast_context->magic = TCTI_MAGIC;
    cast_context->version = TCTI_VERSION;
    cast_context->transmit = transmit_device;
    cast_context->receive = receive_device;
    cast_context->finalize = finalize_device;
    cast_context->cancel = cancel_device;
    cast_context->getPollHandles = getPollHandles_device;
    cast_context->setLocality = setLocality_device;

    cast_context->state = _TCTI_DEVICE_STATE_READY;
    cast_context->file_ptr = NULL;

    return TSS2_RC_SUCCESS;
}

TSS2_RC
getPollHandles_device(TSS2_TCTI_CONTEXT *tcti_context,
                      TSS2_TCTI_POLL_HANDLE *handles,
                      size_t *num_handles)
{
    (void)tcti_context;
    (void)handles;
    (void)num_handles;

    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC
setLocality_device(TSS2_TCTI_CONTEXT *tcti_context,
                   uint8_t locality)
{
    (void)tcti_context;
    (void)locality;

    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC transmit_device(TSS2_TCTI_CONTEXT *tcti_context,
                        size_t size,
                        uint8_t *command)
{
    TSS2_TCTI_CONTEXT_OPAQUE_DEVICE *cast_context = (TSS2_TCTI_CONTEXT_OPAQUE_DEVICE*)tcti_context;
    TSS2_RC send_ret = TSS2_RC_SUCCESS;

    if (_TCTI_DEVICE_STATE_READY != cast_context->state) {
#ifdef TCTI_VERBOSE_LOGGING
        fprintf(stderr, "tcti_device::transmit - transmit called while awaiting a response\n");
#endif
        return TSS2_BASE_RC_BAD_SEQUENCE;
    }

    // Open file
    cast_context->file_ptr = fopen(cast_context->dev_file_path, "r+");
    if (NULL == cast_context->file_ptr) {
#ifdef TCTI_VERBOSE_LOGGING
        fprintf(stderr, "tcti_device::transmit - Error with fopen: (%d) %s\n", errno, strerror(errno));
#endif
        return TSS2_TCTI_RC_IO_ERROR; 
    }

    // Send the command.
    send_ret = send_all(cast_context->file_ptr,
                        command,
                        size);
    if (send_ret != TSS2_RC_SUCCESS) {
        goto transmit_cleanup;
    }
#ifdef TCTI_VERBOSE_LOGGING
    printf("tcti_device::transmit - command={");
    for (size_t i=0; i < size; i++) {
        printf("%#X", command[i]);
        if (i != (size-1)) printf(", ");
    }
    printf("}\n");
#endif

transmit_cleanup:
    if (TSS2_RC_SUCCESS != send_ret && cast_context->file_ptr) {
        fclose(cast_context->file_ptr);
        cast_context->file_ptr = NULL;
    } else {
        cast_context->state = _TCTI_DEVICE_STATE_AWAITING_RESPONSE;
    }

    return send_ret;
}

TSS2_RC receive_device(TSS2_TCTI_CONTEXT *tcti_context,
                       size_t *size,
                       uint8_t *response,
                       int32_t timeout)
{
    TSS2_RC recv_ret = TSS2_RC_SUCCESS;

    TSS2_TCTI_CONTEXT_OPAQUE_DEVICE *cast_context = (TSS2_TCTI_CONTEXT_OPAQUE_DEVICE*)tcti_context;

    // Nb. We don't support timeouts
    if (TSS2_TCTI_TIMEOUT_BLOCK != timeout) {
        recv_ret = TSS2_TCTI_RC_NOT_IMPLEMENTED;
        goto receive_cleanup;
    }

    // Nb. We don't support reporting the size.
    //   A caller must give us enough buffer to read the entire response in one go.
    if (NULL == response || NULL == size) {
        recv_ret = TSS2_BASE_RC_BAD_REFERENCE;
        goto receive_cleanup;
    }

    if (_TCTI_DEVICE_STATE_AWAITING_RESPONSE != cast_context->state) {
#ifdef TCTI_VERBOSE_LOGGING
        fprintf(stderr, "tcti_device::receive - receive called without matching transmit\n");
#endif
        recv_ret = TSS2_BASE_RC_BAD_SEQUENCE;
        goto receive_cleanup;
    }

    size_t fread_ret = fread(response, 1, *size, cast_context->file_ptr);
    if (0 == fread_ret && ferror(cast_context->file_ptr)) {
#ifdef TCTI_VERBOSE_LOGGING
        fprintf(stderr, "tcti_device::receive - Error with fread: (%d) %s\n", errno, strerror(errno));
#endif
        recv_ret = TSS2_TCTI_RC_IO_ERROR; 
        goto receive_cleanup;
    }
    
    if (!feof(cast_context->file_ptr)) {
#ifdef TCTI_VERBOSE_LOGGING
        fprintf(stderr, "tcti_device::receive - Supplied buffer too small for response\n");
#endif
        recv_ret = TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
        goto receive_cleanup;
    }

receive_cleanup:
    if (TSS2_RC_SUCCESS == recv_ret) {
        *size = (size_t)fread_ret;
#ifdef TCTI_VERBOSE_LOGGING
        printf("response={");
        for (size_t i=0; i < *size; i++) {
            printf("%#X", response[i]);
            if (i != (*size-1)) printf(", ");
        }
        printf("}\n");
#endif
    } else {
        *size = 0;
    }

    if (cast_context->file_ptr) {
        fclose(cast_context->file_ptr);
        cast_context->file_ptr = NULL;
    }

    cast_context->state = _TCTI_DEVICE_STATE_READY;

    return recv_ret;
}

TSS2_RC finalize_device(TSS2_TCTI_CONTEXT *tcti_context)
{
    TSS2_TCTI_CONTEXT_OPAQUE_DEVICE *cast_context = (TSS2_TCTI_CONTEXT_OPAQUE_DEVICE*)tcti_context;

    if (NULL != cast_context->file_ptr) {
        fclose(cast_context->file_ptr);
    }

    return TSS2_RC_SUCCESS;
}

TSS2_RC cancel_device(TSS2_TCTI_CONTEXT *tcti_context)
{
    (void)tcti_context;
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC
send_all(FILE* file_ptr,
         uint8_t *in,
         size_t requested_length)
{
    size_t length_left = requested_length;
    size_t bytes_sent = 0;
    while (bytes_sent < requested_length) {
        size_t fwrite_ret = fwrite((char*)&(in[bytes_sent]), 1, length_left, file_ptr);
        if (0 == fwrite_ret) {
#ifdef TCTI_VERBOSE_LOGGING
            perror("tcti_device::send_all - ");
#endif
            return TSS2_TCTI_RC_IO_ERROR;
        }

        bytes_sent += (size_t)fwrite_ret;
        length_left -= (size_t)fwrite_ret;
    }

    fflush(file_ptr);

    return TSS2_RC_SUCCESS;
}
