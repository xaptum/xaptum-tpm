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

#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>

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
    int file_fd;
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
send_all(int file_fd,
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

    cast_context->file_fd = -1;

    // Open file
    cast_context->file_fd = open(cast_context->dev_file_path, O_RDWR);
    if (-1 == cast_context->file_fd) {
#ifdef TCTI_VERBOSE_LOGGING
        fprintf(stderr, "tcti_device::init - Error with open: (%d) %s\n", errno, strerror(errno));
#endif
        return TSS2_TCTI_RC_IO_ERROR;
    }


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

    // Send the command.
    send_ret = send_all(cast_context->file_fd,
                        command,
                        size);
    if (send_ret != TSS2_RC_SUCCESS) {
        return send_ret;
    }
#ifdef TCTI_VERBOSE_LOGGING
    printf("tcti_device::transmit - command={");
    for (size_t i=0; i < size; i++) {
        printf("%#X", command[i]);
        if (i != (size-1)) printf(", ");
    }
    printf("}\n");
#endif

    return send_ret;
}

TSS2_RC receive_device(TSS2_TCTI_CONTEXT *tcti_context,
                       size_t *size,
                       uint8_t *response,
                       int32_t timeout)
{
    TSS2_TCTI_CONTEXT_OPAQUE_DEVICE *cast_context = (TSS2_TCTI_CONTEXT_OPAQUE_DEVICE*)tcti_context;

    // Nb. We don't support timeouts
    if (TSS2_TCTI_TIMEOUT_BLOCK != timeout) {
        return TSS2_TCTI_RC_NOT_IMPLEMENTED;
    }

    // Nb. We don't support reporting the size.
    //   A caller must give us enough buffer to read the entire response in one go.
    if (NULL == response || NULL == size) {
        return TSS2_BASE_RC_BAD_REFERENCE;
    }

    ssize_t read_ret = read(cast_context->file_fd, response, *size);
    if (-1 == read_ret) {
#ifdef TCTI_VERBOSE_LOGGING
        fprintf(stderr, "tcti_device::receive - Error with read: (%d) %s\n", errno, strerror(errno));
#endif
        return TSS2_TCTI_RC_IO_ERROR;
    }

    // 0 indicates EOF, so if we don't get EOF our buffer was too small to read everything.
    uint8_t eof_buf[1];
    ssize_t eof_read_ret = read(cast_context->file_fd, eof_buf, sizeof(eof_buf));
    if (0 != eof_read_ret) {
#ifdef TCTI_VERBOSE_LOGGING
        fprintf(stderr, "tcti_device::receive - Supplied buffer too small for response\n");
#endif
        // Clear out remaining response.
        unsigned char trash[64];
        ssize_t trash_ret = 1;
        while (trash_ret != 0 && trash_ret != -1) {
            trash_ret = read(cast_context->file_fd, trash, sizeof(trash));
        }

        *size = 0;

        return TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
    }

    *size = (size_t)read_ret;

#ifdef TCTI_VERBOSE_LOGGING
    printf("response={");
    for (size_t i=0; i < *size; i++) {
        printf("%#X", response[i]);
        if (i != (*size-1)) printf(", ");
    }
    printf("}\n");
#endif

    return TSS2_RC_SUCCESS;

}

TSS2_RC finalize_device(TSS2_TCTI_CONTEXT *tcti_context)
{
    TSS2_TCTI_CONTEXT_OPAQUE_DEVICE *cast_context = (TSS2_TCTI_CONTEXT_OPAQUE_DEVICE*)tcti_context;

    if (-1 != cast_context->file_fd) {
        close(cast_context->file_fd);
        cast_context->file_fd = -1;
    }

    return TSS2_RC_SUCCESS;
}

TSS2_RC cancel_device(TSS2_TCTI_CONTEXT *tcti_context)
{
    (void)tcti_context;
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC
send_all(int file_fd,
         uint8_t *in,
         size_t requested_length)
{
    size_t length_left = requested_length;
    size_t bytes_sent = 0;
    while (bytes_sent < requested_length) {
        ssize_t write_ret = write(file_fd, (char*)&(in[bytes_sent]), length_left);
        if (-1 == write_ret) {
#ifdef TCTI_VERBOSE_LOGGING
            perror("tcti_device::send_all - ");
#endif
            return TSS2_TCTI_RC_IO_ERROR;
        }

        bytes_sent += (size_t)write_ret;
        length_left -= (size_t)write_ret;
    }

    return TSS2_RC_SUCCESS;
}
