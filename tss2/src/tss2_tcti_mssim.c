/******************************************************************************
 *
 * Copyright 2017 Xaptum, Inc.
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

#include <tss2/tss2_tcti_mssim.h>
#include <tss2/tss2_tpm2_types.h>

#include "internal/tcti_common.h"
#include "internal/marshal.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef NDEBUG
#include <stdio.h>
#endif
#include <string.h>
#include <assert.h>

#define BAD_SOCKET -1
#define DEFAULT_LOCALITY 3
#define SIMULATOR_SEND_COMMAND 8
#define SIMULATOR_SESSION_END 20

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

    int sock;
} TSS2_TCTI_CONTEXT_OPAQUE_SOCKET;

#ifdef VERBOSE_LOGGING
#define TCTI_VERBOSE_LOGGING
#endif

static
TSS2_RC transmit_socket(TSS2_TCTI_CONTEXT *tcti_context,
                        size_t size,
                        uint8_t *command);

static
TSS2_RC receive_socket(TSS2_TCTI_CONTEXT *tcti_context,
                       size_t *size,
                       uint8_t *response,
                       int32_t timeout);

static
TSS2_RC finalize_socket(TSS2_TCTI_CONTEXT *tcti_context);

static
TSS2_RC cancel_socket(TSS2_TCTI_CONTEXT *tcti_context);

static
TSS2_RC
getPollHandles_socket(TSS2_TCTI_CONTEXT *tcti_context,
                      TSS2_TCTI_POLL_HANDLE *handles,
                      size_t *num_handles);

static
TSS2_RC
setLocality_socket(TSS2_TCTI_CONTEXT *tcti_context,
                   uint8_t locality);

static
int
open_socket(const char* hostname,
            const char* port);

static
TSS2_RC
recv_all(int sock,
         uint8_t *out,
         size_t requested_length);

static
TSS2_RC
send_all(int sock,
         uint8_t *in,
         size_t requested_length);

TSS2_RC
Tss2_Tcti_Mssim_Init(TSS2_TCTI_CONTEXT *tcti_context,
                     size_t *size,
                     const char *conf)
{
    if (NULL == size || NULL == conf)
        return TSS2_BASE_RC_BAD_REFERENCE;

    if (tcti_context == NULL) {
        *size = sizeof(TSS2_TCTI_CONTEXT_OPAQUE_SOCKET);
        return TSS2_RC_SUCCESS;
    }

    TSS2_TCTI_CONTEXT_OPAQUE_SOCKET *cast_context = (TSS2_TCTI_CONTEXT_OPAQUE_SOCKET*)tcti_context;

    cast_context->magic = TCTI_MAGIC;
    cast_context->version = TCTI_VERSION;
    cast_context->transmit = transmit_socket;
    cast_context->receive = receive_socket;
    cast_context->finalize = finalize_socket;
    cast_context->cancel = cancel_socket;
    cast_context->getPollHandles = getPollHandles_socket;
    cast_context->setLocality = setLocality_socket;

    char *hostname = NULL;
    char *port = NULL;
    char conf_buf[256] = {};
    strncpy(conf_buf, conf, sizeof(conf_buf));
    if (0 != conf_buf[sizeof(conf_buf) - 1])
        return TSS2_BASE_RC_BAD_VALUE;

    for (char *key = strtok(conf_buf, ","); key; key = strtok(NULL, ",")) {
        char *equals = strchr(key, '=');
        if (NULL == equals)
            return TSS2_BASE_RC_BAD_VALUE;
        *equals = 0;
        if (0 == strncmp(key, "host", 4)) {
            hostname = equals + 1;
        } else if (0 == strncmp(key, "port", 4)) {
            port = equals + 1;
        } else {
            return TSS2_BASE_RC_BAD_VALUE;
        }
    }

    if (NULL == hostname || NULL == port)
        return TSS2_BASE_RC_BAD_VALUE;

    cast_context->sock = open_socket(hostname, port);
    if (BAD_SOCKET != cast_context->sock) {
        return TSS2_RC_SUCCESS;
    } else {
        close(cast_context->sock);
        return TSS2_TCTI_RC_IO_ERROR;
    }
}

TSS2_RC
getPollHandles_socket(TSS2_TCTI_CONTEXT *tcti_context,
                      TSS2_TCTI_POLL_HANDLE *handles,
                      size_t *num_handles)
{
    (void)tcti_context;
    (void)handles;
    (void)num_handles;

    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC
setLocality_socket(TSS2_TCTI_CONTEXT *tcti_context,
                   uint8_t locality)
{
    (void)tcti_context;
    (void)locality;

    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC transmit_socket(TSS2_TCTI_CONTEXT *tcti_context,
                        size_t size,
                        uint8_t *command)
{
    TSS2_TCTI_CONTEXT_OPAQUE_SOCKET *cast_context = (TSS2_TCTI_CONTEXT_OPAQUE_SOCKET*)tcti_context;
    TSS2_RC send_ret;

    // Send SIMULATOR_SEND_COMMAND.
    // We're assuming we're talking to the Microsoft simulator.
    // A proxy that is passing these commands to a real TPM can just ignore this
    uint8_t send_command[sizeof(uint32_t)];
    uint8_t *send_ptr = send_command;
    marshal_uint32(SIMULATOR_SEND_COMMAND, &send_ptr);
    send_ret = send_all(cast_context->sock, send_command, sizeof(send_command));
    if (send_ret != TSS2_RC_SUCCESS) {
        return send_ret;
    }
#ifdef TCTI_VERBOSE_LOGGING
    printf("tcti: transmit_socket: [simulator_send_command={ ");
    for (size_t i=0; i < sizeof(send_command); i++) {
        printf("%#X", send_command[i]);
        if (i != (sizeof(send_command)-1)) printf(", ");
    }
    printf("}, ");
#endif

    // Send locality.
    // Again, this is for the Micrsoft simulator.
    uint8_t locality = DEFAULT_LOCALITY;
    send_ret = send_all(cast_context->sock, &locality, 1);    // no need for endian-switching, just a byte
    if (send_ret != TSS2_RC_SUCCESS) {
        return send_ret;
    }
#ifdef TCTI_VERBOSE_LOGGING
    printf("locality=%u, ", locality);
#endif

    // Send total command size
    uint8_t *size_buffer = command + sizeof(TPM2_ST);    // skip the ST_SESSIONS code
    send_ret = send_all(cast_context->sock,
                        size_buffer,
                        sizeof(uint32_t));
    if (send_ret != TSS2_RC_SUCCESS) {
        return send_ret;
    }
#ifdef TCTI_VERBOSE_LOGGING
    printf("size={");
    for (size_t i=0; i < sizeof(uint32_t); i++) {
        printf("%#X", size_buffer[i]);
        if (i != (sizeof(uint32_t)-1)) printf(", ");
    }
    printf("}, ");
#endif

    // Send the command.
    send_ret = send_all(cast_context->sock,
                        command,
                        size);
    if (send_ret != TSS2_RC_SUCCESS) {
        return send_ret;
    }
#ifdef TCTI_VERBOSE_LOGGING
    printf("command={");
    for (size_t i=0; i < size; i++) {
        printf("%#X", command[i]);
        if (i != (size-1)) printf(", ");
    }
    printf("}]\n");
#endif

    return TSS2_RC_SUCCESS;
}

TSS2_RC receive_socket(TSS2_TCTI_CONTEXT *tcti_context,
                       size_t *size,
                       uint8_t *response,
                       int32_t timeout)
{
    // Nb. We don't support timeouts
    if (TSS2_TCTI_TIMEOUT_BLOCK != timeout)
        return TSS2_TCTI_RC_NOT_IMPLEMENTED;

    TSS2_TCTI_CONTEXT_OPAQUE_SOCKET *cast_context = (TSS2_TCTI_CONTEXT_OPAQUE_SOCKET*)tcti_context;
    TSS2_RC recv_ret;

    // Get the response size
    // (assumed put into the stream by the Microsoft simulator, or whatever proxy is acting as TCP server).
    recv_ret = recv_all(cast_context->sock,
                        response,
                        sizeof(uint32_t));
    if (recv_ret != TSS2_RC_SUCCESS) {
        return recv_ret;
    }
    uint32_t size_from_response;
    uint8_t *size_ptr = response;
    uint32_t trash = sizeof(uint32_t);
    unmarshal_uint32(&size_ptr, &trash, &size_from_response);

    // If the provided buffer is too small,
    // return the error and clear the TCP stream.
    if (*size < size_from_response) {
        uint8_t trash[64];
        ssize_t ret = 0;
        size_t bytes_read = 0;
        while (ret != -1 && bytes_read < size_from_response) {
            ret = recv_all(cast_context->sock, trash, sizeof(trash));
            bytes_read += (size_t)ret;
        }

        *size = 0;  // We have to drop this message, so no use returning its size.

        return TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
    }

    *size = (size_t)size_from_response;

#ifdef TCTI_VERBOSE_LOGGING
    printf("tcti: receive_socket: [size=%zu, ", *size);
#endif

    // Read the rest of the response
    recv_ret = recv_all(cast_context->sock, response, *size);
    if (recv_ret != TSS2_RC_SUCCESS) {
        return recv_ret;
    }
#ifdef TCTI_VERBOSE_LOGGING
    printf("response={");
    for (size_t i=0; i < *size; i++) {
        printf("%#X", response[i]);
        if (i != (*size-1)) printf(", ");
    }
    printf("}]\n");
#endif

    // Read 4 bytes of zeroes (and just ignore them).
    // The Microsoft simulator appends these, so we assume them.
    uint8_t zeroes[4];
    recv_ret = recv_all(cast_context->sock, zeroes, sizeof(zeroes));
    if (recv_ret != TSS2_RC_SUCCESS) {
        return recv_ret;
    }

    return TSS2_RC_SUCCESS;
}

TSS2_RC finalize_socket(TSS2_TCTI_CONTEXT *tcti_context)
{
    TSS2_TCTI_CONTEXT_OPAQUE_SOCKET *cast_context = (TSS2_TCTI_CONTEXT_OPAQUE_SOCKET*)tcti_context;
    
    TSS2_RC ret = TSS2_RC_SUCCESS;

    // Send SIMULATOR_SESSION_END.
    // We're assuming we're talking to the Microsoft simulator.
    // A proxy that is passing these commands to a real TPM can just ignore this
    uint8_t session_end[sizeof(uint32_t)];
    uint8_t *session_ptr = session_end;
    marshal_uint32(SIMULATOR_SESSION_END, &session_ptr);
    ret = send_all(cast_context->sock, session_end, sizeof(session_end));

    close(cast_context->sock);

    return ret;
}

TSS2_RC cancel_socket(TSS2_TCTI_CONTEXT *tcti_context)
{
    (void)tcti_context;
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

int
open_socket(const char* hostname,
            const char* port)
{
    int sock = BAD_SOCKET;

    // Lookup hostname
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    struct addrinfo *servinfo;
    int info_ret = getaddrinfo(hostname, port, &hints, &servinfo);
    if (0 != info_ret) {
#ifndef NDEBUG
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(info_ret));
#endif
        return BAD_SOCKET;
    }

    // Connect to first valid result.
    struct addrinfo *p = servinfo;
    for (; p != NULL; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (-1 == sock) {
            continue;
        }

        int conn_ret = connect(sock, p->ai_addr, p->ai_addrlen);
        if (-1 == conn_ret) {
            close(sock);
            continue;
        }

        break;
    }

    if (NULL == p) {
#ifndef NDEBUG
        fprintf(stderr, "failed to connect to TPM server\n");
#endif
        return BAD_SOCKET;
    }

#ifdef TCTI_VERBOSE_LOGGING
    struct sockaddr *sa = (struct sockaddr*)p->ai_addr;
    void *src;
    if (sa->sa_family == AF_INET) {
        src = &(((struct sockaddr_in*)sa)->sin_addr);
    } else {
        src = &(((struct sockaddr_in6*)sa)->sin6_addr);
    }
    char addrstr[INET6_ADDRSTRLEN];
    inet_ntop(p->ai_family, src, addrstr, sizeof(addrstr));
    printf("connecting to %s\n", addrstr);
#endif

    freeaddrinfo(servinfo);

    return sock;
}

TSS2_RC
recv_all(int sock,
         uint8_t *out,
         size_t out_length)
{
    size_t length_left = out_length;
    size_t bytes_read = 0;
    while (bytes_read < out_length) {
        ssize_t recv_ret = recv(sock, (char*)&(out[bytes_read]), length_left, 0);
        if (-1 == recv_ret) {
#ifndef NDEBUG
            perror("recv_all");
#endif
            return TSS2_TCTI_RC_IO_ERROR;
        }

        bytes_read += (size_t)recv_ret;
        length_left -= (size_t)recv_ret;
    }

    return TSS2_RC_SUCCESS;
}

TSS2_RC
send_all(int sock,
         uint8_t *in,
         size_t requested_length)
{
    size_t length_left = requested_length;
    size_t bytes_sent = 0;
    while (bytes_sent < requested_length) {
        ssize_t send_ret = send(sock, (char*)&(in[bytes_sent]), length_left, 0);
        if (-1 == send_ret) {
            return TSS2_TCTI_RC_IO_ERROR;
#ifndef NDEBUG
            perror("send_all");
#endif
        }

        bytes_sent += (size_t)send_ret;
        length_left -= (size_t)send_ret;
    }

    return TSS2_RC_SUCCESS;
}
