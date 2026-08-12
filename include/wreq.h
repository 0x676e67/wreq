#ifndef WREQ_H
#define WREQ_H

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    char *ProxyUrl;
    char *Url;
    char *Method;
    char *Body;
    int Timeout;
    int IdleTimeout;
    char *Headers;
    char *HeaderOrder;
    char *TlsProfile;
    char *Id;
    char *Cookies;
    bool CloseIdleConnections;
} Request;

typedef struct {
    char *Location;
    char *Protocol;
    uint8_t *Body;
    int BodyLength;
    char *ContentType;
    int Status;
    char *Headers;
    char *RequestUrl;
} Response;

int wreq_execute(const Request *request, Response **response, char **error);
void wreq_response_free(Response *response);
void wreq_error_free(char *error);

#endif
