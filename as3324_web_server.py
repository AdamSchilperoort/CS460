#!/usr/bin/env python3

import argparse

import sys
import itertools
import socket
from socket import socket as Socket

# A simple web server


def main():

    # Command line arguments. Use a port > 1024 by default so that we can run
    # without sudo, for use as a real server you need to use port 80.
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', '-p', default=2080, type=int,
                        help='Port to use')
    args = parser.parse_args()

    # Create the server socket (to handle tcp requests using ipv4), make sure
    # it is always closed by using with statement.
    with Socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:

        # The socket stays connected even after this script ends. So in order
        # to allow the immediate reuse of the socket (so that we can kill and
        # re-run the server while debugging) we set the following option. This
        # is potentially dangerous in real code: in rare cases you may get junk
        # data arriving at the socket.
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        server_socket.bind(('', args.port))
        server_socket.listen(1)

        print("server ready")

        while True:

            with server_socket.accept()[0] as connection_socket:
                # This is a hackish way to make sure that we can receive and process multi
                # line requests.
                request=""
                received="received"
                while len(received)>2:
                        received=connection_socket.recv(1024).decode('ascii')
                        request+=received
                reply = http_handle(request)
                connection_socket.send(reply.encode('ascii'))


            print("\n\nReceived request")
            print("======================")
            print(request.rstrip())
            print("======================")


            print("\n\nReplied with")
            print("======================")
            print(reply.rstrip())
            print("======================")


    return 0


def http_handle(request_string):
    """Given a http requst return a response

    Both request and response are unicode strings with platform standard
    line endings.
    """
    assert not isinstance(request_string, bytes)

    # Prototypes for error messages for RFC 2616
    cont = "HTTP/1.1 100 Continue\n"
    switchProtocol = "HTTP/1.1 101 Switching Protocols\n"
    ok = "HTTP/1.1 200 OK\n"
    created = "HTTP/1.1 201 Created\n"
    accepted = "HTTP/1.1 202 Acceptetd\n"
    nonAuthoritative = "HTTP/1.1 203 Non-Authoritative Information\n"
    noContent = "HTTP/1.1 204 No Content\n"
    resetContent = "HTTP/1.1 205 Reset Content\n"
    partialContent = "HTTP/1.1 206 Partial Content\n"
    multipleChoices = "HTTP/1.1 300 Multiple Choices\n"
    movedPermanently = "HTTP/1.1 301 Moved Permanently\n"
    found = "HTTP/1.1 302 Found\n"
    seeOther = "HTTP/1.1 303 See Other\n"
    notModified = "HTTP/1.1 304 Not Modified\n"
    useProxy = "HTTP/1.1 305 Use Proxy\n"
    tempRedirect = "HTTP/1.1 307 Temporary Redirect\n"
    badRequest = "HTTP/1.1 400 Bad Request\n"
    unauthorized = "HTTP/1.1 401 Unauthorized\n"
    paymentRequired = "HTTP/1.1 402 Payment Required\n"
    forbidden = "HTTP/1.1 403 Forbidden\n"
    fileNotFound = "HTTP/1.1 404 Not Found\n"
    methodNotAllowed = "HTTP/1.1 405 Method Not Allowed\n"
    notAcceptable = "HTTP/1.1 406 Not Acceptable\n"
    proxyAuthentReq = "HTTP/1.1 407 Proxy Authentication Required\n"
    requestTimeout = "HTTP/1.1 408 Request Time-out\n"
    conflict = "HTTP/1.1 409 Conflict\n"
    gone = "HTTP/1.1 410 Gone\n"
    lengthRequired = "HTTP/1.1 411 Length Required\n"
    preconditionFailed = "HTTP/1.1 412 Precondition Failed\n"
    reqEntTooLarge = "HTTP/1.1 413 Request Entity Too Large\n"
    reqURITooLarge = "HTTP/1.1 414 Request-URI Too Large\n"
    unsupportedMediaType = "HTTP/1.1 415 Unsupported Media Type\n"
    requestRangeNotSatisf = "HTTP/1.1 416 Requested range not satisfiable\n"
    expectationFailed = "HTTP/1.1 417 Expectation Failed\n"
    internalServerError = "HTTP/1.1 500 Internal Server Error\n"
    notImplemented = "HTTP/1.1 501 Not Implemented\n"
    badGateway = "HTTP/1.1 502 Bad Gateway\n"
    serviceUnavailable = "HTTP/1.1 503 Service Unavailable\n"
    gatewayTimeOut = "HTTP/1.1 504 Gateway Time-out"
    versionNotSupported = "HTTP/1.1 505 HTTP Version Not Supported\n"

    # Premade response for /index.html
    indexResponse = "\n<!DOCTYPE html>\n<html>\n<head>\n\n<title>Adam Schilperoort</title>\n\n</head>\n\n<body>\n\n\tThis is awesome!\n\n</body>\n"

    # Strip and split request string
    requestString = request_string.rstrip().split('\r\n')[0].split()

    requestLength = len(requestString)

    # If request doesn't meet proper length, return bad Request
    if (requestLength < 3):
        return badRequest

    Method = requestString[0]
    Path = requestString[1]
    Version = requestString[2]

    # check for unsupported version
    if (Version != "HTTP/1.1"):
        return versionNotSupported

    # check if method is invalid syntax for RFC2616
    if(Method != "OPTIONS"
        and Method != "HEAD"
        and Method != "POST"
        and Method != "PUT"
        and Method != "DELETE"
        and Method != "TRACE"
        and Method != "CONNECT"
        and Method != "GET"):
            return badRequest

    # check if method is unsupported
    if(Method == "OPTIONS"
        or Method == "HEAD"
        or Method == "PUT"
        or Method == "DELETE"
        or Method == "TRACE"
        or Method == "CONNECT"):
            return notImplemented

    # implementation of GET
    elif(Method == "GET"):
        # check if file has valid syntax
        if (Path[0] != "/"):
            return badRequest
        if (Path == "/index.html" or Path == "/" ):
            return ok + indexResponse
        else:
            return fileNotFound

    elif(Method == "POST"):
        # check if file has valid syntax
        if (Path == "/index.html" or Path == "/" ):
            return ok
        else:
            return noContent


    return notImplemented

    pass


if __name__ == "__main__":
    sys.exit(main())
