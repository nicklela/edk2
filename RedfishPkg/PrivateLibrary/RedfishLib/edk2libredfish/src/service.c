/** @file
  This file is cloned from DMTF libredfish library tag v1.0.0 and maintained
  by EDKII.

//----------------------------------------------------------------------------
// Copyright Notice:
// Copyright 2017 Distributed Management Task Force, Inc. All rights reserved.
// License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libredfish/LICENSE.md
//----------------------------------------------------------------------------

  Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
  (C) Copyright 2021 Hewlett Packard Enterprise Development LP<BR>
  Copyright (c) 2023-2024, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <redfishService.h>
#include <redfishPayload.h>
#include <redpath.h>

static int
initRest (
  redfishService  *service,
  void            *restProtocol
  );

static redfishService *
createServiceEnumeratorNoAuth (
  const char    *host,
  const char    *rootUri,
  bool          enumerate,
  unsigned int  flags,
  void          *restProtocol
  );

static redfishService *
createServiceEnumeratorBasicAuth (
  const char    *host,
  const char    *rootUri,
  const char    *username,
  const char    *password,
  unsigned int  flags,
  void          *restProtocol
  );

static redfishService *
createServiceEnumeratorSessionAuth (
  const char    *host,
  const char    *rootUri,
  const char    *username,
  const char    *password,
  unsigned int  flags,
  void          *restProtocol
  );

static char *
makeUrlForService (
  redfishService  *service,
  const char      *uri
  );

static json_t *
getVersions (
  redfishService  *service,
  const char      *rootUri
  );

static void
addStringToJsonObject (
  json_t      *object,
  const char  *key,
  const char  *value
  );

CHAR16 *
C8ToC16 (
  CHAR8  *AsciiStr
  )
{
  CHAR16  *Str;
  UINTN   BufLen;

  BufLen = (AsciiStrLen (AsciiStr) + 1) * 2;
  Str    = AllocatePool (BufLen);
  ASSERT (Str != NULL);

  AsciiStrToUnicodeStrS (AsciiStr, Str, AsciiStrLen (AsciiStr) + 1);

  return Str;
}

VOID
RestConfigFreeHttpRequestData (
  IN EFI_HTTP_REQUEST_DATA  *RequestData
  )
{
  if (RequestData == NULL) {
    return;
  }

  if (RequestData->Url != NULL) {
    FreePool (RequestData->Url);
  }

  FreePool (RequestData);
}

VOID
RestConfigFreeHttpMessage (
  IN EFI_HTTP_MESSAGE  *Message,
  IN BOOLEAN           IsRequest
  )
{
  if (Message == NULL) {
    return;
  }

  if (IsRequest) {
    RestConfigFreeHttpRequestData (Message->Data.Request);
    Message->Data.Request = NULL;
  } else {
    if (Message->Data.Response != NULL) {
      FreePool (Message->Data.Response);
      Message->Data.Response = NULL;
    }
  }

  if (Message->Headers != NULL) {
    FreePool (Message->Headers);
    Message->Headers = NULL;
  }

  if (Message->Body != NULL) {
    FreePool (Message->Body);
    Message->Body = NULL;
  }
}

/**
  Converts the Unicode string to ASCII string to a new allocated buffer.

  @param[in]       String       Unicode string to be converted.

  @return     Buffer points to ASCII string, or NULL if error happens.

**/
CHAR8 *
UnicodeStrDupToAsciiStr (
  CONST CHAR16  *String
  )
{
  CHAR8       *AsciiStr;
  UINTN       BufLen;
  EFI_STATUS  Status;

  BufLen   = StrLen (String) + 1;
  AsciiStr = AllocatePool (BufLen);
  if (AsciiStr == NULL) {
    return NULL;
  }

  Status = UnicodeStrToAsciiStrS (String, AsciiStr, BufLen);
  if (EFI_ERROR (Status)) {
    return NULL;
  }

  return AsciiStr;
}

/**
  This function encodes the content.

  @param[in]   ContentEncodedValue   HTTP conent encoded value.
  @param[in]   OriginalContent       Original content.
  @param[out]  EncodedContent        Pointer to receive encoded content.
  @param[out]  EncodedContentLength  Length of encoded content.

  @retval EFI_SUCCESS              Content encoded successfully.
  @retval EFI_UNSUPPORTED          No source encoding funciton,
  @retval EFI_INVALID_PARAMETER    One of the given parameter is invalid.

**/
EFI_STATUS
EncodeRequestContent (
  IN CHAR8   *ContentEncodedValue,
  IN CHAR8   *OriginalContent,
  OUT VOID   **EncodedContent,
  OUT UINTN  *EncodedContentLength
  )
{
  EFI_STATUS  Status;
  VOID        *EncodedPointer;
  UINTN       EncodedLength;

  if ((OriginalContent == NULL) || (EncodedContent == NULL) || (EncodedContentLength == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  Status = RedfishContentEncode (
             ContentEncodedValue,
             OriginalContent,
             AsciiStrLen (OriginalContent),
             &EncodedPointer,
             &EncodedLength
             );
  if (Status == EFI_SUCCESS) {
    *EncodedContent       = EncodedPointer;
    *EncodedContentLength = EncodedLength;
    return EFI_SUCCESS;
  }

  return Status;
}

/**
  This function decodes the content. The Memory block pointed by
  ContentPointer would be freed and replaced with the cooked Redfish
  payload.

  @param[in]        ContentEncodedValue HTTP conent encoded value.
  @param[in, out]   ContentPointer      Pointer to encoded content.
                                        Pointer of decoded content when out.
  @param[in, out]   ContentLength       Pointer to the length of encoded content.
                                        Length of decoded content when out.

  @retval EFI_SUCCESS              Functinos found.
  @retval EFI_UNSUPPORTED          No functions found.
  @retval EFI_INVALID_PARAMETER    One of the given parameter is invalid.

**/
EFI_STATUS
DecodeResponseContent (
  IN CHAR8      *ContentEncodedValue,
  IN OUT VOID   **ContentPointer,
  IN OUT UINTN  *ContentLength
  )
{
  EFI_STATUS  Status;
  VOID        *DecodedPointer;
  UINTN       DecodedLength;

  if (ContentEncodedValue == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Status = RedfishContentDecode (
             ContentEncodedValue,
             *ContentPointer,
             *ContentLength,
             &DecodedPointer,
             &DecodedLength
             );
  if (Status == EFI_SUCCESS) {
    FreePool (*ContentPointer);
    *ContentPointer = DecodedPointer;
    *ContentLength  = DecodedLength;
  }

  return Status;
}

/**
  Create a HTTP URL string for specific Redfish resource.

  This function build a URL string from the Redfish Host interface record and caller specified
  relative path of the resource.

  Callers are responsible for freeing the returned string storage pointed by HttpUrl.

  @param[in]   RedfishData         Redfish network host interface record.
  @param[in]   RelativePath        Relative path of a resource.
  @param[out]  HttpUrl             The pointer to store the returned URL string.

  @retval EFI_SUCCESS              Build the URL string successfully.
  @retval EFI_INVALID_PARAMETER    RedfishData or HttpUrl is NULL.
  @retval EFI_OUT_OF_RESOURCES     There are not enough memory resources.

**/
EFI_STATUS
RedfishBuildUrl (
  IN  REDFISH_CONFIG_SERVICE_INFORMATION  *RedfishConfigServiceInfo,
  IN  CHAR16                              *RelativePath    OPTIONAL,
  OUT CHAR16                              **HttpUrl
  )
{
  CHAR16  *Url;
  CHAR16  *UrlHead;
  UINTN   UrlLength;
  UINTN   PathLen;

  if ((RedfishConfigServiceInfo == NULL) || (HttpUrl == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // RFC2616: http_URL = "http(s):" "//" host [ ":" port ] [ abs_path [ "?" query ]]
  //
  if (RelativePath == NULL) {
    PathLen = 0;
  } else {
    PathLen = StrLen (RelativePath);
  }

  UrlLength = StrLen (HTTPS_FLAG) + StrLen (REDFISH_FIRST_URL) + 1 + StrLen (RedfishConfigServiceInfo->RedfishServiceLocation) + PathLen;
  Url       = AllocateZeroPool (UrlLength * sizeof (CHAR16));
  if (Url == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  UrlHead = Url;
  //
  // Copy "http://" or "https://" according RedfishServiceIpPort.
  //
  if (!RedfishConfigServiceInfo->RedfishServiceUseHttps) {
    StrCpyS (Url, StrLen (HTTPS_FLAG) + 1, HTTP_FLAG);
    Url = Url + StrLen (HTTP_FLAG);
  } else {
    StrCpyS (Url, StrLen (HTTPS_FLAG) + 1, HTTPS_FLAG);
    Url = Url + StrLen (HTTPS_FLAG);
  }

  StrCpyS (Url, StrLen (RedfishConfigServiceInfo->RedfishServiceLocation) + 1, RedfishConfigServiceInfo->RedfishServiceLocation);
  Url = Url + StrLen (RedfishConfigServiceInfo->RedfishServiceLocation);

  //
  // Copy abs_path
  //
  if ((RelativePath != NULL) && (PathLen != 0)) {
    StrnCpyS (Url, UrlLength, RelativePath, PathLen);
  }

  *HttpUrl = UrlHead;
  return EFI_SUCCESS;
}

redfishService *
createServiceEnumerator (
  REDFISH_CONFIG_SERVICE_INFORMATION  *RedfishConfigServiceInfo,
  const char                          *rootUri,
  enumeratorAuthentication            *auth,
  unsigned int                        flags
  )
{
  EFI_STATUS            Status;
  CHAR16                *HttpUrl;
  CHAR8                 *AsciiHost;
  EFI_REST_EX_PROTOCOL  *RestEx;
  redfishService        *ret;

  HttpUrl   = NULL;
  AsciiHost = NULL;
  RestEx    = NULL;
  ret       = NULL;

  if (RedfishConfigServiceInfo->RedfishServiceRestExHandle == NULL) {
    goto ON_EXIT;
  }

  Status = RedfishBuildUrl (RedfishConfigServiceInfo, NULL, &HttpUrl);
  if (EFI_ERROR (Status)) {
    goto ON_EXIT;
  }

  ASSERT (HttpUrl != NULL);

  AsciiHost = UnicodeStrDupToAsciiStr (HttpUrl);
  if (AsciiHost == NULL) {
    goto ON_EXIT;
  }

  Status = gBS->HandleProtocol (
                  RedfishConfigServiceInfo->RedfishServiceRestExHandle,
                  &gEfiRestExProtocolGuid,
                  (VOID **)&RestEx
                  );
  if (EFI_ERROR (Status)) {
    goto ON_EXIT;
  }

  if (auth == NULL) {
    ret = createServiceEnumeratorNoAuth (AsciiHost, rootUri, true, flags, RestEx);
  } else if (auth->authType == REDFISH_AUTH_BASIC) {
    ret = createServiceEnumeratorBasicAuth (AsciiHost, rootUri, auth->authCodes.userPass.username, auth->authCodes.userPass.password, flags, RestEx);
  } else if (auth->authType == REDFISH_AUTH_SESSION) {
    ret = createServiceEnumeratorSessionAuth (AsciiHost, rootUri, auth->authCodes.userPass.username, auth->authCodes.userPass.password, flags, RestEx);
  } else {
    goto ON_EXIT;
  }

  ret->RestEx = RestEx;
ON_EXIT:
  if (HttpUrl != NULL) {
    FreePool (HttpUrl);
  }

  if (AsciiHost != NULL) {
    FreePool (AsciiHost);
  }

  return ret;
}

EFI_HTTP_HEADER *
cloneHttpHeaders (
  EFI_HTTP_MESSAGE  *message,
  UINTN             *HeaderCount
  )
{
  EFI_HTTP_HEADER  *Buffer;
  UINTN            Index;

  if ((message == NULL) || (HeaderCount == NULL)) {
    return NULL;
  }

  *HeaderCount = message->HeaderCount;
  Buffer       = AllocatePool (sizeof (EFI_HTTP_HEADER) *  message->HeaderCount);
  if (Buffer == NULL) {
    return NULL;
  }

  for (Index = 0; Index < message->HeaderCount; Index++) {
    Buffer[Index].FieldName = AllocateCopyPool (AsciiStrSize (message->Headers[Index].FieldName), message->Headers[Index].FieldName);
    ASSERT (Buffer[Index].FieldName != NULL);
    Buffer[Index].FieldValue = AllocateCopyPool (AsciiStrSize (message->Headers[Index].FieldValue), message->Headers[Index].FieldValue);
    ASSERT (Buffer[Index].FieldValue != NULL);
  }

  return Buffer;
}

EFI_HTTP_MESSAGE *
BuildRequestMsg (
  redfishService       *Service,
  const char           *Uri,
  EFI_HTTP_METHOD      Method,
  REDFISH_HTTP_HEADER  *RequestHeader OPTIONAL,
  size_t               ContentLength OPTIONAL,
  const char           *ContentType OPTIONAL,
  const char           *Content OPTIONAL,
  BOOLEAN              DoContentEncoding
  )
{
  EFI_STATUS             Status;
  char                   *Url;
  UINTN                  Index;
  EFI_HTTP_MESSAGE       *RequestMsg;
  EFI_HTTP_REQUEST_DATA  *RequestData;
  UINTN                  HeaderCount;
  HTTP_IO_HEADER         *HttpIoHeader;
  CHAR8                  ContentLengthStr[80];
  CHAR8                  *EncodedContent;
  UINTN                  EncodedContentLen;
  BOOLEAN                HasContent;

  RequestMsg        = NULL;
  RequestData       = NULL;
  Url               = NULL;
  HttpIoHeader      = NULL;
  EncodedContent    = NULL;
  EncodedContentLen = 0;
  HeaderCount       = 5;
  HasContent        = FALSE;

  if ((Service == NULL) || (Uri == NULL) || (Uri[0] == '\0')) {
    return NULL;
  }

  if (Method >= HttpMethodMax) {
    return NULL;
  }

  Url = makeUrlForService (Service, Uri);
  if (Url == NULL) {
    return NULL;
  }

  DEBUG ((DEBUG_MANAGEABILITY, "%a: %a\n", __func__, Url));

  //
  // Step 1: build the HTTP headers.
  //
  if (Service->sessionToken || Service->basicAuthStr) {
    HeaderCount++;
  }

  if ((RequestHeader != NULL) && (RequestHeader->HeaderCount > 0)) {
    HeaderCount += RequestHeader->HeaderCount;
  }

  if ((Content != NULL) && (Content[0] != '\0')) {
    HeaderCount += 2;
    HasContent   = TRUE;
    if (DoContentEncoding) {
      HeaderCount += 2;
    }
  }

  HttpIoHeader = HttpIoCreateHeader (HeaderCount);
  if (HttpIoHeader == NULL) {
    goto ON_ERROR;
  }

  if (Service->sessionToken) {
    Status = HttpIoSetHeader (HttpIoHeader, HTTP_HEADER_X_AUTH_TOKEN, Service->sessionToken);
    if (EFI_ERROR (Status)) {
      goto ON_ERROR;
    }
  } else if (Service->basicAuthStr) {
    Status = HttpIoSetHeader (HttpIoHeader, HTTP_HEADER_AUTHORIZATION, Service->basicAuthStr);
    if (EFI_ERROR (Status)) {
      goto ON_ERROR;
    }
  }

  for (Index = 0; Index < RequestHeader->HeaderCount; Index++) {
    Status = HttpIoSetHeader (HttpIoHeader, RequestHeader->Headers[Index].FieldName, RequestHeader->Headers[Index].FieldValue);
    if (EFI_ERROR (Status)) {
      goto ON_ERROR;
    }
  }

  Status = HttpIoSetHeader (HttpIoHeader, HTTP_HEADER_HOST, Service->HostHeaderValue);
  if (EFI_ERROR (Status)) {
    goto ON_ERROR;
  }

  Status = HttpIoSetHeader (HttpIoHeader, "OData-Version", "4.0");
  if (EFI_ERROR (Status)) {
    goto ON_ERROR;
  }

  Status = HttpIoSetHeader (HttpIoHeader, HTTP_HEADER_ACCEPT, HTTP_CONTENT_TYPE_APP_JSON);
  if (EFI_ERROR (Status)) {
    goto ON_ERROR;
  }

  Status = HttpIoSetHeader (HttpIoHeader, HTTP_HEADER_USER_AGENT, "libredfish");
  if (EFI_ERROR (Status)) {
    goto ON_ERROR;
  }

  Status = HttpIoSetHeader (HttpIoHeader, "Connection", "Keep-Alive");
  if (EFI_ERROR (Status)) {
    goto ON_ERROR;
  }

  //
  // Handle content header
  //
  if (HasContent) {
    if (ContentType == NULL) {
      Status = HttpIoSetHeader (HttpIoHeader, HTTP_HEADER_CONTENT_TYPE, HTTP_CONTENT_TYPE_APP_JSON);
      if (EFI_ERROR (Status)) {
        goto ON_ERROR;
      }
    } else {
      Status = HttpIoSetHeader (HttpIoHeader, HTTP_HEADER_CONTENT_TYPE, (CHAR8 *)ContentType);
      if (EFI_ERROR (Status)) {
        goto ON_ERROR;
      }
    }

    if (ContentLength == 0) {
      ContentLength =  strlen (Content);
    }

    AsciiSPrint (
      ContentLengthStr,
      sizeof (ContentLengthStr),
      "%lu",
      (UINT64)ContentLength
      );
    Status = HttpIoSetHeader (HttpIoHeader, HTTP_HEADER_CONTENT_LENGTH, ContentLengthStr);
    if (EFI_ERROR (Status)) {
      goto ON_ERROR;
    }

    //
    // Encoding
    //
    if (DoContentEncoding) {
      EncodedContent    = (CHAR8 *)Content;
      EncodedContentLen = ContentLength;
      //
      // We currently only support gzip Content-Encoding.
      //
      Status = EncodeRequestContent ((CHAR8 *)HTTP_CONTENT_ENCODING_GZIP, (CHAR8 *)Content, (VOID **)&EncodedContent, &EncodedContentLen);
      if (Status == EFI_INVALID_PARAMETER) {
        DEBUG ((DEBUG_ERROR, "%a: Error to encode content.\n", __func__));
        goto ON_ERROR;
      } else if (Status == EFI_UNSUPPORTED) {
        DEBUG ((DEBUG_MANAGEABILITY, "No content coding for %a! Use raw data instead.\n", HTTP_CONTENT_ENCODING_GZIP));
        Status = HttpIoSetHeader (HttpIoHeader, HTTP_HEADER_CONTENT_ENCODING, HTTP_CONTENT_ENCODING_IDENTITY);
        if (EFI_ERROR (Status)) {
          goto ON_ERROR;
        }
      } else {
        Status = HttpIoSetHeader (HttpIoHeader, HTTP_HEADER_CONTENT_ENCODING, HTTP_CONTENT_ENCODING_GZIP);
        if (EFI_ERROR (Status)) {
          goto ON_ERROR;
        }
      }
    }
  }

  //
  // Step 2: build the rest of HTTP request info.
  //
  RequestData = AllocateZeroPool (sizeof (EFI_HTTP_REQUEST_DATA));
  if (RequestData == NULL) {
    goto ON_ERROR;
  }

  RequestData->Method = Method;
  RequestData->Url    = C8ToC16 (Url);

  //
  // Step 3: fill in EFI_HTTP_MESSAGE
  //
  RequestMsg = AllocateZeroPool (sizeof (EFI_HTTP_MESSAGE));
  if (RequestMsg == NULL) {
    goto ON_ERROR;
  }

  RequestMsg->Data.Request = RequestData;
  RequestMsg->HeaderCount  = HttpIoHeader->HeaderCount;
  RequestMsg->Headers      = HttpIoHeader->Headers;

  if (HasContent) {
    RequestMsg->BodyLength = (DoContentEncoding ? EncodedContentLen : ContentLength);
    RequestMsg->Body       = (VOID *)(DoContentEncoding ? EncodedContent : Content);
  }

  return RequestMsg;

ON_ERROR:

  if (HttpIoHeader != NULL) {
    HttpIoFreeHeader (HttpIoHeader);
  }

  if (RequestData != NULL) {
    FreePool (RequestData);
  }

  if (RequestMsg != NULL) {
    FreePool (RequestMsg);
  }

  return NULL;
}

json_t *
ParseResponseMsg (
  EFI_HTTP_MESSAGE      *ResponseMsg,
  EFI_HTTP_STATUS_CODE  **StatusCode,
  EFI_HTTP_HEADER       **Headers OPTIONAL,
  UINTN                 *HeaderCount OPTIONAL
  )
{
  EFI_STATUS       Status;
  json_t           *Data;
  EFI_HTTP_HEADER  *ContentEncodedHeader;

  if ((ResponseMsg == NULL) || (StatusCode == NULL)) {
    return NULL;
  }

  if (((Headers != NULL) && (HeaderCount == NULL))) {
    return NULL;
  }

  //
  // Initialization
  //
  Data        = NULL;
  *StatusCode = NULL;
  if (Headers != NULL) {
    *Headers     = NULL;
    *HeaderCount = 0;
  }

  //
  // Return the HTTP StatusCode.
  //
  if (ResponseMsg->Data.Response != NULL) {
    *StatusCode = AllocateZeroPool (sizeof (EFI_HTTP_STATUS_CODE));
    if (*StatusCode == NULL) {
      goto ON_ERROR;
    }

    //
    // The caller shall take the responsibility to free the buffer.
    //
    **StatusCode = ResponseMsg->Data.Response->StatusCode;
  }

  //
  // Return the HTTP headers.
  //
  if ((ResponseMsg->Headers != NULL) && (Headers != NULL) && (HeaderCount != NULL)) {
    *Headers = cloneHttpHeaders (ResponseMsg, HeaderCount);
  }

  //
  // Return the HTTP body.
  //
  if ((ResponseMsg->BodyLength != 0) && (ResponseMsg->Body != NULL)) {
    //
    // Check if data is encoded.
    //
    ContentEncodedHeader = HttpFindHeader (ResponseMsg->HeaderCount, ResponseMsg->Headers, HTTP_HEADER_CONTENT_ENCODING);
    if (ContentEncodedHeader != NULL) {
      //
      // The content is encoded.
      //
      Status = DecodeResponseContent (ContentEncodedHeader->FieldValue, &ResponseMsg->Body, &ResponseMsg->BodyLength);
      if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_ERROR, "%a: Failed to decompress the response content %r\n.", __func__, Status));
        goto ON_ERROR;
      }
    }

    Data = json_loadb (ResponseMsg->Body, ResponseMsg->BodyLength, 0, NULL);
  }

  return Data;

ON_ERROR:

  if (*StatusCode != NULL) {
    FreePool (*StatusCode);
  }

  if ((Headers != NULL) && (*Headers != NULL)) {
    HttpFreeHeaderFields (*Headers, *HeaderCount);
  }

  return NULL;
}

json_t *
getUriFromServiceEx (
  redfishService        *service,
  const char            *uri,
  REDFISH_HTTP_HEADER   *RequestHeader OPTIONAL,
  REDFISH_HTTP_HEADER   *ResponseHeader OPTIONAL,
  EFI_HTTP_STATUS_CODE  **StatusCode
  )
{
  json_t            *ret;
  EFI_STATUS        Status;
  EFI_HTTP_MESSAGE  *RequestMsg;
  EFI_HTTP_MESSAGE  ResponseMsg;

  if ((service == NULL) || (uri == NULL) || (StatusCode == NULL)) {
    return NULL;
  }

  DEBUG ((DEBUG_MANAGEABILITY, "%a: %a\n", __func__, uri));

  ZeroMem (&ResponseMsg, sizeof (ResponseMsg));

  RequestMsg = BuildRequestMsg (service, uri, HttpMethodGet, RequestHeader, 0, NULL, NULL, PcdGetBool (PcdRedfishServiceContentEncoding));
  if (RequestMsg == NULL) {
    DEBUG ((DEBUG_ERROR, "%a: cannot build request message for %a\n", __func__, uri));
    return NULL;
  }

  //
  // call RESTEx to get response from REST service.
  //
  Status = service->RestEx->SendReceive (service->RestEx, RequestMsg, &ResponseMsg);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: %a SendReceive failure: %r\n", __func__, uri, Status));
  }

  //
  // Return status code, headers and payload to caller as much as possible.
  //
  ret = ParseResponseMsg (&ResponseMsg, StatusCode, (ResponseHeader == NULL ? NULL : &ResponseHeader->Headers), (ResponseHeader == NULL ? NULL : &ResponseHeader->HeaderCount));

  //
  // Release resources
  //
  if (RequestMsg != NULL) {
    RestConfigFreeHttpMessage (RequestMsg, TRUE);
  }

  RestConfigFreeHttpMessage (&ResponseMsg, FALSE);

  return ret;
}

json_t *
putUriFromServiceEx (
  redfishService        *service,
  const char            *uri,
  const char            *content,
  size_t                contentLength,
  const char            *contentType,
  EFI_HTTP_HEADER       **Headers OPTIONAL,
  UINTN                 *HeaderCount OPTIONAL,
  EFI_HTTP_STATUS_CODE  **StatusCode
  )
{
  json_t            *ret;
  EFI_STATUS        Status;
  EFI_HTTP_MESSAGE  *RequestMsg;
  EFI_HTTP_MESSAGE  ResponseMsg;

  if ((service == NULL) || (uri == NULL) || (content == NULL) || (StatusCode == NULL)) {
    return NULL;
  }

  DEBUG ((DEBUG_MANAGEABILITY, "%a: %a\n", __func__, uri));

  ZeroMem (&ResponseMsg, sizeof (ResponseMsg));

  RequestMsg = BuildRequestMsg (service, uri, HttpMethodPut, NULL, contentLength, contentType, content, PcdGetBool (PcdRedfishServiceContentEncoding));
  if (RequestMsg == NULL) {
    DEBUG ((DEBUG_ERROR, "%a: cannot build request message for %a\n", __func__, uri));
    return NULL;
  }

  //
  // call RESTEx to get response from REST service.
  //
  Status = service->RestEx->SendReceive (service->RestEx, RequestMsg, &ResponseMsg);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: %a SendReceive failure: %r\n", __func__, uri, Status));
  }

  //
  // Return status code, headers and payload to caller as much as possible.
  //
  ret = ParseResponseMsg (&ResponseMsg, StatusCode, Headers, HeaderCount);

  //
  // Release resources
  //

  if (RequestMsg != NULL) {
    FreePool (RequestMsg);
  }

  RestConfigFreeHttpMessage (&ResponseMsg, FALSE);

  return ret;
}

json_t *
patchUriFromServiceEx (
  redfishService        *service,
  const char            *uri,
  const char            *content,
  size_t                contentLength OPTIONAL,
  const char            *contentType OPTIONAL,
  EFI_HTTP_HEADER       **Headers OPTIONAL,
  UINTN                 *HeaderCount OPTIONAL,
  EFI_HTTP_STATUS_CODE  **StatusCode
  )
{
  json_t            *ret;
  EFI_STATUS        Status;
  EFI_HTTP_MESSAGE  *RequestMsg;
  EFI_HTTP_MESSAGE  ResponseMsg;

  if ((service == NULL) || (uri == NULL) || (content == NULL) || (StatusCode == NULL)) {
    return NULL;
  }

  DEBUG ((DEBUG_MANAGEABILITY, "%a: %a\n", __func__, uri));

  ZeroMem (&ResponseMsg, sizeof (ResponseMsg));

  RequestMsg = BuildRequestMsg (service, uri, HttpMethodPatch, NULL, contentLength, contentType, content, PcdGetBool (PcdRedfishServiceContentEncoding));
  if (RequestMsg == NULL) {
    DEBUG ((DEBUG_ERROR, "%a: cannot build request message for %a\n", __func__, uri));
    return NULL;
  }

  //
  // call RESTEx to get response from REST service.
  //
  Status = service->RestEx->SendReceive (service->RestEx, RequestMsg, &ResponseMsg);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: %a SendReceive failure: %r\n", __func__, uri, Status));
  }

  //
  // Return status code, headers and payload to caller as much as possible.
  //
  ret = ParseResponseMsg (&ResponseMsg, StatusCode, Headers, HeaderCount);

  //
  // Release resources
  //

  if (RequestMsg != NULL) {
    FreePool (RequestMsg);
  }

  RestConfigFreeHttpMessage (&ResponseMsg, FALSE);

  return ret;
}

json_t *
postUriFromServiceEx (
  redfishService        *service,
  const char            *uri,
  const char            *content,
  size_t                contentLength,
  const char            *contentType,
  EFI_HTTP_HEADER       **Headers OPTIONAL,
  UINTN                 *HeaderCount OPTIONAL,
  EFI_HTTP_STATUS_CODE  **StatusCode
  )
{
  json_t            *ret;
  EFI_STATUS        Status;
  EFI_HTTP_MESSAGE  *RequestMsg;
  EFI_HTTP_MESSAGE  ResponseMsg;
  EFI_HTTP_HEADER   *XAuthTokenHeader;

  if ((service == NULL) || (uri == NULL) || (content == NULL) || (StatusCode == NULL)) {
    return NULL;
  }

  DEBUG ((DEBUG_MANAGEABILITY, "%a: %a\n", __func__, uri));

  ZeroMem (&ResponseMsg, sizeof (ResponseMsg));

  RequestMsg = BuildRequestMsg (service, uri, HttpMethodPost, NULL, contentLength, contentType, content, PcdGetBool (PcdRedfishServiceContentEncoding));
  if (RequestMsg == NULL) {
    DEBUG ((DEBUG_ERROR, "%a: cannot build request message for %a\n", __func__, uri));
    return NULL;
  }

  //
  // call RESTEx to get response from REST service.
  //
  Status = service->RestEx->SendReceive (service->RestEx, RequestMsg, &ResponseMsg);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: %a SendReceive failure: %r\n", __func__, uri, Status));
  }

  //
  // Return status code, headers and payload to caller as much as possible.
  //
  ret = ParseResponseMsg (&ResponseMsg, StatusCode, Headers, HeaderCount);

  //
  // Parsing the HttpHeader to retrieve the X-Auth-Token if the HTTP StatusCode is correct.
  //
  if ((ResponseMsg.Data.Response != NULL) &&
      ((ResponseMsg.Data.Response->StatusCode == HTTP_STATUS_200_OK) ||
       (ResponseMsg.Data.Response->StatusCode == HTTP_STATUS_204_NO_CONTENT)))
  {
    XAuthTokenHeader = HttpFindHeader (ResponseMsg.HeaderCount, ResponseMsg.Headers, HTTP_HEADER_X_AUTH_TOKEN);
    if (XAuthTokenHeader != NULL) {
      if (service->sessionToken != NULL) {
        free (service->sessionToken);
      }

      service->sessionToken = AllocateCopyPool (AsciiStrSize (XAuthTokenHeader->FieldValue), XAuthTokenHeader->FieldValue);
    }
  }

  //
  // Release resources
  //

  if (RequestMsg != NULL) {
    FreePool (RequestMsg);
  }

  RestConfigFreeHttpMessage (&ResponseMsg, FALSE);

  return ret;
}

json_t *
getUriFromService (
  redfishService        *service,
  const char            *uri,
  EFI_HTTP_STATUS_CODE  **StatusCode
  )
{
  return getUriFromServiceEx (service, uri, NULL, NULL, StatusCode);
}

json_t *
patchUriFromService (
  redfishService        *service,
  const char            *uri,
  const char            *content,
  EFI_HTTP_STATUS_CODE  **StatusCode
  )
{
  return patchUriFromServiceEx (service, uri, content, 0, NULL, NULL, NULL, StatusCode);
}

json_t *
postUriFromService (
  redfishService        *service,
  const char            *uri,
  const char            *content,
  size_t                contentLength,
  const char            *contentType,
  EFI_HTTP_STATUS_CODE  **StatusCode
  )
{
  return postUriFromServiceEx (service, uri, content, contentLength, contentType, NULL, NULL, StatusCode);
}

json_t *
deleteUriFromServiceEx (
  redfishService        *service,
  const char            *uri,
  const char            *content OPTIONAL,
  size_t                contentLength OPTIONAL,
  const char            *contentType OPTIONAL,
  EFI_HTTP_HEADER       **Headers OPTIONAL,
  UINTN                 *HeaderCount OPTIONAL,
  EFI_HTTP_STATUS_CODE  **StatusCode
  )
{
  json_t            *ret;
  EFI_STATUS        Status;
  EFI_HTTP_MESSAGE  *RequestMsg;
  EFI_HTTP_MESSAGE  ResponseMsg;

  if ((service == NULL) || (uri == NULL) || (StatusCode == NULL)) {
    return NULL;
  }

  DEBUG ((DEBUG_MANAGEABILITY, "%a: %a\n", __func__, uri));

  ZeroMem (&ResponseMsg, sizeof (ResponseMsg));

  RequestMsg = BuildRequestMsg (service, uri, HttpMethodDelete, NULL, contentLength, contentType, content, PcdGetBool (PcdRedfishServiceContentEncoding));
  if (RequestMsg == NULL) {
    DEBUG ((DEBUG_ERROR, "%a: cannot build request message for %a\n", __func__, uri));
    return NULL;
  }

  //
  // call RESTEx to get response from REST service.
  //
  Status = service->RestEx->SendReceive (service->RestEx, RequestMsg, &ResponseMsg);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: %a SendReceive failure: %r\n", __func__, uri, Status));
  }

  //
  // Return status code, headers and payload to caller as much as possible.
  //
  ret = ParseResponseMsg (&ResponseMsg, StatusCode, Headers, HeaderCount);

  //
  // Release resources
  //

  if (RequestMsg != NULL) {
    FreePool (RequestMsg);
  }

  RestConfigFreeHttpMessage (&ResponseMsg, FALSE);

  return ret;
}

json_t *
deleteUriFromService (
  redfishService        *service,
  const char            *uri,
  EFI_HTTP_STATUS_CODE  **StatusCode
  )
{
  return deleteUriFromServiceEx (service, uri, NULL, 0, NULL, NULL, NULL, StatusCode);
}

redfishPayload *
getRedfishServiceRoot (
  redfishService        *service,
  const char            *version,
  EFI_HTTP_STATUS_CODE  **StatusCode
  )
{
  json_t      *value;
  json_t      *versionNode;
  const char  *verUrl;

  if (version == NULL) {
    versionNode = json_object_get (service->versions, "v1");
  } else {
    versionNode = json_object_get (service->versions, version);
  }

  if (versionNode == NULL) {
    return NULL;
  }

  verUrl = json_string_value (versionNode);
  if (verUrl == NULL) {
    return NULL;
  }

  value = getUriFromService (service, verUrl, StatusCode);
  if (value == NULL) {
    if ((service->flags & REDFISH_FLAG_SERVICE_NO_VERSION_DOC) == 0) {
      json_decref (versionNode);
    }

    return NULL;
  }

  return createRedfishPayload (value, service);
}

redfishPayload *
getPayloadByPath (
  redfishService        *service,
  const char            *path,
  EFI_HTTP_STATUS_CODE  **StatusCode
  )
{
  redPathNode     *redpath;
  redfishPayload  *root;
  redfishPayload  *ret;

  if (!service || !path || (StatusCode == NULL)) {
    return NULL;
  }

  *StatusCode = NULL;

  redpath = parseRedPath (path);
  if (!redpath) {
    return NULL;
  }

  if (!redpath->isRoot) {
    cleanupRedPath (redpath);
    return NULL;
  }

  root = getRedfishServiceRoot (service, redpath->version, StatusCode);
  if ((*StatusCode == NULL) || (**StatusCode < HTTP_STATUS_200_OK) || (**StatusCode > HTTP_STATUS_206_PARTIAL_CONTENT)) {
    cleanupRedPath (redpath);
    return root;
  }

  if (redpath->next == NULL) {
    cleanupRedPath (redpath);
    return root;
  }

  FreePool (*StatusCode);
  *StatusCode = NULL;

  ret = getPayloadForPath (root, redpath->next, StatusCode);
  if ((*StatusCode == NULL) && (ret != NULL)) {
    //
    // In such a case, the Redfish resource is parsed from the input payload (root) directly.
    // So, we still return HTTP_STATUS_200_OK.
    //
    *StatusCode = AllocateZeroPool (sizeof (EFI_HTTP_STATUS_CODE));
    if (*StatusCode == NULL) {
      ret = NULL;
    } else {
      **StatusCode = HTTP_STATUS_200_OK;
    }
  }

  cleanupPayload (root);
  cleanupRedPath (redpath);
  return ret;
}

void
cleanupServiceEnumerator (
  redfishService  *service
  )
{
  if (!service) {
    return;
  }

  free (service->host);
  json_decref (service->versions);
  if (service->sessionToken != NULL) {
    ZeroMem (service->sessionToken, (UINTN)strlen (service->sessionToken));
    FreePool (service->sessionToken);
  }

  if (service->basicAuthStr != NULL) {
    ZeroMem (service->basicAuthStr, (UINTN)strlen (service->basicAuthStr));
    FreePool (service->basicAuthStr);
  }

  free (service);
}

static int
initRest (
  redfishService  *service,
  void            *restProtocol
  )
{
  service->RestEx = restProtocol;
  return 0;
}

static redfishService *
createServiceEnumeratorNoAuth (
  const char    *host,
  const char    *rootUri,
  bool          enumerate,
  unsigned int  flags,
  void          *restProtocol
  )
{
  redfishService  *ret;
  char            *HostStart;

  ret = (redfishService *)calloc (1, sizeof (redfishService));
  ZeroMem (ret, sizeof (redfishService));
  if (initRest (ret, restProtocol) != 0) {
    free (ret);
    return NULL;
  }

  ret->host  = AllocateCopyPool (AsciiStrSize (host), host);
  ret->flags = flags;
  if (enumerate) {
    ret->versions = getVersions (ret, rootUri);
  }

  HostStart = strstr (ret->host, "//");
  if ((HostStart != NULL) && (*(HostStart + 2) != '\0')) {
    ret->HostHeaderValue = HostStart + 2;
  }

  return ret;
}

EFI_STATUS
createBasicAuthStr (
  IN  redfishService  *service,
  IN  CONST CHAR8     *UserId,
  IN  CONST CHAR8     *Password
  )
{
  EFI_STATUS  Status;
  CHAR8       *RawAuthValue;
  UINTN       RawAuthBufSize;
  CHAR8       *EnAuthValue;
  UINTN       EnAuthValueSize;
  CHAR8       *BasicWithEnAuthValue;
  UINTN       BasicBufSize;

  EnAuthValue     = NULL;
  EnAuthValueSize = 0;

  RawAuthBufSize = AsciiStrLen (UserId) + AsciiStrLen (Password) + 2;
  RawAuthValue   = AllocatePool (RawAuthBufSize);
  if (RawAuthValue == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Build raw AuthValue (UserId:Password).
  //
  AsciiSPrint (
    RawAuthValue,
    RawAuthBufSize,
    "%a:%a",
    UserId,
    Password
    );

  //
  // Encoding RawAuthValue into Base64 format.
  //
  Status = Base64Encode (
             (CONST UINT8 *)RawAuthValue,
             AsciiStrLen (RawAuthValue),
             EnAuthValue,
             &EnAuthValueSize
             );
  if (Status == EFI_BUFFER_TOO_SMALL) {
    EnAuthValue = (CHAR8 *)AllocateZeroPool (EnAuthValueSize);
    if (EnAuthValue == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      return Status;
    }

    Status = Base64Encode (
               (CONST UINT8 *)RawAuthValue,
               AsciiStrLen (RawAuthValue),
               EnAuthValue,
               &EnAuthValueSize
               );
  }

  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  BasicBufSize         = AsciiStrLen ("Basic ") + AsciiStrLen (EnAuthValue) + 2;
  BasicWithEnAuthValue = AllocatePool (BasicBufSize);
  if (BasicWithEnAuthValue == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Exit;
  }

  //
  // Build encoded EnAuthValue with Basic (Basic EnAuthValue).
  //
  AsciiSPrint (
    BasicWithEnAuthValue,
    BasicBufSize,
    "%a %a",
    "Basic",
    EnAuthValue
    );

  service->basicAuthStr = BasicWithEnAuthValue;

Exit:
  if (RawAuthValue != NULL) {
    ZeroMem (RawAuthValue, RawAuthBufSize);
    FreePool (RawAuthValue);
  }

  if (EnAuthValue != NULL) {
    ZeroMem (EnAuthValue, EnAuthValueSize);
    FreePool (EnAuthValue);
  }

  return Status;
}

static redfishService *
createServiceEnumeratorBasicAuth (
  const char    *host,
  const char    *rootUri,
  const char    *username,
  const char    *password,
  unsigned int  flags,
  void          *restProtocol
  )
{
  redfishService  *ret;
  EFI_STATUS      Status;

  ret = createServiceEnumeratorNoAuth (host, rootUri, false, flags, restProtocol);

  // add basic auth str
  Status = createBasicAuthStr (ret, username, password);
  if (EFI_ERROR (Status)) {
    cleanupServiceEnumerator (ret);
    return NULL;
  }

  ret->versions = getVersions (ret, rootUri);
  return ret;
}

static redfishService *
createServiceEnumeratorSessionAuth (
  const char    *host,
  const char    *rootUri,
  const char    *username,
  const char    *password,
  unsigned int  flags,
  void          *restProtocol
  )
{
  redfishService        *ret;
  redfishPayload        *payload;
  redfishPayload        *links;
  json_t                *sessionPayload;
  json_t                *session;
  json_t                *odataId;
  const char            *uri;
  json_t                *post;
  char                  *content;
  EFI_HTTP_STATUS_CODE  *StatusCode;

  content    = NULL;
  StatusCode = NULL;

  ret = createServiceEnumeratorNoAuth (host, rootUri, true, flags, restProtocol);
  if (ret == NULL) {
    return NULL;
  }

  payload = getRedfishServiceRoot (ret, NULL, &StatusCode);
  if ((StatusCode == NULL) || (*StatusCode < HTTP_STATUS_200_OK) || (*StatusCode > HTTP_STATUS_206_PARTIAL_CONTENT)) {
    if (StatusCode != NULL) {
      FreePool (StatusCode);
    }

    if (payload != NULL) {
      cleanupPayload (payload);
    }

    cleanupServiceEnumerator (ret);
    return NULL;
  }

  if (StatusCode != NULL) {
    FreePool (StatusCode);
    StatusCode = NULL;
  }

  links = getPayloadByNodeName (payload, "Links", &StatusCode);
  cleanupPayload (payload);
  if (links == NULL) {
    cleanupServiceEnumerator (ret);
    return NULL;
  }

  session = json_object_get (links->json, "Sessions");
  if (session == NULL) {
    cleanupPayload (links);
    cleanupServiceEnumerator (ret);
    return NULL;
  }

  odataId = json_object_get (session, "@odata.id");
  if (odataId == NULL) {
    cleanupPayload (links);
    cleanupServiceEnumerator (ret);
    return NULL;
  }

  uri  = json_string_value (odataId);
  post = json_object ();
  addStringToJsonObject (post, "UserName", username);
  addStringToJsonObject (post, "Password", password);
  content = json_dumps (post, 0);
  json_decref (post);
  sessionPayload = postUriFromService (ret, uri, content, 0, NULL, &StatusCode);

  if (content != NULL) {
    ZeroMem (content, (UINTN)strlen (content));
    free (content);
  }

  if ((sessionPayload == NULL) || (StatusCode == NULL) || (*StatusCode < HTTP_STATUS_200_OK) || (*StatusCode > HTTP_STATUS_206_PARTIAL_CONTENT)) {
    // Failed to create session!

    cleanupPayload (links);
    cleanupServiceEnumerator (ret);

    if (StatusCode != NULL) {
      FreePool (StatusCode);
    }

    if (sessionPayload != NULL) {
      json_decref (sessionPayload);
    }

    return NULL;
  }

  json_decref (sessionPayload);
  cleanupPayload (links);
  FreePool (StatusCode);
  return ret;
}

static char *
makeUrlForService (
  redfishService  *service,
  const char      *uri
  )
{
  char  *url;

  if (service->host == NULL) {
    return NULL;
  }

  url = (char *)malloc (strlen (service->host)+strlen (uri)+1);
  if (url == NULL) {
    return NULL;
  }

  strcpy (url, service->host);
  strcat (url, uri);
  return url;
}

static json_t *
getVersions (
  redfishService  *service,
  const char      *rootUri
  )
{
  json_t                *ret        = NULL;
  EFI_HTTP_STATUS_CODE  *StatusCode = NULL;

  if (service->flags & REDFISH_FLAG_SERVICE_NO_VERSION_DOC) {
    service->versions = json_object ();
    if (service->versions == NULL) {
      return NULL;
    }

    addStringToJsonObject (service->versions, "v1", "/redfish/v1");
    return service->versions;
  }

  if (rootUri != NULL) {
    ret = getUriFromService (service, rootUri, &StatusCode);
  } else {
    ret = getUriFromService (service, "/redfish", &StatusCode);
  }

  if ((ret == NULL) || (StatusCode == NULL) || (*StatusCode < HTTP_STATUS_200_OK) || (*StatusCode > HTTP_STATUS_206_PARTIAL_CONTENT)) {
    if (ret != NULL) {
      json_decref (ret);
    }

    ret = NULL;
  }

  if (StatusCode != NULL) {
    FreePool (StatusCode);
  }

  return ret;
}

static void
addStringToJsonObject (
  json_t      *object,
  const char  *key,
  const char  *value
  )
{
  json_t  *jValue = json_string (value);

  json_object_set (object, key, jValue);

  json_decref (jValue);
}
