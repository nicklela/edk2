/** @file
  This file defines the Redfish HTTP library interface.

  Copyright (c) 2023-2024, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef REDFISH_HTTP_LIB_H_
#define REDFISH_HTTP_LIB_H_

#include <Protocol/EdkIIRedfishHttpProtocol.h>

/**
  This function free resources in Request. Request is no longer available
  after this function returns successfully.

  @param[in]  Request      HTTP request to be released.

  @retval     EFI_SUCCESS     Resrouce is released successfully.
  @retval     Others          Errors occur.

**/
EFI_STATUS
RedfishHttpFreeRequest (
  IN  REDFISH_REQUEST  *Request
  );

/**
  This function free resources in Response. Response is no longer available
  after this function returns successfully.

  @param[in]  Response     HTTP response to be released.

  @retval     EFI_SUCCESS     Resrouce is released successfully.
  @retval     Others          Errors occur.

**/
EFI_STATUS
RedfishHttpFreeResponse (
  IN  REDFISH_RESPONSE  *Response
  );

/**
  This function expire the cached response of given URI.

  @param[in]  Uri          Target response of URI.

  @retval     EFI_SUCCESS     Target response is expired successfully.
  @retval     Others          Errors occur.

**/
EFI_STATUS
RedfishHttpExpireResponse (
  IN  EFI_STRING  Uri
  );

/**
  Get redfish resource from given resource URI with cache mechanism
  supported. It's caller's responsibility to Response by calling
  RedfishHttpFreeResponse ().

  @param[in]  Service       Redfish service instance to make query.
  @param[in]  Uri           Target resource URI.
  @param[in]  Request       Additional request context. This is optional.
  @param[out] Response      HTTP response from redfish service.
  @param[in]  UseCache      If it is TRUE, this function will search for
                            cache first. If it is FALSE, this function
                            will query Redfish URI directly.

  @retval     EFI_SUCCESS     Resrouce is returned successfully.
  @retval     Others          Errors occur.

**/
EFI_STATUS
RedfishHttpGetResource (
  IN  REDFISH_SERVICE   Service,
  IN  EFI_STRING        Uri,
  IN  REDFISH_REQUEST   *Request OPTIONAL,
  OUT REDFISH_RESPONSE  *Response,
  IN  BOOLEAN           UseCache
  );

/**
  Perform HTTP PATCH to send redfish resource to given resource URI.
  It's caller's responsibility to free Response by calling RedfishHttpFreeResponse ().

  @param[in]  Service       Redfish service instance to make query.
  @param[in]  Uri           Target resource URI.
  @param[in]  Content       Data to patch.
  @param[out] Response      HTTP response from redfish service.

  @retval     EFI_SUCCESS     Resrouce is returned successfully.
  @retval     Others          Errors occur.

**/
EFI_STATUS
RedfishHttpPatchResource (
  IN  REDFISH_SERVICE   Service,
  IN  EFI_STRING        Uri,
  IN  CHAR8             *Content,
  OUT REDFISH_RESPONSE  *Response
  );

/**
  Perform HTTP PATCH to send redfish resource to given resource URI.
  It's caller's responsibility to free Response by calling RedfishHttpFreeResponse ().

  @param[in]  Service       Redfish service instance to make query.
  @param[in]  Uri           Target resource URI.
  @param[in]  Content       Data to patch.
  @param[in]  ContentSize   Size of the Content to be send to Redfish service.
                            This is optional. When ContentSize is 0, ContentSize
                            is the size of Content.
  @param[in]  ContentType   Type of the Content to be send to Redfish service.
                            This is optional.
  @param[out] Response      HTTP response from redfish service.

  @retval     EFI_SUCCESS     Resrouce is returned successfully.
  @retval     Others          Errors occur.

**/
EFI_STATUS
RedfishHttpPatchResourceEx (
  IN  REDFISH_SERVICE   Service,
  IN  EFI_STRING        Uri,
  IN  CHAR8             *Content,
  IN  UINTN             ContentSize OPTIONAL,
  IN  CHAR8             *ContentType OPTIONAL,
  OUT REDFISH_RESPONSE  *Response
  );

/**
  Perform HTTP PUT to send redfish resource to given resource URI.
  It's caller's responsibility to free Response by calling RedfishHttpFreeResponse ().

  @param[in]  Service       Redfish service instance to make query.
  @param[in]  Uri           Target resource URI.
  @param[in]  Content       Data to put.
  @param[out] Response      HTTP response from redfish service.

  @retval     EFI_SUCCESS     Resrouce is returned successfully.
  @retval     Others          Errors occur.

**/
EFI_STATUS
RedfishHttpPutResource (
  IN  REDFISH_SERVICE   Service,
  IN  EFI_STRING        Uri,
  IN  CHAR8             *Content,
  OUT REDFISH_RESPONSE  *Response
  );

/**
  Perform HTTP PUT to send redfish resource to given resource URI.
  It's caller's responsibility to free Response by calling RedfishHttpFreeResponse ().

  @param[in]  Service       Redfish service instance to make query.
  @param[in]  Uri           Target resource URI.
  @param[in]  Content       Data to put.
  @param[in]  ContentSize   Size of the Content to be send to Redfish service.
                            This is optional. When ContentSize is 0, ContentSize
                            is the size of Content.
  @param[in]  ContentType   Type of the Content to be send to Redfish service.
                            This is optional.
  @param[out] Response      HTTP response from redfish service.

  @retval     EFI_SUCCESS     Resrouce is returned successfully.
  @retval     Others          Errors occur.

**/
EFI_STATUS
RedfishHttpPutResourceEx (
  IN  REDFISH_SERVICE   Service,
  IN  EFI_STRING        Uri,
  IN  CHAR8             *Content,
  IN  UINTN             ContentSize OPTIONAL,
  IN  CHAR8             *ContentType OPTIONAL,
  OUT REDFISH_RESPONSE  *Response
  );

/**
  Perform HTTP POST to send redfish resource to given resource URI.
  It's caller's responsibility to free Response by calling RedfishHttpFreeResponse ().

  @param[in]  Service       Redfish service instance to make query.
  @param[in]  Uri           Target resource URI.
  @param[in]  Content       Data to post.
  @param[out] Response      HTTP response from redfish service.

  @retval     EFI_SUCCESS     Resrouce is returned successfully.
  @retval     Others          Errors occur.

**/
EFI_STATUS
RedfishHttpPostResource (
  IN  REDFISH_SERVICE   Service,
  IN  EFI_STRING        Uri,
  IN  CHAR8             *Content,
  OUT REDFISH_RESPONSE  *Response
  );

/**
  Perform HTTP POST to send redfish resource to given resource URI.
  It's caller's responsibility to free Response by calling RedfishHttpFreeResponse ().

  @param[in]  Service       Redfish service instance to make query.
  @param[in]  Uri           Target resource URI.
  @param[in]  Content       Data to post.
  @param[in]  ContentSize   Size of the Content to be send to Redfish service.
                            This is optional. When ContentSize is 0, ContentSize
                            is the size of Content.
  @param[in]  ContentType   Type of the Content to be send to Redfish service.
                            This is optional.
  @param[out] Response      HTTP response from redfish service.

  @retval     EFI_SUCCESS     Resrouce is returned successfully.
  @retval     Others          Errors occur.

**/
EFI_STATUS
RedfishHttpPostResourceEx (
  IN  REDFISH_SERVICE   Service,
  IN  EFI_STRING        Uri,
  IN  CHAR8             *Content,
  IN  UINTN             ContentSize OPTIONAL,
  IN  CHAR8             *ContentType OPTIONAL,
  OUT REDFISH_RESPONSE  *Response
  );

/**
  Perform HTTP DELETE to delete redfish resource on given resource URI.
  It's caller's responsibility to free Response by calling RedfishHttpFreeResponse ().

  @param[in]  Service       Redfish service instance to make query.
  @param[in]  Uri           Target resource URI.
  @param[out] Response      HTTP response from redfish service.

  @retval     EFI_SUCCESS     Resrouce is returned successfully.
  @retval     Others          Errors occur.

**/
EFI_STATUS
RedfishHttpDeleteResource (
  IN  REDFISH_SERVICE   Service,
  IN  EFI_STRING        Uri,
  OUT REDFISH_RESPONSE  *Response
  );

/**
  Perform HTTP DELETE to delete redfish resource on given resource URI.
  It's caller's responsibility to free Response by calling RedfishHttpFreeResponse ().

  @param[in]  Service       Redfish service instance to make query.
  @param[in]  Uri           Target resource URI.
  @param[in]  Content       JSON represented properties to be deleted. This is
                            optional.
  @param[in]  ContentSize   Size of the Content to be send to Redfish service.
                            This is optional. When ContentSize is 0, ContentSize
                            is the size of Content if Content is not NULL.
  @param[in]  ContentType   Type of the Content to be send to Redfish service.
                            This is optional.
  @param[out] Response      HTTP response from redfish service.

  @retval     EFI_SUCCESS     Resrouce is returned successfully.
  @retval     Others          Errors occur.

**/
EFI_STATUS
RedfishHttpDeleteResourceEx (
  IN  REDFISH_SERVICE   Service,
  IN  EFI_STRING        Uri,
  IN  CHAR8             *Content OPTIONAL,
  IN  UINTN             ContentSize OPTIONAL,
  IN  CHAR8             *ContentType OPTIONAL,
  OUT REDFISH_RESPONSE  *Response
  );

#endif
