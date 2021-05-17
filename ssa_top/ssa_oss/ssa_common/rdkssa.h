/*
 * Copyright 2020 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
*/

#ifndef __rdkssa_inc__
#define __rdkssa_inc__
 
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

typedef enum { 
    rdkssaOK=0,
    rdkssaGeneralFailure=-1,
    rdkssaBadPointer=-2,
    rdkssaAttributeNotFound=-3,
    rdkssaSyntaxError=-4,
    rdkssaBadLength=-5,
    rdkssaValidityError=-6,
    rdkssaExpiresError=-7, 
	rdkssaMissingSource=-8,
	rdkssaFileError=-9,
	rdkssaEmptyAttribute=-10,
	rdkssaMissingAttribute=-11,
	rdkssaProviderNotFound=-12,
    /* more here */
    
    rdkssaNYIError=-100
              
} rdkssaStatus_t;

/**
 * Typedef for type safety when passing the generic pointers around
 */

typedef void * rdkssa_blobptr_t;

/**
* Typedef for opaque handles for objects managed by the framework
*/

typedef void * rdkssa_handle_t;


/**
*  rdkssaDataBuf_t defines a structure containing the length and databuffer for 
*  binary/memory based I/O options.
*
*  The dataBuffer member is defined to ensure a pointer-sized alignment.
*  Actual length must be handled by the caller.  To allocate, call
*  malloc( sizeof(rdkssaDataBuf_t) + sizeOfData ) where sizeOfData is the length
*  of the data buffer needed.
*
*  You MUST use the above allocation method to account for the alignment padding.
*  Do NOT use something like malloc( sizeof(size_t) + my_data_length );
*/

typedef struct rdkssaDataBuf_s { 
    size_t sizeOfData;
    uint8_t  __attribute__ ((aligned (sizeof(void*)))) dataBuffer[];
} rdkssaDataBuf_t, *rdkssaDataBufPtr_t;

/**
 * Declaration macro to ensure uniform API signature easily
 */
#define RDKSSA_API( apiname ) rdkssaStatus_t apiname (rdkssa_blobptr_t apiBlobPtr, const char * const apiAttributes[])

/**
 * Declaration macro for arrays of atttributes, to ensure compatibility easily:
 */
#define RDKSSA_ATTRIBS( attribsname ) const char * const attribsname[]

/**
 * For now, characters not allowed in parameter values
 */
#define RDKSSA_BADCHARS "{}@\\&|*<>[]()$;"

/**
 **
 ** Provider APIs
 **
 ** Unless indicated otherwise:
 ** Parameter/Attributes can be provided in any order, and mandatory ones are indicatd by a "+" which is NOT
 ** part of the name
 **
 ** Allowed character set:
 ** Until the full implementation using the secure exec wrapper is ready, the input char set MUST NOT include:
 **     Parsing delimiters: '{'   '}'   ','  
 **     Shell metachars: '@'   '\'   '&'   '|'   '*'   '<'   '>'   '['   ']'   '('   ')'   '$'   ';'
 **     The BEST implementation of any use of ssa is to use ALPHA-NUMERIC CHARS
 **
 ** All API's return: 
 ** - rdkssaOK if no errors occur.  
 ** - Otherwise, one of the above error codes for rdkssa errors, or
 ** - A positive value excess 10000 for error codes coming from the underlying platform implementation. (Subtract 10000 to recover platform error code)
 **   This is so an error code > 10000 can be differentiated from rdkssa codes
 **/


/**
 * 
 * rdkssaIdentityProvider
 *
 * Identity Provider takes a string vector, vector null-terminated, and returns the requested identity attribute(s)
 * Different providers may return the requested data in a provider-specific format, such as a JSON structure.
 * The default provider takes one attribute as input, and returns one requested identity attribute in the apiBlobPtr buffer
 *
 * apiBlobPtr      Pointer to a rdkssaDataBuf_t to recieve the information requested by the attribute
 *				   sizeOfData field contains the amount of memory available in rdkssaDataBuf_t and the data buffer 
 *				   MUST be large enough to receive the requested data
 *				   If not, rdkssaBadLength is returned and sizeOfData  will contain the amount of memory required.
 * attributes[]    Null terminated string array, default provider currently expects one non-NULL entry, followed by NULL, specifying the requested attribute
 *                 Currently supported identity attributes for the default provider are:
 *                 "BASEMACADDRESS", "SERIALNUMBER"
 *                 At least one must be present.
 *
 * Return:         If successful, *apiBlobPtr will contain a 0-terminated string with the value of the requested parameter.  MAC addresses are returned as colon-separated ASCII hex.
 *                 Other format specifics are/will be defined on Confluence
 *
 */
RDKSSA_API( rdkssaGetIdentityAttribute);

/**
 *
 * rdkssaStorageProvider
 *
 * StorageProvider provides facilities for storage and retrieval of data to/from a
 * secure store.  The details of the secure store are opaque to the caller.  At 
 * some point in the future, an API can be added to initialize a store with user-supplied
 * attributes, but at present, the store will use capabilities as defined by the underlying
 * platform and chosen store implementation for that platform. There may be hardware support,
 * or not, etc.
 *
 **/

/**
 * rdkssaStorageAccess
 *
 * blobPtr: If "SRC=MEM" or "DST=MEM" attribute is specified as described below, points to a rdkssaDataBuf_t
 *			For "DST=MEM" the destination buffer must be large enough for the requested data.
 *			If the destination buffer is too small, rdkssaBadLength is returned and the required size is stored in sizeOfData
 *
 * attributes[]:  NULL terminated list of strings containing one of the following sets of strings:
 * 
 * additional Name=Value pairs
 *  SRC=<inputfile> or SRC=MEM      (e.g. "IN=/path/to/file.dat")
 *
 * -or-
 *
 * additional Name=Value pairs
 *  DST=<outputfile> or DST=MEM
 *
 * -or-
 *
 *  DEL=<credential name>
 *
 * For "IN=MEM" or "OUT=MEM" the source or destination information is in the caller's
 * memory space. 
 * 
 */
RDKSSA_API(rdkssaStorageAccess);

/**
 * rdkssaCAProvider
 *
 * The CAProvider provides an interface to various certificate-authority-related functions to
 * abstract the implementation, vendor, etc. from the caller.
 *
 * The following API is defined for the CA Provider but not all are initially implemented
 * rdkssaCACreatePKCS12 (implemented)
 * rdkssaCACheckValidity (implemented)
 * rdkssaCAUpdatePKCS12 (implemented) 
 * rdkssaCACheckExpiration
 * rdkssaCACreateCSR
 * rdkssaCASignCSR
 * rdkssaCARevoke
 */

/**
 * rdkssaCACreatePKCS12
 *
 * blobPtr: Pointer to a reserved NULL pointer for use by the API implementation.  
 *          Must be writable, aligned for a pointer, and is opaque to the caller.
 * attributes[]: NULL terminated list of strings containing the following name=value pairs (with validity definitions)
 *          Attributes with "+" are required
 * +CN=<common name> (max length of CN: 255) ( allowed charset [alphanum\.\-] )
 * +MAC=<MAC address of requester> ( IPv4 or IPv6 address per standard )
 * +SER=<Serial number as defined by the platform)  ( [alphanum\-\.] )
 * +PATH=<path to return PKCS12 file to> ( valid path separator "/" plus [alphanum\.] )
 * TERMINATING ATTRIBUTE: MUST BE LAST in the vector of attributes
 * +PP=<passphrase for PKCS12 bundle> ( alphanum+punctuation )
 *
 * Optional:
 * SAN=<one additional SAN field> ( per SAN specifications )
 * IP=<IP address of requestor> ( per IP specifications )
 * VALID=<length of desired validity from "now"> ( format TBD )
 *
 * If successful, a PKCS12 bundle is saved to PATH, with private key protected under PP
 */
RDKSSA_API(rdkssaCACreatePKCS12);

/**
 * rdkssaCACheckValidity
 *
 * blobPtr: NULL
 * attributes[]: NULL terminated list of strings containing the listed name=value pairs (with validity definitions)
 * +PKCS12=<path to read PKCS12 file from> ( valid path separator "/" plus [alphanum\.] )
 * OR
 * +X509=<path to read PKCS12 file from> ( valid path separator "/" plus [alphanum\.] )
 *
 * Returns:
 *  rdkssaOK - if the certificate is good.
 *  rdkssaValidityError - if the cert is expired or there is an error with the platform implementation
 * 
 */
RDKSSA_API(rdkssaCACheckValidity);

/**
 * rdkssaCAUpdatePKCS12
 *
 * Performs an update of an existing PKCS12 bundle, reissuing it with updated keypair and expiration
 *
 * blobPtr: NULL
 * attributes[]:  NULL terminated list of strings containing the listed name=value pairs (with validity definitions)
 * +PATH=<path to read PKCS12 file from/ save to> ( valid path separator "/" plus [alphanum\.] )
 * VALIDITY=<length of desired validity from "now"> ( format TBD )
 *
 * If successful, the updated PKCS12 bundle is save to the location at PATH.
 */
RDKSSA_API(rdkssaCAUpdatePKCS12);

/**
* rdkssaSymmetricKey Provider
*
* The SymmetricKey Provider provides an interface to various symmetric key functions
*
*/

/**
* rdkssaCreateSymKey
* 
* blobPtr: pointer to 
* struct { 
*		rdkssa_handle_t keyHandle 
*		rdkssaDataBufPtr_t keySeed;
*	 }
*	keySeed may point to an array of bytes to be used in key derivation, or NULL if not used
*	if keySeed->sizeOfData == 0  keySeed will not be used nless required by TYPE in which case an error is returned.
*	keyHandle is defined & returned by the provider and is used to reference the created key in subsequent calls.

* attributes[]: NULL terminated list of strings containing the listed name=value pairs
* TYPE="HMAC" | "CMAC" | "PBKDF2" | "RAND" | "CEDM" (Comcast provider only) | <omitted>: default RAND
* LENGTH="128" | "256" | <omitted>: default 128
*
* Used/required for TYPE not "RAND"
* +SEED=<0-terminated UTF-8 string for key derivation> | "MEM" (data in keySeed->dataBuffer, keySeed->sizeoOfData must not be 0)
*
* Used & required with PBKDF2:
* +SALT=<0-terminated UTF-8 salt>
* ITER=<iterations> ([0-9]+) | <omitted>: default=10,000
*
* Used & required with HMAC and CMAC per NIST 800-108
* +LABEL=<0-terminated UTF>
* +CONTEXT=<0-terminated UTF-8>
*
*/

RDKSSA_API(rdkssaCreateSymKey);

/**
* rdkssaExtractSymKey	- extract RAW key bytes from a created key
*
* blobPtr: pointer to
* struct { 
*		rdkssa_handle_t keyHandle 
*		rdkssaDataBufPtr_t keyBytes;
*	 }
*	keyHandle is the value returned from rdkssaCreateSymKey
*	keyBytes is pointer to storage allocated by user to receive the exported key
*	keyBytes->sizeOfData must be large enough to contain the returned key in the requested format
*	If sizeOfData is too small, rdkssaBadLength is returned and sizeOfData  will contain the amount of memory required.
*   
* attributes[]:
* none = pass one attribute of 0 length or NUKLL
*
* WARNING: improper handling of key data may result in unwanted disclosure of the key value
* 
*/

RDKSSA_API(rdkssaExtractSymKey);

/**
* rdkssaDestroySymKey		- Permanently destroy symmetric key data
*
* blobPtr: Pointer to key handle returned from rdkssaCreateSymKey
* attributes[]:
* none = pass NULL or one attribute of 0 length
* 
*/

RDKSSA_API(rdkssaDestroySymKey);

/**
* rdkssaExportSymKey		- Export a wrapped key
*
* blobPtr: Pointer to
* struct { 
*		rdkssa_handle_t keyHandle
*		rdkssa_handle_t kekHandle;     If kek is in keyring, otherwise NULL
*		rdkssaDataBufPtr_t keyBytes;
*		rdkssaDataBufPtr_t kekBytes;   If kek is in byte format and kekHandle == NULL
*	 }
* attributes[]:
* TYPE="NIST" | "SIMPLE" | <omitted>: default "SIMPLE"
*
* If TYPE is "NIST" use the AES keywrap standard per NIST
* If TYPE is "SIMPLE" use a simple AES ECB encryption of the key; the key and kek sizes must agree
* Confidentiality and management of the KEK is the responsibility of the caller
* Wrapped key bytes are returned in keyBytes buffer:
*	keyBytes is pointer to storage allocated by user to receive the exported key
*	keyBytes->sizeOfData must be large enough to contain the returned key in the requested format
*	If sizeOfData is too small for the exported wrapped key,rdkssaBadLength is returned and the amount of 
*	storage required will be returned in sizeOfData
*	The actual size of the wrapped key is returned in sizeOfData regardless
*/

RDKSSA_API(rdkssaExportSymKey);

/**
* rdkssaImportSymKey		- Import a wrapped key so it can be unwrapped and used via keyring handle
*
* blobPtr: Pointer to
* struct { 
*		rdkssa_handle_t keyHandle
*		rdkssa_handle_t kekHandle;
*		rdkssaDataBufPtr_t keyBytes;
*	 }
* attributes[]:
* TYPE="NIST" | "SIMPLE" | <omitted>: default "SIMPLE"
* Confidentiality and management of the KEK is the responsibility of the caller
* If TYPE is "NIST" use the AES keywrap standard per NIST
* If TYPE is "SIMPLE" use a simple AES ECB encryption of the key; the key and kek sizes must agree
* Wrapped key bytes are input via keyBytes buffer:
*	keyBytes is pointer to storage containing the wrapped key
*	keyBytes->sizeOfData must be large enough to contain the returned key in the requested format
*	If sizeOfData is too small for the exported wrapped key,rdkssaBadLength is returned and the amount of 
*	storage required will be returned in sizeOfData
*/

RDKSSA_API(rdkssaImportSymKey);

/**
* rdkssaRandom Provider
*
* The Random Provider provides an interface to an underlying CSRNG
*
*/

/**
* rdkssaInitRandom		-	Initialize the provider's entropy pool
*
* blobPtr:	pointer to rdkssaDataBuf_t entropy; ( Optional, may be NULL ) 
* 			If present, data buffer contain the length and data to be used for seeding the entropy pool
*			If entropy->sizeOfData == 0, no seed data will be used
* attributes[]:
* SEED=<0-terminated UTF-8 string of entropy> ( Optional, may be NULL or empty attribute )
* If entropy and SEED are both present, they will both be used in an implementation-dependent way
*/

RDKSSA_API( rdkssaInitRandom );

/**
* rdkssaGetRandom		-	Obtain cryptographically random bytes
*
* blobPtr: pointer to rdkssaDataBuf_t randBytes;
* If the randBytes buffer contains zero sizeOfData, rdkssaBadLength is returned and no other action is taken.
* Otherwise the caller's buffer is filled with sizeOfData bytes from the providers CS(P)RNG
* attributes[]:
* none = pass NULL or one attribute of 0 length
*/

RDKSSA_API( rdkssaGetRandom );

/**
* rdkssaMount Provider
*
* The Mount Provider provides an interface to mount a persistent secure volume
*
*/

/**
* rdkssaMount		-	Mount a secure volume
*
*
* blobPtr: Pointer to a key handle returned from rdkssaCreateSymKey if KEY="HANDLE"
* attributes[]:
* +MOUNTPOINT=<where to mount the new volume>
* +PATH=<path of the new volume to be created>
* KEY=<path to credential, credential name per caller's storage provider> | "HANDLE" | <omitted>: provider-defined key material
* PARTITION=<device partition info>
*/

RDKSSA_API( rdkssaMount );

/**
* rdkssaUnmount	-	Unmount (but leave intact) a secure volume
*
* blobPtr: unused may be NULL
* attributes[]=
* +PATH=<path of volume to be unmounted>
*/

RDKSSA_API( rdkssaUnmount );

/**
* rdkssaKeyring Provider
*
* The Keyring Provider provides an interface to securely maintain keys at runtime,
* allowing storage, retrieval and destruction of supported key objects
*
*/

/**
 * rdkssaGetKeyringKey	-	Retrieve the data payload associated with a key serial number if permissions allow
 *
 * blobPtr: ptr to
 * struct {
 *		rdkssa_handle_t keyHandle;		(opaque) Value returned from a call to rdkssaPutKeyringKey
 *		rdkssaDataBufPtr_t keyBytes;	Ppinter to buffer for returned key payload
 *	 }
 * attributes[]=
 * +NAME=<name of key as assigned when rdkssaPutKeyringKey called>
 *
 * The key payload is returned in caller's buffer; the buffer size MUST be large enough for the key payload,
 * and is assumed to be known by the caller
 */
 
RDKSSA_API(rdkssaGetKeyringKey);

/**
 * rdkssaPutKeyringKey	-	Create a new key or update existing 
 *
 * blobPtr: ptr to
 * struct {
 *		rdkssa_handle_t keyHandle;		(opaque) Value to be returned 
 *		rdkssaDataBufPtr_t keyBytes;	Ppinter to buffer containing key payload
 *	 }
 * attributes[]=
 * +NAME=<name of key to assign> ( [A-Za-z0-9_] )
 * PERM=<permissions string> ( format TBD, default = "ALL" if missing )
 *
 * The key payload is supplied in caller's buffer
 */

RDKSSA_API(rdkssaPutKeyringKey);

/**
 * rdkssaDeleteKeyFromKeyring	-	Delete/destroy key from keyring 
 *
 * blobPtr: keyHandle
 * attributes[]=
 * +NAME=<name of key as assiged> ( [A-Za-z0-9_] )
 */

RDKSSA_API(rdkssaDeleteKeyFromKeyring);




/**
 * END CURRENT API DEFINITIONS 
 */

/**
 * Add other API calls and their documentation ABOVE this.  Here's the declaration for use with template code
 */
RDKSSA_API(rdkssaHandleAPITemplate);

/* Logging */
#ifdef RDKSSA_LOG_FILE

#define RDKSSA_DEBUG_LOG_FILE_NAME "/rdklogs/logs/rdkssa.txt"
void _rdkssa_debug_log( const char* fmt, ...);

#define LOG_ERROR(...)                         _rdkssa_debug_log(__VA_ARGS__)
#define LOG_INFO(...)                          _rdkssa_debug_log(__VA_ARGS__)
#define LOG_DEBUG(...)                         _rdkssa_debug_log(__VA_ARGS__)

#else

#define LOG_ERROR(format, ...)                     fprintf(stderr, format, __VA_ARGS__)
#define LOG_INFO(format,  ...)                     fprintf(stderr, format, __VA_ARGS__)
#define LOG_DEBUG(format, ...)                     fprintf(stderr, format, __VA_ARGS__)

#endif

#ifdef USE_COLORS
#define COL_RED "\033[0;31m"
#define COL_GRN "\033[0;32m"
#define COL_YEL "\033[0;33m"
#define COL_BLU "\033[0;34m"
#define COL_MAG "\033[0;35m"
#define COL_CYA "\033[0;36m"
#define COL_DEF "\033[0m"
#define PREFIX(format)                             ("%12s:%3d:%16s - " format)
#define RDKSSA_CRITICAL_ERROR(format, ...)         LOG_ERROR(PREFIX(COL_RED"CRITICAL ERR:"COL_DEF format), strrchr(__FILE__,'/')+1,__LINE__, __func__, ##__VA_ARGS__)
#else
// do not use colors on targets
#define PREFIX(format)                             ("%d\t: %s - " format)
#define RDKSSA_CRITICAL_ERROR(format, ...)         LOG_ERROR(PREFIX(format), __LINE__, __func__, ##__VA_ARGS__)
#endif

#if defined(USE_COLORS) && defined(RDKSSA_ERROR_ENABLED)
#define RDKSSA_LOG_ERROR(format, ...)              LOG_ERROR(PREFIX(COL_RED"ERR:"COL_DEF format), strrchr(__FILE__,'/')+1,__LINE__, __func__, ##__VA_ARGS__)
#elif defined(RDKSSA_ERROR_ENABLED)
#define RDKSSA_LOG_ERROR(format, ...)              LOG_ERROR(PREFIX(format), __LINE__, __func__, ##__VA_ARGS__)
#else
#define RDKSSA_LOG_ERROR(format,  ...)
#endif



#if defined(USE_COLORS) && defined(RDKSSA_INFO_ENABLED)
#define RDKSSA_LOG_INFO(format,  ...)              LOG_INFO(PREFIX(COL_YEL"INF:"COL_DEF format),  strrchr(__FILE__,'/')+1,__LINE__, __func__, ##__VA_ARGS__)
#elif defined(RDKSSA_INFO_ENABLED)
#define RDKSSA_LOG_INFO(format,  ...)              LOG_INFO(PREFIX(format),  __LINE__, __func__, ##__VA_ARGS__)
#else
#define RDKSSA_LOG_INFO(format,  ...)
#endif

#if defined(USE_COLORS) && defined(RDKSSA_DEBUG_ENABLED)
#define RDKSSA_LOG_DEBUG(format, ...)              LOG_DEBUG(PREFIX(COL_BLU"DBG:"COL_DEF format), strrchr(__FILE__,'/')+1,__LINE__, __FUNCTION__, ##__VA_ARGS__)
#elif defined(RDKSSA_DEBUG_ENABLED)
#define RDKSSA_LOG_DEBUG(format,  ...)             LOG_DEBUG(PREFIX(format),  __LINE__, __func__, ##__VA_ARGS__)
#else
#define RDKSSA_LOG_DEBUG(format, ...)
#endif /* RDKSSA_DEBUG_ENABLED */


/**
 * public utility functions
 */
void rdkssa_memfree(rdkssa_blobptr_t *mem, size_t sz);
void rdkssa_memwipe( volatile void *mem, size_t sz );
int rdkssaExecv( char *exargv[] );
int rdkssaExecvIO( char *exargv[], rdkssa_blobptr_t, void(*callback)(rdkssa_blobptr_t) );
void rdkssaCleanupVector( char ***v );
const char *rdkssaAttrCheck( const char *valueStr );

/**
 ** 
 ** Common definitions for all provider components and SSA clients
 **
 **/

/*Magic numbers and strings*/
#define ATTRIBUTE_NULL                             NULL
#define MAX_SUPPORTED_ATTRIBUTES                   (32)
#define MAX_ATTRIBUTE_BUFF_LENGTH                  (32767) /* for API's taking caller bufPtr pointer to pointer to buffer */
#define MIN_ATTRIBUTE_NAME_LENGTH                  (2)
#define MAX_ATTRIBUTE_NAME_LENGTH                  (2048)
#define MAX_GENERIC_ATRIB_LENGTH                   (32)
#define MAX_ATTRIBUTE_VALUE_LENGTH                 (2048)
#define COMMAND_SEPARATOR_GAP                      " "
#define VALUE_DELIM                                '='
#define ATTRIB_DELIM                               ','
#define COMMAND_HEAD                               '{'
#define COMMAND_TAIL                               '}'

/**** PROVIDERS ****/
#define PROVIDER_CA                                 "CA"
#define PROVIDER_IDENT                              "IDENT"
#define PROVIDER_STOR                               "STOR"

/**** SUPPORTED ATTRIBUTES FOR THE RDK SSA*****/
/*CLI Attribute string values */
#define ATTRIBUTE_CA_CREATE                          "CREATE"
#define ATTRIBUTE_CA_UPDATE                          "UPDATE"
#define ATTRIBUTE_CA_CHECK                           "CHECK"

/*IDENTITY ATRIBUTE to fetch Platform Hal parameters */
#define ATTRIBUTE_BASEMACADDRESS                    "BASEMACADDRESS"
#define ATTRIBUTE_SERIALNUMBER                      "SERIALNUMBER"

/*STORAGE ATRIBUTES*/
#define ATTRIBUTE_STOR_STORAGE                      "STORAGE"
#define ATTRIBUTE_SRC                               "SRC"
#define ATTRIBUTE_DST                               "DST"
#define ATTRIBUTE_DEL                               "DEL" // not implemented yet
#define ATTRIBUTE_MEM                               "MEM" // not implemented yet

#endif
