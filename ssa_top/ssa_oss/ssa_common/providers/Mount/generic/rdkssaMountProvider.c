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

#include "rdkssa.h"
#include "rdkssaCommonProtected.h"
#include "rdkssaMountProvider.h"
#include "rdkssaMountProviderPrivate.h"
#include "safec_lib.h"
/**
 * Forward declarations for individual handlers for each attrib
 */

static inline rdkssaStatus_t rdkssaMountMountpoint(rdkssa_blobptr_t, const char *);
static inline rdkssaStatus_t rdkssaMountPath(rdkssa_blobptr_t, const char *);
static rdkssaStatus_t rdkssaMountKey(rdkssa_blobptr_t, const char *);
static inline rdkssaStatus_t rdkssaMountPartition(rdkssa_blobptr_t, const char *);

/**
 * Declare stack-based structure that collects the input parameters
 * If a lot of similar declarations/definitions are needed, put them into ./private/rdkssaMountProviderPrivate.h
 */
typedef struct {
	char mountPoint[MAX_ATTRIBUTE_VALUE_LENGTH];
	char mountPath[MAX_ATTRIBUTE_VALUE_LENGTH];
	/* If reading file */
	size_t  mountKeyActualSize;
	uint8_t mountKey[MAX_ATTRIBUTE_VALUE_LENGTH];
	/* If using a key handle, defined by contract with the SymKey provider or proprietary */
	rdkssa_handle_t keyHandle;
} mount_param_t, *mount_param_ptr;


// MOUNTPOINT = name the mountpoint.
static rdkssaStatus_t rdkssaMountMountpoint(rdkssa_blobptr_t blobPtr, const char *valueStr) {
    RDKSSA_LOG_DEBUG( "    rdkssaMountMountpoint\n" );
	mount_param_ptr pp = (mount_param_ptr)blobPtr;
	errno_t rc = -1;

	if ( pp == NULL ) { return rdkssaBadPointer;}
	if ( rdkssaAttrCheck( valueStr ) == NULL ) { return rdkssaValidityError; } 
	rc = strcpy_s( pp->mountPoint, sizeof(pp->mountPoint) , valueStr );
	ERR_CHK(rc);
	return rdkssaOK;
}

// PATH = Name the path to the new dir
static rdkssaStatus_t rdkssaMountPath(rdkssa_blobptr_t blobPtr, const char *valueStr) {
    RDKSSA_LOG_DEBUG( "    rdkssaMountPath\n" );
	mount_param_ptr pp = (mount_param_ptr)blobPtr;
	errno_t rc = -1;

	if ( pp == NULL ) { return rdkssaBadPointer;}
	if ( rdkssaAttrCheck( valueStr ) == NULL ) { return rdkssaValidityError; } 
	rc = strcpy_s( pp->mountPath, sizeof(pp->mountPath) , valueStr );
	ERR_CHK(rc);
	return rdkssaOK;	
}

//  KEY = fetch key
static rdkssaStatus_t rdkssaMountKey(rdkssa_blobptr_t blobPtr, const char *valueStr) {
    RDKSSA_LOG_DEBUG( "    rdkssaMountKey\n" );
	mount_param_ptr pp = (mount_param_ptr)blobPtr;

	if ( pp == NULL ) { 
		RDKSSA_LOG_ERROR( "rdkssaMount KEY NULL ptr\n" );
		return rdkssaBadPointer;
	}
	if ( rdkssaAttrCheck( valueStr ) == NULL ) { 
		RDKSSA_LOG_ERROR( "rdkssaMount KEY bad attribute\n" );
		return rdkssaValidityError; 
	} 

	FILE *keyfileh;
	
	if ( strncmp( valueStr, "HANDLE", strlen("HANDLE") ) == 0 ) {
		/* this OSS provider doesn't yes support handling handle-based keys */
		RDKSSA_LOG_ERROR( "rdkssaMount KEY=HANDLE not implemented\n" );
		return rdkssaNYIError;
	}
	
	/**
	 * OSS version of provider assumes KEY= is a file name if not a HANDLE
	 * Proprietary versions may treat the KEY= parameter differently
	 * including any adding other key generation/derivation logic in 
	 * this function.
	 *
	 * The exit condition is that if KEY= is specified, there is a key returned
	 * in the mount parameters structure with non-zero length
	 *
	 * Proprietary versions may defer key management to the main API logic
	 */
	if ( strncmp( valueStr, "STDIN", strlen("STDIN") ) == 0 ) {
		keyfileh = stdin;
	} else {
		keyfileh = fopen( valueStr, "r" );
		if ( keyfileh == NULL ) {
			RDKSSA_LOG_ERROR( "rdkssaMount KEY missing file\n" );
			return rdkssaFileError; 
		}
	}	   
	
	/* read the key bytes, up to max length, no validity check on key length except empty */
	/* This version of OSS provider does not use the storage provider, just the file system */
	if ( !( pp->mountKeyActualSize = fread( pp->mountKey, 1, MAX_ATTRIBUTE_VALUE_LENGTH, keyfileh ) ) ) {
		if ( keyfileh != stdin ) { 
			fclose( keyfileh ); 
		}
		RDKSSA_LOG_ERROR( "rdkssaMount KEY empty file\n" );
		return rdkssaFileError;
	}
	if ( keyfileh != stdin ) { fclose( keyfileh ); }	
	return rdkssaOK;
	
 }

static rdkssaStatus_t rdkssaMountPartition(rdkssa_blobptr_t blobPtr, const char *valueStr) {
    RDKSSA_LOG_ERROR( "rdkssaMountPartition not implemented\n" );
    return rdkssaNYIError;
}


/**
 * mountWriteKeyCallback
 *
 * This callback function is called by rdkssaExecvPipeOutput used to
 * pipe to a child function to avoid exposure of key material to user
 * file system. Function is in rdkssaProvierHelpers.
 */
 
static rdkssaStatus_t mountWriteKeyCallback( int fd, rdkssa_blobptr_t callerBlob)
{
		mount_param_ptr pp = (mount_param_ptr)callerBlob;
		
		/* shouldn't be NULL but we are defensive*/
		if ( pp == NULL ) {
			RDKSSA_LOG_ERROR( "mountWriteKeyCallback NULL ptr\n" );
			return rdkssaBadPointer;
		}
		/* We know there is a key because the parameters were checked for a 0-length key */
		ssize_t rc = write( fd, pp->mountKey, pp->mountKeyActualSize );
		if ( rc != pp->mountKeyActualSize ) {
			RDKSSA_LOG_ERROR( "mountWriteKeyCallback write error\n" );
			return rdkssaFileError;			
		}
		return rdkssaOK;
}

/**
 * API Entry points for Mount Provider supported API's
 */
RDKSSA_API( rdkssaMount )
{
	mount_param_t mountParameters;
	rdkssaStatus_t iRetAtr;
	
    /**
     * Function pointers to specific handlers as/if needed for each identified attribute
     */
    static const AttributeHandlerStruct mountHandlers[]= {
        {"MOUNTPOINT", rdkssaMountMountpoint },
        {"PATH", rdkssaMountPath },
        {"KEY", rdkssaMountKey },
        {"PARTITION", rdkssaMountPartition },	// nyi.
		{ NULL, NULL }
    };	
	
	/* init the handle field */
	if ( apiBlobPtr == NULL ) { 
		mountParameters.keyHandle = NULL;
	} else {
		mountParameters.keyHandle = *( rdkssa_handle_t * )apiBlobPtr;
	}

	/* make empty strings (don't! use memset or initializers to do things like this */
	mountParameters.mountPoint[0] = '\0';
	mountParameters.mountPath[0] = '\0';
	mountParameters.mountKeyActualSize = 0; /* 0 length means there is no key! */
	/* Perform the operations defined by the attribute vector */
	iRetAtr = rdkssaHandleAPIHelper((void*)&mountParameters, apiAttributes, mountHandlers );
	if ( iRetAtr != rdkssaOK ) {
		RDKSSA_LOG_ERROR( "rdkssaMount error in handler\n" );
		return iRetAtr;
	}
	/* All input parameters have been processed, Note: HANDLE and PARTITION are unsupported for now */
	if ( mountParameters.mountPoint[0] == '\0' || mountParameters.mountPath[0] == '\0' ) { 
		RDKSSA_LOG_ERROR( "rdkssaMount missing required parameter(s)\n" );
		return rdkssaMissingAttribute;
	}
	/* See if the OSS version has implemented ANY key management */
	if ( mountParameters.mountKeyActualSize == 0 ) {
		RDKSSA_LOG_ERROR( "rdkssaMount key management not implemented\n" );	
		/* Proprietary key management is required for this version of Mount Provider*/
		return rdkssaNYIError;
	}
	/* All set: mountpoint, path, and key all exist. call exec with callback */
	const char *mountArgv[ 4 ] = { "/usr/bin/ecfsMount" };
	mountArgv[1] = mountParameters.mountPoint;
	mountArgv[2] = mountParameters.mountPath;
	iRetAtr = rdkssaExecvPipeOutput( mountArgv, (rdkssa_blobptr_t)&mountParameters,  mountWriteKeyCallback );
	if ( iRetAtr != rdkssaOK ) {
		RDKSSA_LOG_ERROR( "rdkssaMount exec failed\n" );	
	}
	return iRetAtr;
}
RDKSSA_API( rdkssaUnmount )
{
	return rdkssaNYIError;
}



/**
 * See template for an example
 */
#if defined( UNIT_TESTS ) || defined( PLTFORM_TEST )
#include "./unit_tests.h"
#endif // needed for both UNIT_TESTS and PLTFORM_TEST

#ifdef UNIT_TESTS
// STUB rdkssaHandleAPIHelper - do nothing
rdkssaStatus_t rdkssaHandleAPIHelper( rdkssa_blobptr_t apiBlobPtr, const char *const attributes[], const AttributeHandlerStruct attributeTable[]) {
    RDKSSA_LOG_UT("rdkssaHandleAPIHelper STUBBED OUT\n" );
    return rdkssaOK;
}
int rdkssaExecvPipeOutput(const char *argv[],rdkssa_blobptr_t callerBlob, rdkssaIOCallback callback ) {
    RDKSSA_LOG_DEBUG("rdkssaExecvPipeOutput\n" );
    return rdkssaOK;
}
// ut stubs -- these are shortened versions of real functions from helpers
void rdkssa_memwipe( volatile void *mem, size_t sz ) {
    memset( (void *)mem, 0, sz );
}
void rdkssa_memfree(void **mem, size_t sz) {
    if(*mem) { free((void *)*mem); *mem=NULL;}
}
//check for bad characters
const char *rdkssaAttrCheck( const char *valueStr ) {
    const char *retStr = valueStr;
    if ( strpbrk(valueStr, RDKSSA_BADCHARS ) != NULL )  retStr = NULL;
    return retStr;
}
int utmain_mount(int argc, char *argv[]);
int main(int argc, char *argv[] ) {
    return utmain_mount( argc, argv );
}
int utmain_mount(int argc, char *argv[] )
{
    RDKSSA_LOG_UT("=== Unit tests MOUNT begin ===\n");
    RDKSSA_LOG_UT("=== Unit tests FAIL ===\n");	
	return -1;
    RDKSSA_LOG_UT("=== Unit tests STOR SUCCESS ===\n");
    return 0;
}
#endif

#ifdef PLTFORM_TEST
int pltfrmmain(int argc, char *argv[] ) {
    RDKSSA_LOG_UT( "PLTFORM TEST\n" );
    const char * const attrtbl[] = {
        "MOUNTPOINT=/nvram/rdkssa",
        "PATH=/nvram/secure",
        "KEY=/etc/ecfs-mount-sample-dummy-key",
	 NULL };
    UTST( rdkssaMount( NULL, attrtbl ) == rdkssaOK );
    RDKSSA_LOG_UT( "PLTFORM TEST SUCCESS\n" );
    return 0;
}

int main(int argc, char *argv[] ) {
    return pltfrmmain( argc, argv );
}
#endif

