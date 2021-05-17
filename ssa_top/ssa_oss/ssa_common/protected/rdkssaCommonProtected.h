/*
 * Copyright 2020 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* Used by all providers, so in a common protected header */

#ifndef __rdkssa_common_protected_inc__
#define __rdkssa_common_protected_inc__

#include "rdkssa.h"


/*Function pointer the attribute functions*/
typedef rdkssaStatus_t (*AttributeHandlerFuncPtr)(rdkssa_blobptr_t ,const char *);

//structure of fuction pointer
typedef struct AttributeHandlerStruct 
{
    const char *attributeNameStr;
    AttributeHandlerFuncPtr attributeOperation; 
} AttributeHandlerStruct, *AttributeHandlerStructPtr;

/**
 * helper function to look up an attribute name and call the matching function
 */
rdkssaStatus_t attributeHandlerHelper(rdkssa_blobptr_t apiBlobPtr, const char *attributeName, const AttributeHandlerStruct attributeTable[]);
rdkssaStatus_t rdkssaHandleAPIHelper(rdkssa_blobptr_t  apiBlobPtr, const char * const attributes[], const AttributeHandlerStruct attributeTable[]);

/**
 * Safe exec, instead of system()
 */
int rdkssaExecv( char *exargv[] );

/**
 * for exec with io redirection [for inward popen() can be used]
 * define a pipe, but for the SSA parent code use fd's for pipe writes, 
 * not stdout, so there's more flexibility in the functions that need io
 *
 * the exec with IO takes parameters to send to a callback which a provider 
 * specifies. The provider callback uses the fd's for r/w as needed
 *
 */
typedef rdkssaStatus_t (*rdkssaIOCallback)(int fd, rdkssa_blobptr_t callerBlob );
// safe exec with IO redirection (this may need synchronization!)
rdkssaStatus_t rdkssaExecvPipeOutput( const char *exargv[], rdkssa_blobptr_t callerBlob, rdkssaIOCallback callback );


 
#endif //__rdkssa_common_protected_inc__
