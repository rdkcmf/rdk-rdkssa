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

#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <stdarg.h>

#include "rdkssa.h"
#include "rdkssaCommonProtected.h"
#include "rdkssaCommonPrivate.h"

#define NSPR( s ) ((s)?(s):"(null)")  // null string protect

#ifdef RDKSSA_LOG_FILE
void _rdkssa_debug_log( const char* fmt, ...) {
    FILE* debug_file = NULL;
    va_list va;

    va_start(va,fmt);
    debug_file = fopen(RDKSSA_DEBUG_LOG_FILE_NAME, "a" );
    if (debug_file != NULL) {
        vfprintf(debug_file,fmt,va);
        fflush(debug_file);
        fclose(debug_file);
    }
    else{
       fprintf(stderr,"ERROR!!! rdkssa debug log file not set \n");
    }

    va_end(va);
}

#endif

// rdkssa_memwipe - clear memory
void rdkssa_memwipe( volatile void *mem, size_t sz ) {
    if( mem == NULL) {
        RDKSSA_LOG_ERROR("NULL ptr passed \n");
        return;
    }
    memset( (void *)mem, 0, sz );
    return;
}

// rdkssa_memfree - wipe memory before freeing
void rdkssa_memfree(void **mem, size_t sz) {
    if( mem == NULL ) { 
        RDKSSA_LOG_ERROR("NULL ptr passed \n"); 
        return;
    }
    if(*mem) 
    {
        rdkssa_memwipe( *mem, sz );
        free((void *)*mem);
    }
    *mem = NULL;
    return;
}

/**
 * rdkssaCleanupVector        -       free everything of an allocated array of pointers to allocation memory
 */
void rdkssaCleanupVector( char ***v )
{
    if ( v == NULL || *v == NULL ) return; // nothing to do
    char ***vctr = (char ***)v;
    int i;
    for( i=0; i<MAX_SUPPORTED_ATTRIBUTES; i++ ) {
        if ( (*vctr)[i] !=NULL ) { free( (*vctr)[i] ); (*vctr)[i] = NULL;}
    }
    free( *vctr );
    *vctr = NULL;
}


// safe exec calls
int rdkssaExecv( char *exargv[] ) {
    if( exargv == NULL || exargv[0] == NULL) {
        RDKSSA_LOG_ERROR("NULL ptr passed\n");
        return 1;
    }
    extern char** environ; // existing env vars
    int ret;
    int pid = fork ();
    if (pid == 0) {
        // child process -- execute from argv
        ret = execve( exargv[0], exargv, environ );
        RDKSSA_LOG_ERROR( "  execve for %s returned %d\n", NSPR(exargv[0]), ret );
        exit( -1 );
    }
    int status;
	
    ret = waitpid (pid, &status, 0);
    if (ret == -1) {
        RDKSSA_LOG_ERROR( "    execv wait error %d\n", ret );
        return ret;
    } else if (ret != pid) {
        RDKSSA_LOG_ERROR( "    execv child process NOT done: %d, status %d\n", ret, status );
        return 1; // error
    }
    if (WIFEXITED(status)) {
        ret = WEXITSTATUS(status);
    }
    return ret;
}

// safe exec with IO redirection (this may need synchronization!)
// should be in protected directory. Move later.
rdkssaStatus_t rdkssaExecvPipeOutput(const char *exargv[], rdkssa_blobptr_t callerBlob, rdkssaIOCallback callback ) {
	int ret;
	extern char** environ; // existing env vars

	if( exargv == NULL || exargv[0] == NULL || callback == NULL ) {
		RDKSSA_LOG_ERROR("NULL ptr passed\n");
		return rdkssaBadPointer;
	}

	int fds[2];                      // an array that will hold two file descriptors
	if ( pipe(fds) == -1 ) {    // populates fds with two file descriptors
		RDKSSA_LOG_ERROR( "  pipe failed\n" );
		return rdkssaGeneralFailure;
	}

	pid_t pid = fork();              // create child process that is a clone of the parent
	if ( pid == -1 ) {
		RDKSSA_LOG_ERROR("  fork error\n");
		return rdkssaGeneralFailure;
	}

	if (pid == 0) {
		// child process -- execute from argv
		dup2(fds[0],0);    
		close(fds[1]);		// is that right?
		ret = execve( exargv[0],(char* const*) exargv, environ );  // reads from parent stdout
		RDKSSA_LOG_ERROR( "  execve for %s returned %d\n", NSPR(exargv[0]), ret );
		exit( ret );
	}
	// parent
	close( fds[0] );						// for redirected input use popen
	callback(fds[1],callerBlob);			// callback function writes stdout

	int status;
	ret = waitpid (pid, &status, 0);

	if (ret == -1) {
		RDKSSA_LOG_ERROR( "    execv wait error %d\n", ret );
		return ret;
	} else if (ret != pid) {
		RDKSSA_LOG_ERROR( "    execv child process NOT done: %d, status %d\n", ret, status );
		return 1; // error
	}
	if (WIFEXITED(status)) {
		ret = WEXITSTATUS(status);
	}
	return ret;
}

// verfify that attribute string is valid (size, contents)
// return string if valid, return NULL if not
const char *rdkssaAttrCheck( const char *valueStr ) {
    const char *retStr = valueStr;
    if ( valueStr == NULL || *valueStr == '\0' ) {
        RDKSSA_LOG_ERROR("  null attribute\n");
        return NULL;
    }
    if ( strnlen(valueStr,MAX_ATTRIBUTE_VALUE_LENGTH+1) > MAX_ATTRIBUTE_VALUE_LENGTH ) {
        RDKSSA_LOG_ERROR("  attribute too long\n");
        return NULL;
    }
    // if any bad characters are found, return NULL
    if ( strpbrk(valueStr, RDKSSA_BADCHARS ) != NULL ) {
        RDKSSA_LOG_ERROR("Bad Character found in attribute [%s]\n", valueStr);
        retStr = NULL;
    }
    // should we check for whitespace too?
    return retStr;
}
/**
 * 
 * my_attributeHandler
 *
 * All Providers takes a string vector, vector null-terminated, and process the requested  attribute(s)
 * Different providers may consume input attributes in a provider-specific format, such as a JSON structure
 * Different providers may produce output data in a provider-specific format, such as a binary struct or string
 * Each provider documents and publishes the expected input and output formats.
 *
 * apiBlobPtr       Pointer to a variable to recieve the pointer to memory allocated for the attribute result
                Memory will be allocated by the function to hold the attribute value
                *** Caller must call free() to free the allocated memory!
  
 * attribute    Null terminated string, specifying the attibute(s) to be handled
 *              There is complete flexibility in how the API, and attribute handle the input string,
 *
 * Return:      If successfu, *apiBlobPtr will contain an API specific output, as defined by the provider.

 */
rdkssaStatus_t attributeHandlerHelper(rdkssa_blobptr_t apiBlobPtr, const char *attributeName, const AttributeHandlerStruct attributeTable[])
{
    rdkssaStatus_t iRet=rdkssaGeneralFailure;
    size_t inputAtrbNameLength;
    int iAttributIterator = 0;

    if ( attributeName == NULL || attributeTable == NULL ) 
    {
        RDKSSA_LOG_ERROR("NULL passed to attributeHandlerHelper: (%p, %p)\n", attributeName, attributeTable);
        return rdkssaBadPointer;
    }
    /* GW: migrate str* calls to use the SafeC library, so this would be: */
    /* strnlen_s(attributeString, MAX_ATTRIBUTE_NAME_LENGTH) */
    inputAtrbNameLength = strnlen( attributeName, MAX_ATTRIBUTE_NAME_LENGTH+1 );
    if(inputAtrbNameLength > MAX_ATTRIBUTE_NAME_LENGTH || inputAtrbNameLength < MIN_ATTRIBUTE_NAME_LENGTH)
    {
        RDKSSA_LOG_DEBUG( "attributeHandlerHelper attributeName=[%c%c%c%c...]\n", 
                   attributeName[0], attributeName[1], attributeName[2], attributeName[3] );
        RDKSSA_LOG_ERROR("unexpected attribute length %lu\n",(unsigned long)inputAtrbNameLength);
        return rdkssaGeneralFailure;
    }
    RDKSSA_LOG_DEBUG( "attributeHandlerHelper attributeName=[%s]\n", attributeName);

    /**
     * Look for an "=" - if found the operation handler is expected to expect the remainder of the string.
     * e.g. "MY_ATTRIBUTE=123456\0" will call the handler with "123456\0"  -- NOTE: THE ATTRIBUTE NAME WILL NOT BE PASSED
     * but instead the value is passed.  You can always structure the value to contain the name if necessary, even like
     " "MY_ATTRIBUTE=MY_ATTRIBUTE:657838234" and parse the value however you want in the handler.  Complete flexibility.
     */
    char copyName[MAX_ATTRIBUTE_NAME_LENGTH];
    char *eq = strchr(attributeName,'=');
    const char *attrPtr = attributeName;
    
    if ( eq != NULL ) 
    { 
        int copyLen = eq-attributeName;
        if ( copyLen == 0 ) {
            RDKSSA_LOG_ERROR("syntax error in attribute (leading =)\n");
            return rdkssaSyntaxError;
        }
        /* checks above promise it doesn't exceed max len */
        memcpy( copyName, attributeName, copyLen );
        copyName[copyLen] = '\0';
        attrPtr = copyName;
    } 
    RDKSSA_LOG_DEBUG("attributeHandlerHelper attrPtr[%s], eq[%s]\n", (attrPtr?attrPtr:"NULL"), (eq?eq:"NULL"));
    /* After that bit, attrPtr points to either the original attrb strng or the prefix to the "=" */
    /* Now, loop over the attribute names in the provided table */
    for(iAttributIterator = 0;
            iAttributIterator<MAX_SUPPORTED_ATTRIBUTES && 
            attributeTable[iAttributIterator].attributeNameStr != NULL;
            iAttributIterator++)
    {
        if(attributeTable[iAttributIterator].attributeOperation == NULL)
        {
            continue;  /* nothing to call.  Reserved for further use */
        }

        // GW: TODO: Move to strcmp_s 
        // GW: TODO: Use syntax "xxxx=yyyy" and strchr etc to get name from string
        //if(!strncmp(my_supportedAttributes[iAttributIterator].attributeNameStr, 
        //          attributeString, inputAtrbNameLength) )
        if(strncmp(attributeTable[iAttributIterator].attributeNameStr,
                   attrPtr, 
                   MAX_ATTRIBUTE_NAME_LENGTH ) != 0 )
        {
            continue;   
        }
        
        // it matches this one, execute the function with the rest of the attribute
        if ( eq != NULL ) 
        {
            attrPtr = ++eq; /* now past the "=" */
        }
        RDKSSA_LOG_DEBUG( "Calling the func for %s with [%s] apiBlobPtr(%p) attrib handler ptr(%p)\n", attributeTable[iAttributIterator].attributeNameStr,
                                                   attrPtr, apiBlobPtr, attributeTable[iAttributIterator].attributeOperation );

        iRet = attributeTable[iAttributIterator].attributeOperation(apiBlobPtr, attrPtr);
        if(iRet != rdkssaOK)
        {
            RDKSSA_LOG_ERROR("attribute handler for %s failed (%d)\n", attributeName, iRet);
        }
//        RDKSSA_LOG_DEBUG("Ret value [%d]\n", iRet);
        return iRet;
    }
    RDKSSA_LOG_ERROR("Attribute not available [%s]\n", attributeName);
    return rdkssaAttributeNotFound;
}

/**
 * EXTERNAL API. This is all the caller sees (other than published constants etc
 *
 * Add this to "rdkssa.h" function declarations
 */
rdkssaStatus_t rdkssaHandleAPIHelper( rdkssa_blobptr_t apiBlobPtr, const char * const attributes[], const AttributeHandlerStruct attributeTable[])
{
    rdkssaStatus_t iRetAtr = rdkssaAttributeNotFound;

    if ( attributeTable == NULL || attributes == NULL ) {
        RDKSSA_LOG_ERROR("NULL param passed (, %p, %p)\n", attributes, attributeTable);
        return rdkssaBadPointer;
    }

    /**
    *  Loop over multiple attributes and call the lookup and execute handler function.
    **/
    int i;
    for( i=0; i < MAX_SUPPORTED_ATTRIBUTES && attributes[i] != NULL; i++ ) {
        iRetAtr = attributeHandlerHelper(apiBlobPtr, attributes[i], attributeTable);
        if ( iRetAtr != rdkssaOK ) { break; }
    }
    return iRetAtr;
}

/**
 * See template for an example
 */
#if defined( UNIT_TESTS )
#include "unit_tests.h"
#define UT_ATTRIB_STR "UT_ATTRIB_STR"
#define UT_ATTRIB_VAL "UT_ATTRIB_VAL"
#endif

#ifdef UNIT_TESTS
int utmain_helpers(int argc, char *argv[] );

int main(int argc, char *argv[]  ) {
    return utmain_helpers( argc, argv );
}

// unit test subroutines for test sets 
static void ut_rdkssaCleanupVector( void );
static void ut_rdkssaHelpersMem( void );
static void ut_rdkssaExecv( void );
static void ut_rdkssaAttrCheck( void );
static void ut_attributeHandlerHelper( void );
static void ut_rdkssaHandleAPIHelper( void );
static void ut_rdkssaHandleAPIHelperTemplate( void );

int utmain_helpers(int argc, char *argv[]  )
{

    RDKSSA_LOG_UT("=== Unit tests HELPERS begin ===\n");

    ut_rdkssaCleanupVector( );
    ut_rdkssaHelpersMem( );
    ut_rdkssaExecv( );
    ut_rdkssaAttrCheck( );
    ut_attributeHandlerHelper( );
    ut_rdkssaHandleAPIHelper( );
    ut_rdkssaHandleAPIHelperTemplate( );

    RDKSSA_LOG_UT("=== Unit tests HELPERS SUCCESS ===\n");
    return 0;
}

// ut function to setup arg vector
char **utNewVector( const char *arg0, const char *arg1, const char *arg2, 
                    const char *arg3, const char *arg4, const char *arg5)
{
    char **newVector = calloc( (MAX_SUPPORTED_ATTRIBUTES+1), sizeof(char *) );
    if ( newVector == NULL ) return NULL;

    if ( arg0 != NULL ) newVector[0] = strdup( arg0 );
    if ( arg1 != NULL ) newVector[1] = strdup( arg1 );
    if ( arg2 != NULL ) newVector[2] = strdup( arg2 );
    if ( arg3 != NULL ) newVector[3] = strdup( arg3 );
    if ( arg4 != NULL ) newVector[4] = strdup( arg4 );
    if ( arg5 != NULL ) newVector[5] = strdup( arg5 );

    return newVector;
}

static void ut_rdkssaCleanupVector( void ) {
    RDKSSA_LOG_UT("rdkssaCleanupVector\n");
    char **cmdvctr1 = utNewVector( "app", NULL, NULL, NULL, NULL, NULL );
    UTST( cmdvctr1 != NULL );
    rdkssaCleanupVector( &cmdvctr1 ); // vector is all null
    UTST( cmdvctr1 == NULL );

    cmdvctr1 = utNewVector( "app", NULL, NULL, NULL, NULL, NULL );
    UTST( cmdvctr1 != NULL );
    UT_STRCMP( cmdvctr1[0], "app", MAX_ATTRIBUTE_VALUE_LENGTH );
    UTST( cmdvctr1[1] == NULL );
    rdkssaCleanupVector( &cmdvctr1 ); // free memory
    UTST( cmdvctr1 == NULL );
    rdkssaCleanupVector( &cmdvctr1 ); // test null vector too
    UTST( cmdvctr1 == NULL );
    cmdvctr1 = utNewVector( "VAR1=VAL1","VAR2=VAL2","VAR3=VAL3", NULL, NULL, NULL );
    UTST( cmdvctr1 );
    // check that vector was setup correctly
    UT_STRCMP( cmdvctr1[0], "VAR1=VAL1", MAX_ATTRIBUTE_VALUE_LENGTH );
    UT_STRCMP( cmdvctr1[1], "VAR2=VAL2", MAX_ATTRIBUTE_VALUE_LENGTH );
    UT_STRCMP( cmdvctr1[2], "VAR3=VAL3", MAX_ATTRIBUTE_VALUE_LENGTH );
    UTST( cmdvctr1[3] == NULL );
    rdkssaCleanupVector( &cmdvctr1 ); // free memory
    // error cases
    RDKSSA_LOG_UT("    expect 2 error message\n");
    rdkssaCleanupVector( NULL ); // should not crash
    rdkssaCleanupVector( &cmdvctr1 ); // points to null
    RDKSSA_LOG_UT("rdkssaCleanupVector SUCCESS\n");
}

// memory and system functions
static void ut_rdkssaHelpersMem( void ) {
    RDKSSA_LOG_UT("  rdkssaHelpersMem\n");

    RDKSSA_LOG_UT("    rdkssa_memwipe\n");
    char memtmp[] = "fdskjlfjlkfjslkdsjflksdfjl";
    char zero[100] = { 0 };
    UTST( memcmp( memtmp, zero, sizeof( memtmp ) ) );
    rdkssa_memwipe( memtmp, sizeof(memtmp) );
    UTST0( memcmp( memtmp, zero, sizeof( memtmp ) ) );

    RDKSSA_LOG_UT("    rdkssa_memfree\n");
    char *memtmp2 = strdup( "temp" );
    rdkssa_memfree( (void *)&memtmp2, strnlen( memtmp2, 1000 ) );
    UTST0( memtmp2 );


    RDKSSA_LOG_UT("  rdkssaHelpersMem SUCCESS\n");
}


static void ut_rdkssaExecv( void ) {
    RDKSSA_LOG_UT("  rdkssaExecv\n");

    char *exargv[] = { "/bin/echo", "one", "two", "three", NULL };
    UTST( rdkssaExecv( exargv ) == 0 );

    // create a test script
#define UTSCR "/tmp/utech.tmp"
    UTST0( system( "echo \"#!/bin/sh\necho [\"'$1' '$2' '$3'\"]\" > " UTSCR) );
    UTST0( system( "chmod +x " UTSCR ) );
    char *exargv2[] = { UTSCR, "four", "five", "six", NULL };
    UTST( rdkssaExecv( exargv2 ) == 0 );
    remove( UTSCR );
#define UTTCHD "/tmp/uttouched123.tmp"
    remove( UTTCHD );
    UTST( system( "ls "UTTCHD ) );
    char *exargv3[] = { "/bin/touch", UTTCHD, NULL };
    UTST( rdkssaExecv( exargv3 ) == 0 );
    UTST0( system( "ls "UTTCHD ) );
    remove( UTTCHD );

    UTST( rdkssaExecv( NULL ) != 0 );
    char *exargvz[] = { NULL };
    UTST( rdkssaExecv( exargvz ) != 0 );
    char *exargv4[] = { "notfound", UTTCHD, NULL };
    UTST( rdkssaExecv( exargv4 ) != 0 );

    RDKSSA_LOG_UT("    ut_rdkssaExecv SUCCESS\n");
}

static void ut_rdkssaAttrCheck( void ) {
    RDKSSA_LOG_UT("  ut_attrSyntaxCheck\n");
    UTST( rdkssaAttrCheck( NULL ) == NULL );
    const char *str = "onetwothree";
    const char *tst = rdkssaAttrCheck( str );
    UTST( tst == str );
    UTST( rdkssaAttrCheck( "abcdefg" ) != NULL );

    RDKSSA_LOG_UT("  ut_rdkssaAttrCheck expect multiple errors\n");
    char toolong[MAX_ATTRIBUTE_VALUE_LENGTH+2] = {0};
    memset( toolong, 'g', sizeof(toolong)-1 );
    UTST( rdkssaAttrCheck( toolong ) == NULL );
    // RDKSSA_BADCHARS "{}@\\&|*<>[]()$;"
    UTST( rdkssaAttrCheck( "{abcdefgh" ) == NULL );
    UTST( rdkssaAttrCheck( "a}bcdefgh" ) == NULL );
    UTST( rdkssaAttrCheck( "ab@cdefgh" ) == NULL );
    UTST( rdkssaAttrCheck( "abc\\defgh" ) == NULL );
    UTST( rdkssaAttrCheck( "abcd&efgh" ) == NULL );
    UTST( rdkssaAttrCheck( "abcde|fgh" ) == NULL );
    UTST( rdkssaAttrCheck( "abcdef*gh" ) == NULL );
    UTST( rdkssaAttrCheck( "abcdefg$h" ) == NULL );
    UTST( rdkssaAttrCheck( "abcdefgh;" ) == NULL );

    RDKSSA_LOG_UT("  ut_rdkssaAttrCheck SUCCESS\n");
}



// attribute handlers for unit tests
#define UTSTRSZ 100
#define UTAPISZ 5 // 4 handlers

// keep track of handler memory and counts in this static
typedef struct {
  char *mem[UTAPISZ];
  int  cnt[UTAPISZ]; // [0] total, [1] handler1 cnt, [2] etc.
} utm_t;
static utm_t utm = {{0},{0}};

// cleanup and reset ut memeory for next test
static void reset_ut(void) { 
    //RDKSSA_LOG_DEBUG("  reset_ut\n");
    int  indx=0;
    for ( indx=0;indx<UTAPISZ;indx++) {
        if ( utm.mem[indx] != NULL ) {
            //RDKSSA_LOG_DEBUG("  freeing %p", utm.mem[indx]);
            rdkssa_memfree( (void **)&utm.mem[indx], strnlen( utm.mem[indx], UTSTRSZ ) );
        }
        assert( utm.mem[indx] == NULL );
    }
    rdkssa_memwipe( &utm, sizeof(utm)); // wipe everything
}
// increment one of the counts ([0] is total, [1] is just for handler1, etc.
static void incr_utcnt( int num, int amount ) {
    assert( num>=0 && num<UTAPISZ ); // internal error
    utm.cnt[num]+=amount;
    //RDKSSA_LOG_DEBUG("utm.cnt[%d] is now %d\n",num, utm.cnt[num] );
}
// check the api counts, on error display counts and return false
static int chk_utcnt( int c0, int c1, int c2, int c3, int c4 ) {
    if (! ( c0==utm.cnt[0] && c1==utm.cnt[1] && c2==utm.cnt[2] && c3==utm.cnt[3] && c4==utm.cnt[4] ) ) {
        RDKSSA_LOG_UT("  utcnt (%d,%d,%d,%d,%d)\n",utm.cnt[0],utm.cnt[1],utm.cnt[2],utm.cnt[3],utm.cnt[4]);
        return 0; // false
    }
    return 1; // true
}

// check args, store hdr and attribute value in newly allocated blob
// four handlers similar but with different num value;
// result is stored in blob array in appropriate index
static rdkssaStatus_t utHandler_main(rdkssa_blobptr_t blobPtr, int num, const char *attribStr) {
    assert( num > 0 && num <= UTAPISZ );
    if (attribStr==NULL) return rdkssaBadPointer;
    incr_utcnt(0,1);
    incr_utcnt(num,1);
    RDKSSA_LOG_DEBUG( "utHandler%d attribStr [%s]\n", num, attribStr );
    if ( blobPtr != NULL ) {
        char **apimem = (char **)blobPtr;
        if (  apimem[num] != NULL ) rdkssa_memfree( (void *)&apimem[num], strnlen( apimem[num], UTSTRSZ ) );
        assert(  apimem[num] == NULL ); // shouldn't happen
        char attr[UTSTRSZ];
        int wl = snprintf( attr, sizeof(attr), "H%d:%s", num, attribStr );
        assert( wl < UTSTRSZ ); // shouldn't happen
        apimem[num] = strndup( attr,sizeof(attr));
        RDKSSA_LOG_DEBUG( "utHandler%d new [%s]\n", num, apimem[num] );
    }
    return rdkssaOK;
}
static rdkssaStatus_t utHandler1(rdkssa_blobptr_t blobPtr,const char *attribStr) {
    return utHandler_main( blobPtr, 1, attribStr );
}
static rdkssaStatus_t utHandler2(rdkssa_blobptr_t blobPtr,const char *attribStr) {
    return utHandler_main( blobPtr, 2, attribStr );
}
static rdkssaStatus_t utHandler3(rdkssa_blobptr_t blobPtr,const char *attribStr) {
    return utHandler_main( blobPtr, 3, attribStr );
}
static rdkssaStatus_t utHandler4(rdkssa_blobptr_t blobPtr,const char *attribStr) {
    return utHandler_main( blobPtr, 4, attribStr );
}

// for extra long attribute name
#define NAME256 "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
#define NAME2048 NAME256 NAME256 NAME256 NAME256 NAME256 NAME256 NAME256 NAME256
 
static void ut_attributeHandlerHelper( void ) {
    RDKSSA_LOG_UT("  attributeHandlerHelper\n");
    //char *utmem[UTAPISZ] = {0};// stores results from each handler
    AttributeHandlerStruct utAttTable[] = { {"red", &utHandler1},
                                            {"blue", &utHandler2},
                                            {"green", &utHandler3},
                                            {ATTRIBUTE_NULL, NULL} };

    RDKSSA_LOG_UT("  attributeHandlerHelper test 1\n");
    reset_ut();
    // expect success
    UTST( attributeHandlerHelper( (void *)&utm.mem, "red", utAttTable ) == rdkssaOK );
    UTST( chk_utcnt( 1,1,0,0,0 ) );
    UTST0( strcmp( utm.mem[1], "H1:red" ));
    UTST( attributeHandlerHelper( (void *)&utm.mem, "blue", utAttTable ) == rdkssaOK );
    UTST( chk_utcnt( 2,1,1,0,0 ) );
    UTST0( strcmp( utm.mem[2], "H2:blue" ));
    UTST( attributeHandlerHelper( (void *)&utm.mem, "red=6", utAttTable ) == rdkssaOK );
    UTST( chk_utcnt( 3,2,1,0,0 ) );
    UTST0( strcmp( utm.mem[1], "H1:6" ));

    RDKSSA_LOG_UT("  attributeHandlerHelper test 2\n");
    reset_ut();
    UTST( attributeHandlerHelper( NULL, "blue=1", utAttTable ) == rdkssaOK );
    UTST( chk_utcnt( 1,0,1,0,0 ) );
    UTST( attributeHandlerHelper( NULL, "blue=2", utAttTable ) == rdkssaOK );
    UTST( chk_utcnt( 2,0,2,0,0 ) );
    UTST( attributeHandlerHelper( NULL, "blue=3", utAttTable ) == rdkssaOK );
    UTST( chk_utcnt( 3,0,3,0,0 ) );

    RDKSSA_LOG_UT("  attributeHandlerHelper test 3\n");
    // slightly more complex compares
    AttributeHandlerStruct utAttTable2[] = { {"red", &utHandler1},
                                            {"red1", &utHandler2},
                                            {"blue1",&utHandler3},
                                            {"blue", &utHandler4},
                                            {ATTRIBUTE_NULL, NULL} };
    reset_ut();
    UTST( attributeHandlerHelper( (void *)&utm.mem, "red=alpha", utAttTable2 ) == rdkssaOK );
    UTST( chk_utcnt( 1,1,0,0,0 ) );
    UTST0( strcmp( utm.mem[1], "H1:alpha" ));
    UTST( attributeHandlerHelper( (void *)&utm.mem, "red1=beta", utAttTable2 ) == rdkssaOK );
    UTST( chk_utcnt( 2,1,1,0,0 ) );
    UTST0( strcmp( utm.mem[2], "H2:beta" ));
    UTST( attributeHandlerHelper( (void *)&utm.mem, "blue1=gamma", utAttTable2 ) == rdkssaOK );
    UTST( chk_utcnt( 3,1,1,1,0 ) );
    UTST0( strcmp( utm.mem[3], "H3:gamma" ));
    UTST( attributeHandlerHelper( (void *)&utm.mem, "blue=delta", utAttTable2 ) == rdkssaOK );
    UTST( chk_utcnt( 4,1,1,1,1 ) );
    UTST0( strcmp( utm.mem[4], "H4:delta" ));

    RDKSSA_LOG_UT("  attributeHandlerHelper expect 5 errors\n");
    reset_ut();
    UTST( attributeHandlerHelper( (void *)&utm.mem, NULL, utAttTable ) == rdkssaBadPointer );
    UTST( attributeHandlerHelper( (void *)&utm.mem, "red", NULL ) == rdkssaBadPointer );
    UTST( attributeHandlerHelper( (void *)&utm.mem, "niy", utAttTable ) == rdkssaAttributeNotFound );
    UTST( chk_utcnt( 0,0,0,0,0 ) );

    // too short and too long attribute names
    UTST( attributeHandlerHelper( NULL, "o", utAttTable ) == rdkssaGeneralFailure );
    char longname[MAX_ATTRIBUTE_NAME_LENGTH+3]={0};
    memset( longname, 'y', sizeof(longname)-1 );
    UTST( attributeHandlerHelper( NULL, longname, utAttTable ) == rdkssaGeneralFailure );
    UTST( chk_utcnt( 0,0,0,0,0 ) );

    // one more extreme test, long but not too long
    AttributeHandlerStruct utAttTableMx[] = { {NAME2048, &utHandler2}, // dummy routine
                                             {ATTRIBUTE_NULL, NULL} };
    memset( longname, 'z', MAX_ATTRIBUTE_NAME_LENGTH );
    longname[MAX_ATTRIBUTE_NAME_LENGTH] = '\0';
    UTST( attributeHandlerHelper( NULL, longname, utAttTableMx ) == rdkssaOK ); // length ok

    RDKSSA_LOG_UT("  attributeHandlerHelper SUCCESS\n");
}

static void ut_rdkssaHandleAPIHelper( void ) {
    RDKSSA_LOG_UT("  rdkssaHandleAPIHelper\n");
    rdkssaStatus_t ret;
    const char * const attArray[] = {
        "ATTR3=9",
        "ATTR2=8",
        "ATTR4=7",
        "ATTR1=6",
        NULL
    };
    AttributeHandlerStruct utHndTable[] = { {"ATTR1", &utHandler1},
                                            {"ATTR2", &utHandler2},
                                            {"ATTR3", &utHandler3},
                                            {"ATTR4", &utHandler4},
                                            {ATTRIBUTE_NULL, NULL} };

    RDKSSA_LOG_UT("  rdkssaHandleAPIHelper first test\n");
    reset_ut();
    ret = rdkssaHandleAPIHelper( (void *)&utm.mem, attArray, utHndTable);
    UTST( ret == rdkssaOK );
    UTST( chk_utcnt( 4,1,1,1,1 ) );
    UTST0( strcmp( utm.mem[1], "H1:6" ));
    UTST0( strcmp( utm.mem[2], "H2:8" ));
    UTST0( strcmp( utm.mem[3], "H3:9" ));
    UTST0( strcmp( utm.mem[4], "H4:7" ));

    const char * const attArray2[] = {
        "A3=abc",
        "A2=def",
        "A4=ghi",
        "A1=jkl",
        "A4=mno",
        NULL
    };
    AttributeHandlerStruct utHndlTable2[] = {{"A1", &utHandler3},
                                             {"A2", &utHandler2},
                                             {"A3", &utHandler4},
                                             {"A4", &utHandler1},
                                             {ATTRIBUTE_NULL, NULL} };
    reset_ut();
    ret = rdkssaHandleAPIHelper( (void *)&utm.mem, attArray2, utHndlTable2);
    UTST( chk_utcnt( 5,2,1,1,1 ) );
    UTST0( strcmp( utm.mem[1], "H1:mno" ));
    UTST0( strcmp( utm.mem[2], "H2:def" ));
    UTST0( strcmp( utm.mem[3], "H3:jkl" ));
    UTST0( strcmp( utm.mem[4], "H4:abc" ));

    RDKSSA_LOG_UT("  rdkssaHandleAPIHelper SUCCESS\n");
}


/**
 * template for an example
 */
static
rdkssaStatus_t utHandlerFunc(rdkssa_blobptr_t blobPtr,const char *attribStr)
{
    RDKSSA_LOG_INFO( "utHandlerFunc received attribStr %p\n",attribStr );
    if ( attribStr == NULL ) return rdkssaBadPointer;
    
    RDKSSA_LOG_INFO( "utHandlerFunc received attribStr %s\n",attribStr );
    if ( strncmp( UT_ATTRIB_STR, attribStr, sizeof( UT_ATTRIB_STR )-1 == 0 ) )
    {
        RDKSSA_LOG_INFO( "utHandlerFunc: bad attribStr\n" );
        return rdkssaGeneralFailure;        
    }
    
    RDKSSA_LOG_INFO( "utHandlerFunc received blobPtr %p\n",blobPtr );
    /* blobPtr is NOT allowed in our handler */
    if ( blobPtr == NULL ) return rdkssaBadPointer ;
    
    char **p = (char **)blobPtr;
    RDKSSA_LOG_INFO( "utHandlerFunc received *blobPtr %s\n", *p );
    if( strncmp(UT_ATTRIB_VAL, *p, strlen(UT_ATTRIB_VAL)) )
    {
        RDKSSA_LOG_INFO( "utHandlerFunc: bad *blobPtr value\n" );
        return rdkssaGeneralFailure;
    }
    return rdkssaOK;
}


static void ut_rdkssaHandleAPIHelperTemplate( void ) {
    RDKSSA_LOG_UT("  rdkssaHandleAPIHelper Template\n");

    char *testStr = UT_ATTRIB_VAL;
    char **testStrPtr = &testStr;
    rdkssaStatus_t ret;
    const char * const attribStrArray[] = {
        UT_ATTRIB_STR,
        NULL
    };

    AttributeHandlerStruct utHandlerFuncTable[] = {
        { UT_ATTRIB_STR, utHandlerFunc },
        { NULL, NULL }
    };

    ret = rdkssaHandleAPIHelper( (void *)testStrPtr, 
                                 attribStrArray, 
                                 utHandlerFuncTable);
    UTST( ret == rdkssaOK );

    RDKSSA_LOG_UT("  rdkssaHandleAPIHelper Template expect 3 errors\n");
    testStr = "NOPE!";
    ret = rdkssaHandleAPIHelper( (void *)testStrPtr, 
                                     attribStrArray, 
                                     utHandlerFuncTable);
    UTST( ret == rdkssaGeneralFailure );

    testStr = UT_ATTRIB_VAL;
    utHandlerFuncTable[0].attributeNameStr = "NOPE!";
    ret = rdkssaHandleAPIHelper( (void *)testStrPtr, 
                                 attribStrArray, 
                                 utHandlerFuncTable);
    UTST( ret == rdkssaAttributeNotFound );

    utHandlerFuncTable[0].attributeNameStr = "UT_ATTRIB_STR";
    const char * const attribStrArray2[] = {
        "NOPE",
        NULL
    };
    ret = rdkssaHandleAPIHelper( (void *)testStrPtr, 
                                 attribStrArray2, 
                                 utHandlerFuncTable);
    UTST( ret == rdkssaAttributeNotFound );

    RDKSSA_LOG_UT("  rdkssaHandleAPIHelper Template SUCCESS\n");
}

#endif // UNIT_TESTS
