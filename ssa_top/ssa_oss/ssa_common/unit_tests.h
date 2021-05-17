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

#ifndef __unit_tests__
#define __unit_tests__

#if defined(UNIT_TESTS) || defined(PLTFORM_TEST)
#include <assert.h>
#define UTST( t ) assert( (t) != 0 )
#define UTST0( t ) assert( (t) == 0 )
#define UT_STRCMP( v, x, l ) assert( strncmp(v,x,l) == 0 )
#define UT_STRDIFF( v, x, l ) assert( strncmp(v,x,l) != 0 )
#define UT_STRSTRT( v, x, l ) assert( strncmp(v,x,strnlen(x,l)) == 0 )
// ut utils
#define UT_SYSTEM( c ) {printf("cmd:%s\n", (c)?(c):"");assert( system( c )==0 );}
#define UT_REMOVE( f ) {printf("rm %s\n", (f)?(f):"");assert( remove( f ) == 0 );}
#define UT_EXIT( ) {printf("Early Exit\n");assert( 0 );}

// exit codes
#define UT_OK   0
#define UT_ERR  1

#ifdef USE_COLORS
//#define COL_RED "\033[0;31m"
//#define COL_GRN "\033[0;32m"
//#define COL_YEL "\033[0;33m"
//#define COL_BLU "\033[0;34m"
//#define COL_MAG "\033[0;35m"
#define COL_CYA "\033[0;36m"
#define COL_DEF "\033[0m"
#else
#define COL_CYA ""
#define COL_DEF ""
#endif
#ifdef USE_COLORS
#define PREFIXU(formatu)                (COL_CYA"%12s:%3d:%12s - " formatu COL_DEF)
#define LOG_UNITTEST(formatu, ...)        {fprintf(stdout, formatu, __VA_ARGS__);fflush(stdout);}
#define RDKSSA_LOG_UT(formatu, ...)     LOG_UNITTEST(PREFIXU("UT:" formatu), strrchr(__FILE__,'/')+1,__LINE__,__FUNCTION__, ##__VA_ARGS__)
#else
#define PREFIXU(formatu)                  ("%d\t: %s - " formatu)
#define LOG_UNITTEST(formatu, ...)        {fprintf(stdout, formatu, __VA_ARGS__);fflush(stdout);}
#define RDKSSA_LOG_UT(formatu, ...)       LOG_UNITTEST(PREFIXU(formatu),  __LINE__, __func__, ##__VA_ARGS__)
#endif
#endif // UNIT_TESTS

#endif //__unit_tests__
