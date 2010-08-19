/*
 * Copyright (c) Members of the EGEE Collaboration. 2006-2010.
 * See http://www.eu-egee.org/partners/ for details on the copyright holders.
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
 */

#ifndef _PEP_BUFFER_H_
#define _PEP_BUFFER_H_

#ifdef  __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdio.h>
#include <limits.h>

/** buffer EOF and ERROR */
#define BUFFER_EOF    INT_MIN
#define BUFFER_ERROR  -1
#define BUFFER_OK      0

/** Stupid boolean */
#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif


/**
 * The BUFFER type.
 */
typedef struct buffer BUFFER;

/**
 * Creates a buffer with the given initial size.
 * If size < 2, then at least 16 bytes of memory are allocated.
 *
 * @param size_t size the initial size.
 *
 * @return a pointer to the new buffer or NULL if an error occurs.
 */
BUFFER * buffer_create(size_t size);

/**
 * Delete the buffer.
 *
 * @param BUFFER * buffer pointer to the buffer.
 */
void buffer_delete(BUFFER * buffer);

/**
 * Writes the buffer to an output stream.
 *
 * @param BUFFER * buffer pointer to the buffer.
 * @param FILE * ostream pointer to the output stream.
 *
 * @return size_t number of bytes written to the output stream.
 *                or BUFFER_ERROR if an error occurs.
 */
size_t buffer_fwrite(BUFFER * buffer, FILE * ostream);

/**
 * Writes count element, each size byte long, from the src array into the buffer.
 * The buffer allocates enough memory to store the written bytes.
 *
 * @param void * src pointer to the source array.
 * @param size_t size size in byte of each element.
 * @param size_t count number of element to read.
 * @param BUFFER * buffer pointer to the buffer.
 *
 * @return size_t number of bytes written into the buffer.
 *                or BUFFER_ERROR if an error occurs.
 */
size_t buffer_write(const void * src, size_t size, size_t count, void * buffer);

/**
 * Fully read an input stream in to the buffer.
 *
 * @param BUFFER * buffer pointer to the buffer.
 * @param FILE * istream pointer to the input stream.
 *
 * @return size_t number of bytes read from the input stream
 *                or BUFFER_ERROR if an error occurs.
 */
size_t buffer_fread(BUFFER * buffer, FILE * istream);

/**
 * Reads count element, each size byte long, from the buffer and store them
 * into the destination array.
 *
 * @param void * dst pointer to the destination array.
 * @param size_t size in byte of each element.
 * @param size_t count number of element to read.
 * @param BUFFER * buffer pointer to the buffer.
 *
 * @return size_t number of bytes effectively read from the buffer
 *                or BUFFER_ERROR if an error occurs.
 */
size_t buffer_read(void * dst, size_t size, size_t count, void * buffer);

/**
 * Tests the end of buffer.
 *
 * @param BUFFER * buffer pointer to the buffer.
 *
 * @return int FALSE if there is some unread data in the buffer, TRUE otherwise.
 */
int buffer_eof(BUFFER * buffer);

/**
 * Returns the next available character or BUFFER_EOF
 *
 * @param BUFFER * buffer pointer to the buffer.
 *
 * @return int the next character or BUFFER_EOF.
 */
int buffer_getc(BUFFER * buffer);

/**
 * Push back the character c, cast as a unsigned char, into the buffer.
 *
 * @param int c the character to push back at the begin of the buffer.
 * @param BUFFER * buffer pointer to the buffer.
 *
 * @return int BUFFER_OK or BUFFER_ERROR if an error occurs.
 */
int buffer_ungetc(int c, BUFFER * buffer);

/**
 * Adds the character c, cast as a unsigned char, at the end of the buffer.
 *
 * @param int c the character to add at the end of the buffer.
 * @param BUFFER * buffer pointer to the buffer.
 *
 * @return int BUFFER_OK or BUFFER_ERROR if an error occurs.
 */
int buffer_putc(int c, BUFFER * buffer);

/**
 * Rewind the buffer read position.
 *
 * @param BUFFER * buffer pointer to the buffer.
 *
 * @return int BUFFER_OK or BUFFER_ERROR if an error occurs.
 */
int buffer_rewind(BUFFER * buffer);

/**
 * Reset the buffer write and read position pointer, and zero the buffer content.
 *
 * @param BUFFER * buffer pointer to the buffer.
 *
 * @return int BUFFER_OK or BUFFER_ERROR if an error occurs.
 */
int buffer_reset(BUFFER * buffer);

/**
 * Returns the number of char available to read.
 *
 * @param BUFFER * buffer pointer to the buffer.
 *
 * @return size_t number of bytes in buffer or 0 if an error occurs.
 */
size_t buffer_length(BUFFER * buffer);

#ifdef  __cplusplus
}
#endif

#endif

