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
 * The ADT BUFFER type.
 */
typedef struct pep_buffer pep_buffer_t;

/**
 * Creates a buffer with the given initial size.
 * If size < 2, then at least 16 bytes of memory are allocated.
 *
 * @param size_t size the initial size.
 *
 * @return a pointer to the new buffer or NULL if an error occurs.
 */
pep_buffer_t * pep_buffer_create(size_t size);

/**
 * Delete the buffer.
 *
 * @param pep_buffer_t * buffer pointer to the buffer.
 */
void pep_buffer_delete(pep_buffer_t * buffer);

/**
 * Writes the buffer to an output stream.
 *
 * @param pep_buffer_t * buffer pointer to the buffer.
 * @param FILE * ostream pointer to the output stream.
 *
 * @return size_t number of bytes written to the output stream.
 *                or BUFFER_ERROR if an error occurs.
 */
size_t pep_buffer_fwrite(pep_buffer_t * buffer, FILE * ostream);

/**
 * Writes count element, each size byte long, from the src array into the buffer.
 * The buffer allocates enough memory to store the written bytes.
 *
 * @param void * src pointer to the source array.
 * @param size_t size size in byte of each element.
 * @param size_t count number of element to read.
 * @param pep_buffer_t * buffer pointer to the buffer.
 *
 * @return size_t number of bytes written into the buffer.
 *                or BUFFER_ERROR if an error occurs.
 */
size_t pep_buffer_write(const void * src, size_t size, size_t count, void * buffer);

/**
 * Fully read an input stream in to the buffer.
 *
 * @param pep_buffer_t * buffer pointer to the buffer.
 * @param FILE * istream pointer to the input stream.
 *
 * @return size_t number of bytes read from the input stream
 *                or BUFFER_ERROR if an error occurs.
 */
size_t pep_buffer_fread(pep_buffer_t * buffer, FILE * istream);

/**
 * Reads count element, each size byte long, from the buffer and store them
 * into the destination array.
 *
 * @param void * dst pointer to the destination array.
 * @param size_t size in byte of each element.
 * @param size_t count number of element to read.
 * @param pep_buffer_t * buffer pointer to the buffer.
 *
 * @return size_t number of bytes effectively read from the buffer
 *                or BUFFER_ERROR if an error occurs.
 */
size_t pep_buffer_read(void * dst, size_t size, size_t count, void * buffer);

/**
 * Tests the end of buffer.
 *
 * @param pep_buffer_t * buffer pointer to the buffer.
 *
 * @return int FALSE if there is some unread data in the buffer, TRUE otherwise.
 */
int pep_buffer_eof(pep_buffer_t * buffer);

/**
 * Returns the next available character or BUFFER_EOF
 *
 * @param pep_buffer_t * buffer pointer to the buffer.
 *
 * @return int the next character or BUFFER_EOF.
 */
int pep_buffer_getc(pep_buffer_t * buffer);

/**
 * Push back the character c, cast as a unsigned char, into the buffer.
 *
 * @param int c the character to push back at the begin of the buffer.
 * @param pep_buffer_t * buffer pointer to the buffer.
 *
 * @return int BUFFER_OK or BUFFER_ERROR if an error occurs.
 */
int pep_buffer_ungetc(int c, pep_buffer_t * buffer);

/**
 * Adds the character c, cast as a unsigned char, at the end of the buffer.
 *
 * @param int c the character to add at the end of the buffer.
 * @param pep_buffer_t * buffer pointer to the buffer.
 *
 * @return int BUFFER_OK or BUFFER_ERROR if an error occurs.
 */
int pep_buffer_putc(int c, pep_buffer_t * buffer);

/**
 * Rewind the buffer read position.
 *
 * @param pep_buffer_t * buffer pointer to the buffer.
 *
 * @return int BUFFER_OK or BUFFER_ERROR if an error occurs.
 */
int pep_buffer_rewind(pep_buffer_t * buffer);

/**
 * Reset the buffer write and read position pointer, and zero the buffer content.
 *
 * @param pep_buffer_t * buffer pointer to the buffer.
 *
 * @return int BUFFER_OK or BUFFER_ERROR if an error occurs.
 */
int pep_buffer_reset(pep_buffer_t * buffer);

/**
 * Returns the number of char available to read.
 *
 * @param pep_buffer_t * buffer pointer to the buffer.
 *
 * @return size_t number of bytes in buffer or 0 if an error occurs.
 */
size_t pep_buffer_length(pep_buffer_t * buffer);

#ifdef  __cplusplus
}
#endif

#endif

