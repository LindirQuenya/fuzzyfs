/*
 * fuzzyfs: Case-insensitive FUSE file system
 * Copyright (C) 2020  Joel Puig Rubio <joel.puig.rubio@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#define FUSE_USE_VERSION 26
#define TRUE 1
#define FALSE 0
// The factor by which the memo dictionary multiplies its size when it's out of room.
#define SCALING_FACTOR 2
// The number of entries the memo dictionary should start out with.
#define MEMODICT_INIT_SIZE 32

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>

static const char* DOT = ".";

const char* root = NULL;

// TODO: use fast-compare instead of strcmp for everything.

// Many thanks to https://stackoverflow.com/a/3536261, whose code I modified for this.
// This is essentially a hash table, but without the hashes.
typedef struct
{
	// An array to hold the input char*'s.
	char **input;
	// An array to hold the output char*'s.
	char **output;
	// Output and input will always have the same size and number of elements used.
	size_t used;
	size_t size;
} DynamicDictionary;

// This is the instance of the dictionary that we will be using.
static DynamicDictionary memoDict;
// A lock for reading and writing to the dictionary.
static pthread_mutex_t memoLock;

// Initialize the memo dictionary to a given size.
void initDDict(DynamicDictionary *d, size_t initialSize)
{
	// Whatever the initial size is
	d->input = malloc(initialSize * sizeof(char*));
	d->output = malloc(initialSize * sizeof(char*));
	// The number of elements used. Also works as an index for the first empty slot.
	d->used = 0;
	// The total size of the dictionary.
	d->size = initialSize;
}

/* Below are three insertDDict variants.
 *
 * One of them calls strdup on both arguments, and places the results
 * in the dictionary. This one is the most standard, but it could induce
 * overhead from any unneeded strdups. I haven't used it, so I commented it out.
 *
 * The second will strdup the input but not the output. This allows us to
 * use slightly cleaner syntax when calling it, and it avoids an extra strdup.
 *
 * The third takes only one argument, strdup's it, and points both the input
 * and output to that. It's for cases in which we want to cache an unmodified
 * input-output "pair" without using extra memory.
 *
 * An astute observer may note that we always strdup the input. This is because
 * the input is either a pointer to a FUSE path (managed and freed separately by
 * FUSE) or a pointer to DOT, which is a read-only static string. If it's the latter,
 * we have used only one unneeded byte of memory and performed only one unneeded
 * strdup. This can only occur once because it will be memoized. I don't think
 * this is an important consideration.
 *
 * Speaking of important considerations: thread-safety! None of the DynamicDictionary
 * functions are thread-safe: you'll have to ensure that your caller locks around
 * them properly.
 */

// Insert an element into the dictionary, expanding if needed.
/*void insertDDict(DynamicDictionary *d, char *in, char *out)
{
	// If this dictionary has already been freed or is uninitialized,
	if (d->input == NULL || d->output == NULL)
	{
		// Do nothing.
		return;
	}
	// If we're getting passed invalid strings,
	if (in == NULL || out == NULL)
	{
		// Do nothing.
		return;
	}
	// If the next empty slot is out-of-bounds,
	if (d->used == d->size)
	{
		// Increase the size by a factor of SCALING_FACTOR.
		d->size = (int)(SCALING_FACTOR * d->size);
		// Call realloc to expand the input and output arrays.
		d->input = realloc(d->input, d->size * sizeof(char*));
		d->output = realloc(d->output, d->size * sizeof(char*));
	}
	// Insert the element. Note: this allocates new memory.
	d->input[d->used] = strdup(in);
	d->output[d->used] = strdup(out);
	// Increment the number of used elements.
	d->used++;
}*/

// Insert an element into the dictionary, expanding if needed.
// This version doesn't call strdup() on the out string, just the in string.
// This should improve performance in some instances.
// Beware though: you can't go free out later, if you use this!
void insertDDict_noOutStrdup(DynamicDictionary *d, char *in, char *out)
{
	// If this dictionary has already been freed or is uninitialized,
	if (d->input == NULL || d->output == NULL)
	{
		// Do nothing.
		return;
	}
	// If we're getting passed invalid strings,
	if (in == NULL || out == NULL)
	{
		// Do nothing.
		return;
	}
	// If the next empty slot is out-of-bounds,
	if (d->used == d->size)
	{
		// Increase the size by a factor of SCALING_FACTOR.
		d->size = (int)(SCALING_FACTOR * d->size);
		// Call realloc to expand the input and output arrays.
		d->input = realloc(d->input, d->size * sizeof(char*));
		d->output = realloc(d->output, d->size * sizeof(char*));
	}
	// Insert the element. Note: this allocates new memory, but only for input.
	d->input[d->used] = strdup(in);
	d->output[d->used] = out;
	// Increment the number of used elements.
	d->used++;
}

// Insert an element into the dictionary, expanding it if needed.
// This version inserts the same string into input and output.
// For when the input is the same as the output, and we want to save memory.
void insertDDict_noMod(DynamicDictionary *d, char *in_and_out)
{
	// If this dictionary has already been freed or is uninitialized,
	if (d->input == NULL || d->output == NULL)
	{
		// Do nothing.
		return;
	}
	// If we're getting passed invalid strings,
	if (in_and_out == NULL)
	{
		// Do nothing.
		return;
	}
	// If the next empty slot is out-of-bounds,
	if (d->used == d->size)
	{
		// Increase the size by a factor of SCALING_FACTOR.
		d->size = (int)(SCALING_FACTOR * d->size);
		// Call realloc to expand the input and output arrays.
		d->input = realloc(d->input, d->size * sizeof(char*));
		d->output = realloc(d->output, d->size * sizeof(char*));
	}
	// Insert the element. Note: this allocates new memory.
	d->input[d->used] = strdup(in_and_out);
	d->output[d->used] = d->input[d->used];
	// Increment the number of used elements.
	d->used++;
}

// Check if the dictionary contains an input value that is the same as in.
// Returns the corresponding output value if found, and null otherwise.
char* searchDDict(DynamicDictionary *d, char *in)
{
	// If this dictionary has already been freed or is uninitialized,
	if (d->input == NULL || d->output == NULL)
	{
		// Do nothing.
		return NULL;
	}
	if (in == NULL)
	{
		return NULL;
	}
	// Loop over every element. Note: We search backwards so that the recently-stored
	// elements get faster results.
	// TODO: maybe for absolutely enormous arrays, we make d->input
	// be sorted, and then we can use a binary search here instead of the linear one.
	for (int i = d->used - 1; i >= 0; i--)
	{
		// If the input strings match,
		if (strcmp(in, d->input[i]) == 0)
		{
			// We found it! Return a pointer to the output string.
			return d->output[i];
		}
	}
	// It wasn't found. Return null.
	return NULL;
}

// Free all the memory associated with the dynamic dictionary.
void freeDDict(DynamicDictionary *d)
{
	// For every element,
	for (int i = 0; i < d->used; i++)
	{
		// Free the input-output pair.
		free(d->input[i]);
		// Check that the input-output pair isn't a noMod.
		if (d->input[i] != d->output[i])
		{
			// If they're different, free the second as well.
			// We wouldn't want a double free.
			free(d->output[i]);
		}
		// Set the pointers to null, just in case some
		// madman tries accessing them after freeing the dict.
		d->input[i] = NULL;
		d->output[i] = NULL;
	}
	// All the elments are freed, free the arrays
	// themselves and set their pointers to null.
	free(d->input);
	d->input = NULL;
	free(d->output);
	d->output = NULL;
	// Set the size and number-of-used-elements to zero.
	d->used = 0;
	d->size = 0;
}

/*
 * If the requested path is '/', returns DOT.
 * If the requested path starts with '/', strips the leading '/' off.
 * Leaves the string otherwise untouched.
 */
const char* fix_path(const char* path)
{
	// Make p, which points to the same thing as path.
	const char *p = path;

	// If the string starts with '/',
	if (p[0] == '/')
	{
		// If the next character is the null terminator
		// (that is, the whole string is just '/'),
		if (p[1] == '\0')
			// Return DOT.
			return DOT;
		// If the next character is not the null terminator,
		// The string only starts with '/'. Skip the first character.
		p++;
	}
	// If the string doesn't start with '/', leave it untouched.
	// Return the string.
	return p;
}

/* Get the correct case for a file path by searching case-insenitively for matches.
 * Input: path - a string holding the path that you want to correct the case of.
 * This will iterate over slash-delimited chunks of path. On each iteration, it corrects
 * the case of the current chunk (if correction is needed) by looking for files in the
 * current chunk's parent directory (constructed from previous case-corrected chunks) that
 * case-insensitively match the current chunk. If one is found, the current chunk is corrected.
 * This repeats until the entire path is case-corrected. The case-corrected path is returned.
 */
char* fix_path_case(const char* path)
{
	char *p;
	DIR *dp;
	struct dirent *de;
	struct stat s = { 0 };
	int len, found;
	char *token, *parent, *saveptr;

	// p is a copy of path. Note: this allocates new memory.
	p = strdup(path);
	// Split p on slashes. saveptr will follow along so that we can call it again to get the next token.
	token = strtok_r(p, "/", &saveptr);
	// Keep going until we get a null back - that is, loop over all slash-delimited chunks of p.
	while (token != NULL)
	{
		// len is how far into the string the current chunk is.
		len = token - p;
		// If we're not on the first chunk, which would have len = 0,
		if (len)
		{
			// strtok_r replaces all the delimiters with nulls so that chunks can be treated as
			// their own separate strings. This will be a useful property for the current chunk,
			// but we will need the delimiter in place on previous chunks. This line restores the
			// delimiter directly before this chunk.
			*(token - 1) = '/'; // restore delimiter
		}

		// If the current capitalization of the path (up to the current chunk) is incorrect,
		// (that is, if getting info about the currently-specified chunk returns a nonzero exit code)
		// Remember, strtok_r will place a null terminator after the current chunk, so we're not
		// doing the whole path, just from the string beginning to the null terminator.
		if (lstat(p, &s))
		{
			// If we're not on the first chunk,
			if (len)
			{
				// Fill parent with the portion of p preceding this chunk.
				// Note: this allocates new memory!
				parent = (char*)malloc(len + 1);
				strncpy(parent, p, len);
				// And remember to null-terminate.
				parent[len] = '\0';
			}
			// Else, we are on the first chunk.
			else
			{
				// parent is just DOT. Also allocates new memory.
				parent = strdup(DOT);
			}

			// Open the directory.
			dp = opendir(parent);
			// If the directory doesn't exist or isn't a directory or we don't have access (unlikely, we're root.)
			if (dp == NULL)
			{
				// Free some memory and return null.
				free(p);
				p = NULL;
				free(parent);
				parent = NULL;
				return NULL;
			}

			// We haven't found the next portion yet. To be fair, we haven't started looking.
			found = FALSE;
			// For each filename in the parent directory,
			// Note: don't free de. It's managed separately.
			while ((de = readdir(dp)) != NULL)
			{
				// See if we can find a filename that case-insensitively matches the current chunk.
				if (strcasecmp(de->d_name, token) == 0)
				{
					// Wow, we found it! Log the name change.
					printf("%s --> %s\n", token, de->d_name);
					// Also, change the current chunk to the case-changed version.
					strcpy(token, de->d_name);
					// We found it, so we can change the variable.
					found = TRUE;
					break;
				}
			}
			// Close the directory.
			closedir(dp);
			// parent isn't needed anymore, free it and make it null.
			free(parent);
			parent = NULL;

			// If we didn't find anything,
			if (!found)
			{
				// The file or directory doesn't exist in any capitalization.
				// Free p, set it to null, and return.
				free(p);
				p = NULL;
				return NULL;
			}
		}

		// Move to the next chunk of the string.
		token = strtok_r(NULL, "/", &saveptr);
	}

	return p;
}

// Gets file attributes.
static int fuzzyfs_getattr(const char *path, struct stat *stbuf)
{
	int res;
	char *p;
	char *strRes;

	// Increment past any leading slashes.
	p = (char*)fix_path(path);

	// Lock: We're about to read/write memoDict.
	pthread_mutex_lock(&memoLock);
	// Pass a pointer to memoDict.
	// Also, remember: p currently points to memory allocated for path.
	// Note: if this succeeds, it just returns a pointer to somewhere in the dictionary.
	// Don't you dare try to free it.
	strRes = searchDDict(&memoDict, p);
	// If the search failed...
	if (strRes == NULL)
	{
		// Just try without any modifications.
		// The file attributes should be put in stbuf.
		res = lstat(p, stbuf);
		// It worked? Return zero.
		if (!res)
		{
			// Also put it in the memoDict.
			// The string requires no modification, so we can use noMod.
			insertDDict_noMod(&memoDict, p);
			// Unlock: we're done reading and writing to memoDict.
			pthread_mutex_unlock(&memoLock);
			return 0;
		}

		// If the error code is anything but ENOENT ("file not found"), return it.
		if (errno != ENOENT)
		{
			// Unlock: we're done reading and writing to memoDict.
			pthread_mutex_unlock(&memoLock);
			// We found nothing, so no memo.
			return -errno;
		}

		// The error was ENOENT.
		// See if fix_path_case finds anything.
		// Note: this allocates new memory for p, unless it returns an error.
		if (!(strRes = fix_path_case(p)))
		{
			// It doesn't. Return ENOENT.
			// Unlock: we're done reading and writing to memoDict.
			pthread_mutex_unlock(&memoLock);
			// Again, nothing found. No memo.
			return -ENOENT;
		}

		// fix_path_case did find something.
		// Memoize! This function won't strdup strRes, so we won't free strRes either.
		insertDDict_noOutStrdup(&memoDict, p, strRes);
	}
	// Unlock: we're done reading and writing to memoDict.
	pthread_mutex_unlock(&memoLock);

	// Put the result's attributes in stbuf.
	res = lstat(strRes, stbuf);
	// Unless lstat errored out, return zero.
	assert(res != -1);
	return 0;
}

// Reads the contents of a directory.
static int fuzzyfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			   off_t offset, struct fuse_file_info *fi)
{
	DIR *dp = NULL;
	struct dirent *de;
	char *p;
	char *strRes;

	(void) offset;
	(void) fi;

	// Increment past the leading slash, if any.
	p = (char*)fix_path(path);

	// Lock: We're about to read/write memoDict.
	pthread_mutex_lock(&memoLock);
	// Pass a pointer to memoDict.
	// Also, remember: p currently points to memory allocated for path.
	// Note: if this succeeds, it just returns a pointer to somewhere in the dictionary.
	// Don't you dare try to free it.
	strRes = searchDDict(&memoDict, p);

	// If the search failed...
	if (strRes == NULL)
	{
		// Try to open the directory without path modification.
		dp = opendir(p);
		// Check if it worked.
		if (dp != NULL)
		{
			// If it did work without modification, memoize that result.
			insertDDict_noMod(&memoDict, p);
		}
		// Else-cases: it didn't work.
		// If the error was anything but ENOENT, return that error.
		else if (errno != ENOENT)
		{
			// Unlock: we're done reading and writing to memoDict.
			pthread_mutex_unlock(&memoLock);
			// Nothing found, so no memo.
			return -errno;
		}
		// The error was ENOENT.
		// See if fix_path_case finds anything.
		else if (!(strRes = fix_path_case(p)))
		{
			// It found nothing. Unlock and return ENOENT.
			pthread_mutex_unlock(&memoLock);
			// Again, nothing found. No memo.
			return -ENOENT;
		}
		// fix_path_case did find something.
		else
		{
			// Memoize! This function won't strdup strRes, so we won't free strRes either.
			insertDDict_noOutStrdup(&memoDict, p, strRes);
		}
	}
	// Unlock: we're done reading and writing to memoDict.
	pthread_mutex_unlock(&memoLock);
	// If dp is still null...
	if (dp == NULL)
	{
		// strRes should at this point hold a valid path. Try to open it.
		dp = opendir(strRes);
	}
	// Assert that it worked.
	assert(dp != NULL);

	// At this point, we have either bailed out or placed the directory stream in dp.
	while ((de = readdir(dp)) != NULL)
	{
		// Make a new stat struct.
		struct stat st;
		// Zero it out.
		memset(&st, 0, sizeof(st));
		// Copy the inode and mode.
		st.st_ino = de->d_ino;
		// TODO: figure out what this is doing. Why are we setting the mode from the type?
		st.st_mode = de->d_type << 12;
		// Call the magic FUSE filler function.
		if (filler(buf, de->d_name, &st, 0))
		{
			break;
		}
	}
	// Close the directory and return zero.
	closedir(dp);
	return 0;
}

// Basic check that a file exists.
static int fuzzyfs_open(const char *path, struct fuse_file_info *fi)
{
	int res;
	char *p;
	char *strRes;

	// Increment past the leading slash, if any.
	p = (char*)fix_path(path);

	// Lock: We're about to read/write memoDict.
	pthread_mutex_lock(&memoLock);
	// Pass a pointer to memoDict.
	// Also, remember: p currently points to memory allocated for path.
	// Note: if this succeeds, it just returns a pointer to somewhere in the dictionary.
	// Don't you dare try to free it.
	strRes = searchDDict(&memoDict, p);
	// If the search failed...
	if (strRes == NULL)
	{
		// Try to open the file normally.
		res = open(p, fi->flags);

		// It worked? Return zero.
		if (res != -1)
		{
			// Also put it in the memoDict.
			// The string requires no modification, so we can use noMod.
			insertDDict_noMod(&memoDict, p);
			// Unlock: we're done reading and writing to memoDict.
			pthread_mutex_unlock(&memoLock);
			// Close the file descriptor and return zero.
			close(res);
			return 0;
		}

		// If the error code is anything but ENOENT ("file not found"), return it.
		if (errno != ENOENT)
		{
			// Unlock: we're done reading and writing to memoDict.
			pthread_mutex_unlock(&memoLock);
			// We found nothing, so no memo.
			return -errno;
		}

		// The error was ENOENT.
		// See if fix_path_case finds anything.
		// Note: this allocates new memory for p, unless it returns an error.
		if (!(strRes = fix_path_case(p)))
		{
			// It doesn't. Return ENOENT.
			// Unlock: we're done reading and writing to memoDict.
			pthread_mutex_unlock(&memoLock);
			// Again, nothing found. No memo.
			return -ENOENT;
		}

		// fix_path_case did find something.
		// Memoize! This function won't strdup strRes, so we won't free strRes either.
		insertDDict_noOutStrdup(&memoDict, p, strRes);
	}
	// Unlock: we're done reading and writing to memoDict.
	pthread_mutex_unlock(&memoLock);

	// If it can, open it.
	res = open(strRes, fi->flags);
	// Then close the file descriptor.
	close(res);
	// As long as there were no errors, return zero.
	assert(res != -1);
	return 0;
}

// Read size bytes from the given file into the buffer buf, beginning offset bytes into the file.
static int fuzzyfs_read(const char *path, char *buf, size_t size, off_t offset,
			struct fuse_file_info *fi)
{
	int fd = -1;
	int res;
	char *p;
	char *strRes;

	(void) fi;

	// Increment past the leading slash, if any.
	p = (char*)fix_path(path);
	// Lock: We're about to read/write memoDict.
	pthread_mutex_lock(&memoLock);
	// Pass a pointer to memoDict.
	// Also, remember: p currently points to memory allocated for path.
	// Note: if this succeeds, it just returns a pointer to somewhere in the dictionary.
	// Don't you dare try to free it.
	strRes = searchDDict(&memoDict, p);
	// If the search failed...
	if (strRes == NULL)
	{
		// Try to open it read-only without modifications.
		fd = open(p, O_RDONLY);

		// It worked? Memoize it.
		if (fd != -1)
		{
			// The string requires no modification, so we can use noMod.
			insertDDict_noMod(&memoDict, p);
		}
		// If the error was not an ENOENT, return that error.
		else if (errno != ENOENT)
		{
			// Unlock: we're done reading and writing to memoDict.
			pthread_mutex_unlock(&memoLock);
			return -errno;
		}
		// If it gave ENOENT, see if fix_path_case can fix it.
		else if (!(strRes = fix_path_case(p)))
		{
			// If it can't, return ENOENT.
			// Unlock: we're done reading and writing to memoDict.
			pthread_mutex_unlock(&memoLock);
			return -ENOENT;
		}
		// fix_path_case did find something.
		else
		{
			// Memoize! This function won't strdup strRes, so we won't free strRes either.
			insertDDict_noOutStrdup(&memoDict, p, strRes);
		}
	}
	// Unlock: we're done reading and writing to memoDict.
	pthread_mutex_unlock(&memoLock);
	// If fd is still -1...
	if (fd == -1)
	{
		// Open the file read-only.
		fd = open(strRes, O_RDONLY);
		// Asser that it worked.
		assert(fd != -1);
	}

	// Read from the file descriptor.
	res = pread(fd, buf, size, offset);
	// If there was an error, pass it through.
	if (res == -1)
	{
		res = -errno;
	}

	// Close the file descriptor.
	close(fd);
	// Return whatever retval we get.
	return res;
}

static void *fuzzyfs_init(struct fuse_conn_info *conn)
{
	// cd into the root directory, wherever that is.
	if (chdir(root) == -1)
	{
		// If it didn't work, throw some errors.
		perror("chdir");
		exit(1);
	}

	return NULL;
}

static void fuzzyfs_destroy(void *private_data)
{
	// We're about to free the DDict, so we lock.
	pthread_mutex_lock(&memoLock);
	freeDDict(&memoDict);
	pthread_mutex_unlock(&memoLock);
	// Destroy the mutex.
	pthread_mutex_destroy(&memoLock);
}

static int fuzzyfs_opt_parse(void *data, const char *arg, int key,
			     struct fuse_args *outargs)
{
	// If root is unset and we're handling a positional argument,
	// Note: this will be triggered only by the first argument.
	if (!root && key == FUSE_OPT_KEY_NONOPT)
	{
		// Set root to the absolute version of that argument.

		// when fuse starts, it changes the workdir to the root
		// must resolve relative paths beforehand
		if (!(root = realpath(arg, NULL)))
		{
			perror(outargs->argv[0]);
			exit(1);
		}
		// It worked. Return success.
		return 0;
	}

	// Return failure.
	return 1;
}

// Setup the mapping between the fuse functions and the fuzzyfs functions.
static struct fuse_operations fuzzyfs_oper = {
	.getattr	= fuzzyfs_getattr,
	.readdir	= fuzzyfs_readdir,
	.open		= fuzzyfs_open,
	.read		= fuzzyfs_read,
	.init		= fuzzyfs_init,
	.destroy	= fuzzyfs_destroy,
};

int main(int argc, char *argv[])
{
	// Init the mutex lock.
	pthread_mutex_init(&memoLock, NULL);
	// We're about to initialize the memoDict, so we lock.
	pthread_mutex_lock(&memoLock);
	initDDict(&memoDict, MEMODICT_INIT_SIZE);
	pthread_mutex_unlock(&memoLock);

	// Parse the args.
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	fuse_opt_parse(&args, NULL, NULL, fuzzyfs_opt_parse);
	// Set the umask to zero - all permissions are allowed.
	umask(0);
	// Call the fuse_main function to start everything.
	return fuse_main(args.argc, args.argv, &fuzzyfs_oper, NULL);
}
