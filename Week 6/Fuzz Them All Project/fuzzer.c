/*-
 *
 *  Fuzzer for CSE 543 Arizona State University Course
 *
 *  Author:
 *  	Marco Ermini - mermini@asu.edu - ASU ID 1222142220
 *
 *
 *  Usage: "seed string" | fuzzer prng_seed num [-0] [-a] [-d delay] [-p]
 * 												[-s seedfilein] [-o outfile] [-r infile]
 *
 *  Generate random values to standard output iterating num times.
 *
 *  Options:
 *
 *		prng_seed	32-bit integer to be used as to seed the prng function
 *      num			number of iteration in producing the output
 *      -0			NULL (zero) value character to be included
 *      -a			Uses all ASCII character (default)
 *      -p    		Uses printable ASCII only
 *      -d delay	Delay for "delay" seconds between outputs
 *      -o outfile  Record characters in "outfile" along with STDOUT
 *      -r infile   Replay characters from "infile" - does not generate them
 *      -s seed in	Read seed value from file; defaults to "seed" in current directory
 *      -e seed out	Saves generated seed value in file; defaults to "seedout" in current directory
 *
 *  Defaults:
 *      ./fuzzer (-a) (-s seed) prng_seed num_of_iterations 
 */

//#define DEBUG 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <ctype.h>

/*
 * Constants
 */
#define SWITCH '-'
#define CHARS_TO_ADD	10U

/*
 * Global flags and values
 */
unsigned int	prng_seed = 0;
unsigned int	numiter = 0;
unsigned long	delay = 0;
int     		flag0 = 0;
int     		flaga = 1;
int     		flagx = 0;
int     		flago = 0;
int     		flagr = 0;
int     		flags = 0;
char			*infile, *outfile;
FILE			*in, *out;
char			seedfilein [255];
void			*string_seed = NULL;
unsigned int	string_seed_len = 0;
unsigned char 	*final_buffer = NULL;
FILE			*OUTFUZZ;

/*
 * Functions' declarations
 */
void			usage();
void			init();
void			garbage_collector();
void			replay();
int				randomstr(void *, size_t);
void			printfuzz(unsigned int);
void			putstr(unsigned char *, size_t);
void			putch(char);
void			reseed();

/*
 * Display usage to the user
 */
void usage()
{
     puts("Usage: \"seed string\" | fuzz prng_seed num_iter [-0] [-a] [-d delay] [-p]");
     puts("            [-o outfile] [-r infile] [-s seed file input]");
     exit(1);
}

/*
 * main function
 */
int main(int argc, char** argv)
{
	unsigned int	param_value = 0;

	/* By default, file name is "seed" in the current directory */
	strcpy (seedfilein, "seed");

#ifdef DEBUG
	fprintf(stderr, "[DEBUG] Running in DEBUG mode...\n\n");
#endif
	/*
	* Parse command line 
	*/
    while (*(++argv) != NULL)
		if (**argv != SWITCH) {		/* Not a switch, must be a value			*/
			if (sscanf(*argv, "%u", &param_value) != 1) {
				usage();
				return 0;
			}
			if (prng_seed == 0) {	/* first parameter is prng_seed   			*/
				prng_seed = param_value;
#ifdef DEBUG
			fprintf(stderr, "[DEBUG] Read PRNG value to: %d\n", prng_seed);
#endif
			} else {				/* second parameter is iteration number		*/
				numiter = param_value;
#ifdef DEBUG
			fprintf(stderr, "[DEBUG] Read Number Iteration value to: %d\n", numiter);
#endif
			}
		} else {					/* identify switch parameters 				*/
			switch ((*argv)[1]) {
				case '0':
					flag0 = 1;
#ifdef DEBUG
					fprintf(stderr, "[DEBUG] Allow NULL values flag set\n");
#endif
					break;
				case 'a':
					flaga = 1;
#ifdef DEBUG
					fprintf(stderr, "[DEBUG] Require printable ASCII flag set\n");
#endif
					break;
				case 'd':
					argv++;
					if (sscanf(*argv, "%u", &param_value) != 1) {
						perror ("Error: -d option requires a numeric value (delay)\n");
						usage();
						garbage_collector();
						exit (1);
					}
					else
						delay = param_value * 1000000;
#ifdef DEBUG
						fprintf(stderr, "[DEBUG] Set delay to: %d\n", delay);
#endif
					break;
				case 'o':
					flago = 1;
					argv++;
					outfile = *argv;
#ifdef DEBUG
					fprintf(stderr, "[DEBUG] Set output file to: %d\n", outfile);
#endif
					break;
				case 'p':
					flaga = 0;
#ifdef DEBUG
					fprintf(stderr, "[DEBUG] Print all ASCII characters:\n");
#endif
					break;
				case 'r':
					flagr = 1;
					argv++;
					infile = *argv;
#ifdef DEBUG
					fprintf(stderr, "[DEBUG] Set input file to: %d\n", infile);
#endif
					break;
				case 's':
					argv++;
					if (sscanf(*argv, "%255s", seedfilein) != 1) {
						perror ("Error: -s option requires a file name (seed file to read from)\n");
						usage();
						garbage_collector();
						exit (1);
					}
#ifdef DEBUG
					fprintf(stderr, "[DEBUG] Set output file to: %d\n", outfile);
#endif
					break;
				default:
					usage();
			}
		}

	init();
	if (flagr)
		replay();
	else
		printfuzz (numiter);

	garbage_collector();
	return 0;
}

/*
 * Initialize random number generator, open files, print prng_seed
 */
void init()
{
	unsigned char c;

	/*
	 * Read seed value from STDIN, if piped
	 */
	if (!isatty(fileno(stdin))) {
		int i = 0;
		string_seed = calloc(BUFSIZ, 1);
		do {
			c = fgetc(stdin);
			if(feof(stdin)) {
				break;
			}
			((char *)string_seed)[i++] = c;
		} while (1 && i <= BUFSIZ);

		string_seed_len = i;
#ifdef DEBUG
		fprintf(stderr, "[DEBUG] Incoming piped seed from STDIN: %*s\n", string_seed_len-1, string_seed);
#endif
	} else {
		/*
		* The seed value has not been piped, so we retrieve value
		* from the seed file.
		* Allows arbitrary lenght and stores into string_seed.
		*/
		FILE	*sf;
		size_t	new_len;
		long	bufsize;

		if ((sf = fopen(seedfilein, "rb")) == NULL) {
			char b[BUFSIZ];
			sprintf(b, "Cannot open read seed file: %s. Exiting.\n", seedfilein);
			perror (b);
			garbage_collector();
			exit(1);
		} else {
			if (!fseek(sf, 0L, SEEK_END)) {
				/* Get the size of the file */
				bufsize = ftell(sf);
				if (bufsize == -1) {
					char b[BUFSIZ];
					sprintf(b, "Cannot seek end of read seed file: %s. Exiting.\n", seedfilein);
					perror (b);
					garbage_collector();
					exit (1);
				}

				/* Go back to the start of the file */
				if (fseek(sf, 0L, SEEK_SET) != 0) {
					char b[BUFSIZ];
					sprintf(b, "Cannot seek start of read seed file: %s. Exiting.\n", seedfilein);
					perror (b);
					garbage_collector();
					exit (1);
				}

				/* Allocate our buffer to that size */
#ifdef DEBUG
				fprintf(stderr, "[DEBUG] Allocating %d bytes for seed file read buffer\n", (int)(sizeof(char) * (bufsize + 1)));
#endif
				string_seed = calloc(sizeof(char), bufsize + 1);
				if (string_seed) {
					/* Read the seed file into the buffer */
					new_len = fread(string_seed, sizeof(char), bufsize, sf);
					if (ferror (sf) != 0) {
						char b[BUFSIZ];
						sprintf(b, "Cannot read seed file input: %s. Exiting.\n", seedfilein);
						perror (b);
						garbage_collector();
						exit (1);
					}
					//else {
					//	string_seed[newLen++] = '\0'; /* Forces NULL termination. */
					//}
					string_seed_len = bufsize;
				} else {
					perror ("Cannot allocate memory for buffer. Exiting.\n");
					garbage_collector();
					exit (1);					
				}
			}
			fclose(sf);
#ifdef DEBUG
			fprintf(stderr, "[DEBUG] Seed file opened: %s\n[DEBUG] Seed read from file: %*s\n", seedfilein, string_seed_len-1, string_seed);
#endif
		}
	}

	/*
	 * Initialize random numbers generator with prng_seed, if passed
	 */
	if (!prng_seed) {
		long now;
		/* If no prng_seed is specified, use srand with current time.
		 * This is cryptographically bad!
		 */
		srand(time(&now));
#ifdef DEBUG
		fprintf(stderr, "[DEBUG] Initialized PRNG to current time - value: %ld\n", now);
#endif
	} else {
		if (prng_seed < 0) {
			char b[BUFSIZ];
			sprintf(b, "Wrong prng_seed provided: value %d is illegal. Exiting.", prng_seed);
			perror (b);
			exit(1);
		}
		srand(prng_seed);
#ifdef DEBUG
		fprintf(stderr, "[DEBUG] Initialized PRNG to provided value: %d\n", prng_seed);
#endif
	}

	/*
	 * Open data files if requested.
	 */
	if (flago)
		if ((out = fopen(outfile, "wb")) == NULL) {
			char b[BUFSIZ];
			sprintf(b, "Cannot open output file %s. Exiting.\n", outfile);
			perror (b);
			exit(1);
		}
	if (flagr)
		if ((in = fopen(infile, "rb")) == NULL) {
			char b[BUFSIZ];
			sprintf(b, "Cannot open input file %s. Exiting.\n", infile);
			perror (b);
			garbage_collector();
			exit(1);
		}
}
/*
 * Prints the fuzz string.
 * Fuzz string is composed by string_seed, with every byte permutated
 * by 13% probability on every iteration that is not the first.
 * With every 500 iterations, generates 10 random new characters and
 * adds them to the bottom of the string_seed.
 */
void printfuzz(unsigned int current_iter)
{
	/* current_iter is the current iteraction run on the command line.
	 * From the perspective of this software, it's the maximum number
	 * of iteration to execute.
	 */
	unsigned int	num_new_random_buffs = current_iter / 500;
	unsigned int	final_buff_len = string_seed_len + (num_new_random_buffs * 10) + 1;	// Allow for final "0x0A"
	int 			max_prob = RAND_MAX * 0.13;		// 13% probability
	int				change;

#ifdef DEBUG
	fprintf(stderr, "[DEBUG] Parses seed to change 13 percent of the characters\n");
#endif

	/* Prepares the required memory buffer		*/
	final_buffer = (unsigned char *)calloc (final_buff_len, 1);						// Create a buffer holding everything
	memcpy (final_buffer, string_seed, string_seed_len);							// First copy the string see in the buffer
	if (final_buff_len - string_seed_len > 0)
		if (randomstr(final_buffer + string_seed_len, final_buff_len - string_seed_len)) {	// creates random string and fills the buffer
			perror ("Cannot allocate memory for buffer. Exiting.\n");
			garbage_collector();
			exit(1);
		}
	/* Randomize the string "current_iter" times, with a probability "max_prob"		*/
	for (int j = 1; j <= current_iter; j++) {										// recurse all the iteractions
		for (int i = 0; i < final_buff_len; i ++) {
			change = rand();
			/* If we are in the 13%, we increment the ASCII value by one.	*/
			if (change <= max_prob) {
				(final_buffer [i]) ++;
				if (!flaga) {
					if (final_buffer [i] < 32)	// only uses printable ASCII, wraps around if out of range
						final_buffer [i] = 126;
					if (final_buffer [i] > 126)
						final_buffer [i] = 32;
				}
			}
		}
	}
	final_buffer [final_buff_len-1] = (unsigned char)0x0A;							// Always terminate with 0x0A

	putstr (final_buffer, (size_t)final_buff_len-1);
}

/*
 * Returns a random string of "string_len" size into buffer "pointer",
 * with characters matching the effective range requested by command
 * line parameters.
 */
int randomstr(void *pointer, size_t size)
{
	int				m, h;		/* first and last character			*/
	int				readnb, i, c;

	/*
	 * Every random character is of the form c = rand() % m + h 
	 */
	m = 1;
	h = 255;					/* Defaults, uses 1-255 			*/
	if (flag0) {
		m = 0;
		h = 255;				/* All ASCII, including 0, 0-255 	*/
	}
	if (!flaga) {
		m = 32;
		h = 95 + (flag0!=0); 	/* Only uses printables, 32 to 126 	*/
	}

	if ((size <= 0U) || (size > BUFSIZ))
		return 1;

	for (i = 0; i < size; i++) {
        c = (int) (rand() % (h - m + 1)) + m;
		if (flag0 && !flaga && c == 127)
			c = 0;
		((char *)pointer) [i] = (char) c;
	}

	return 0;
}

void reseed(){
	if (!prng_seed)
		srand(time(NULL));
	else {
		if (prng_seed < 0) {
			char b[BUFSIZ];
			sprintf(b, "Wrong prng_seed provided: value %d is illegal. Exiting.", prng_seed);
			perror (b);
			exit(1);
		}
		srand(prng_seed);
	}
}

/*
 * Output a stream of bytes to STDOUT - with delay, if required
 */
void putstr(unsigned char *_buf, size_t size)
{
	if (!isatty(fileno(stdout))) {
#ifdef DEBUG
		fprintf(stderr, "[DEBUG] Piping out fuzzed string to STDOUT: %*s\n", (int)size-1, _buf);
#endif
		if (write(fileno(stdout), _buf, size) != size) {
//		if (fwrite(_buf, sizeof(char), size, fileno(stdout)) != size) {
			perror("Cannot write output buffer to STDOUT. Exiting.\n");
			garbage_collector();
			exit(1);
		}
	} else {
#ifdef DEBUG
		fprintf(stderr, "[DEBUG] Printing out fuzzed string to file: %s %*s\n", outfile, (int)size-1, _buf);
#endif
		fprintf (stdout, "%*s", (int)size, _buf);
	}
	if (flago)
	{
		if (write(fileno(out), &_buf, size) != size) {
			char b[BUFSIZ];
			sprintf(b, "Cannot write fuzzed string to output file %s. Exiting.\n", outfile);
			perror (b);
			garbage_collector();
			exit(1);
		}
#ifdef DEBUG
	fprintf(stderr, "[DEBUG] Wrote: %u bytes to STDOUT\n", (int)size);
#endif
	}
	if (delay)
		usleep(delay);
}

/*
 * Output a byte to STDOUT - with delay, if required 
 */
void putch(char c)
{
	if (write(fileno(stdout), &c, 1) != 1) {
		perror("Cannot write output buffer. Exiting.");
		garbage_collector();
		exit(1);
	}
	if (flago)
		if (write(fileno(out), &c, 1) != 1) {
			char b[BUFSIZ];
			sprintf(b, "Cannot write output file %s. Exiting.\n", outfile);
			perror (b);
			garbage_collector();
			exit(1);
		}
	if (delay)
		usleep(delay);
}

/*
 * Replay characters from input file, char by char
 */
void replay()
{
	unsigned char	c;

	do {
		c = fgetc(in);
		if(feof(in))
			break;
		putch((char)c);
	} while (1);
}

/*
 * Close all file handles and release memory
 */
void garbage_collector()
{
	if (flago)
		if (fclose(out) == EOF) {
			char b[BUFSIZ];
			sprintf(b, "Cannot close output file %s. Exiting.\n", outfile);
			perror (b);
			if (string_seed)
				free (string_seed);
			if (final_buffer)
				free (final_buffer);
			exit(1);
		}
	if (flagr)
		if (fclose(in) == EOF) {
			char b[BUFSIZ];
			sprintf(b, "Cannot close input file %s. Exiting.\n", infile);
			perror (b);
			if (string_seed)
				free (string_seed);
			if (final_buffer)
				free (final_buffer);
			exit(1);
		}
	if (string_seed)
		free (string_seed);
	if (final_buffer)
		free (final_buffer);
}
