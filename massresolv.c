/**
 * Simple Mass DNS PTR resolver
 *
 * Author: Pantelis Roditis <proditis]at[echothrust.com>
 * indent: indent -orig -bl -bli0 -ts 4 massresolv-1.1.c
 * $Id: massresolv-1.1.c,v 1.1 1999/01/23 13:19:12 databus Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <resolv.h>
extern struct __res_state _res;

int             MAXCHILD = 150;
int             children = 0;

void
usage(char *arg)
{
	fprintf(stderr, "----mass dns resolver------\n");
	fprintf(stderr, "\tfrom r00thell.org\n");
	fprintf(stderr,
			"usage: %s start_ip end_ip [ipofdnsserver] [MAXCHILD]\n", arg);
	fprintf(stderr, "eg: %s 192.168.1.1 192.168.1.255 192.168.1.254 50\n",
			arg);
}

int
main(int argc, char **argv)
{
	unsigned long    burp, startip = 0l, endip = 0l,	temp = 0l,i = 0l,	dns = 0l;
	struct hostent  *hp;
	struct in_addr  *ini;
	char           **p;

  /* We need at least 2 arguments (start/end ip) */
	if (argc < 3)
	{
		usage(argv[0]);
		exit(0);
	}

  /* Check if IP's are parsable */
	if ((int) (startip = inet_addr(argv[1])) == -1
		|| (int) (endip = inet_addr(argv[2])) == -1)
	{
		(void) printf("IP-address must be of the form a.b.c.d\n");
		usage(argv[0]);
		exit(2);
	}

  // Set MAXCHILD if user provided a 4th parameter
  if (argc == 4)
	{
		MAXCHILD = atoi(argv[3]);
	}

  startip = htonl(startip);
	endip = htonl(endip);

  memset(&_res, 0x0, sizeof(_res));
	// Initialize resolver
	res_init();

	// RESET LOCAL OPTIONS
	_res.options = 0;
  // TURN OFF DNSSEARCH and DEFNAMES
	_res.options &= ~(RES_DNSRCH | RES_DEFNAMES);
	// TURN ON INSECURE1
  _res.options |= RES_INSECURE1;
  // TURN ON INSECURE1
	_res.options |= RES_INSECURE2;
  // USE TCP
	_res.options |= RES_USEVC;
  // TURN ON RECURSE
	_res.options |= RES_RECURSE;

  sethostent(1);
	setnetent(0);

#ifdef DEBUG
	printf("System DNS Server(s): ");
	for (int i = 0; i < _res.nscount; i++)
		printf("%s", inet_ntoa(_res.nsaddr_list[i].sin_addr));
	putchar('\n');
#endif

	if (argv[3] != NULL && (dns = inet_addr(argv[3])) != -1)
	{
    // SET DNS SERVER ADDR
    (void) memcpy((void *) &_res.nsaddr_list[0].sin_addr,
					  &dns, sizeof(dns));
		_res.nscount = 1;
	}
#ifdef DEBUG
	printf("Switching to DNS: %s\n",
		   inet_ntoa(_res.nsaddr_list[0].sin_addr));
#endif



	// find out the last and the first and fix the order dude
	if (endip < startip)
	{
		temp = startip;
		startip = endip;
		endip = temp;
	}
	/*
	 * yeap this here really works
	 */
	for (i = startip; i <= endip; i++)
	{

		burp = ntohl(i);
		if (children >= MAXCHILD)
		{
			wait(NULL);
			children--;
		}
		switch (fork())
		{
		case 0:
			hp = gethostbyaddr((void *) &burp, sizeof(burp), AF_INET);
			/* check if we got an answer */
			if (hp != NULL)
			{
				for (p = hp->h_addr_list; *p != 0; p++)
				{
					struct in_addr  in;
					char          **q;
					(void) memcpy(&in.s_addr, *p, sizeof(in.s_addr));

					// Print ip and resolved name
					(void) printf("%s\t%s", inet_ntoa(in), hp->h_name);

					// Start printing the aliases (if any)
					for (q = hp->h_aliases; *q != 0; q++)
						(void) printf(" %s", *q);

					(void) putchar('\n');
				}
			}
			exit(0);
    // Fork failed
		case -1:
			printf("fork() burrrrpppp\n");
			exit(-1);
		default:
			children++;
			break;
		}
	}
	while (children--)
	{
		wait(NULL);
	}

	exit(0);
}
