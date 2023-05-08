/*
 * parallel tcp port scanner
 *
 * TODO: make netscan.c:/^iodialt use scan->clone
 */
#include <u.h>
#include <libc.h>
#include <thread.h>
#include <bio.h>
#include <ndb.h>

typedef struct scan scan;
typedef struct toscan toscan;

struct scan
{
	char	clone[NETPATHLEN];
	char	proto[64];
	char	host[256];
	char	service[64];

	/* result */
	char	err[ERRMAX];
	int	waserror;
};

int	debug;
int	flagv;
int	flag6;
int	flagt;
char	*netmtpt = "/net";
long	nio;
Channel	*cin;
Channel	*cout;

/* global scanner state */
char	*theclone;
char	*thehost;
char	**theports;
int	thenports;

int timedout;

void
catch(void*, char *msg){
	timedout = 1;

	if(strcmp(msg, "alarm") == 0){
		noted(NCONT);
	}

	noted(NDFLT);
}

static long
iodialt(va_list *arg)
{
	int fd, ms, ret;
	scan *s;

	s = va_arg(*arg, scan*);
	ms = va_arg(*arg, int);

	threadsetname("iodialt %s!%s!%s", s->proto, s->host, s->service);

	timedout = 0;
	ret = 0;

	notify(catch);
	alarm(ms);

	fd = open(theclone, ORDWR);
	if(fd < 0)
		sysfatal("open: %r");
	if(fprint(fd, "connect %s!%s", s->host, s->service) < 0)
		ret = -1;

	alarm(0);
	if(timedout)
		werrstr("connection timed out");

	close(fd);
	return ret;
}

void
scanner(void *)
{
	void *p;
	char addr[256];
	scan *s;
	Ioproc *io;

	io = ioproc();

	while(recv(cin, &p) > 0){
		s = p;

		threadsetname("scanner %s", addr);

		if(iocall(io, iodialt, s, flagt) < 0){
			s->waserror = 1;
			errstr(s->err, ERRMAX);
		} else {
			s->waserror = 0;
			s->err[0] = 0;
		}

		if(sendp(cout, s) < 0)
			break;

		threadsetname("scanner idle");
	}

	closeioproc(io);

	adec(&nio);

	threadexits(nil);
}

void
initscan(void)
{
	int i;

	cin = chancreate(sizeof(scan*), 0);
	cout = chancreate(sizeof(scan*), 10);

	for(i = 0; i < nio; i++){
		threadcreate(scanner, nil, 8192);
	}
}

void
produce(void*)
{
	int i;
	scan *res;

	threadsetname("producer");

	for(i = 0; i < thenports; i++){
		res = mallocz(sizeof(scan), 1);
		snprint(res->proto, sizeof(res->proto), "%s", "tcp");
		snprint(res->host, sizeof(res->host), "%s", thehost);
		snprint(res->service, sizeof(res->service), "%s", theports[i]);
		sendp(cin, res);
	}

	chanclose(cin);
	threadexits(nil);
}

void
doscan(void)
{
	int i;
	scan *res;
	threadcreate(produce, nil, 8192);

	for(i = 0; i < thenports; i++){
		if((res = recvp(cout)) == nil)
			break;

		if(res->waserror == 0)
			print("%s!%s!%-5s open\n", res->proto, res->host, res->service);
		else if(flagv)
			print("%s!%s!%-5s closed %s\n", res->proto, res->host, res->service, res->err);

		free(res);
	}
}

void
usage(void)
{
	fprint(2, "%s [-6v] [-t timeoutms] [-n niothread] [-x netmtpt] host [port ...]\n", argv0);
	threadexitsall("usage");
}

void
threadmain(int argc, char *argv[])
{
	int defports[] = { 7, 9, 21, 22, 23, 25, 80, 110, 143, 443, 564, 567, 993, 995, 5356, 8080, 17007, 17009, 17010 };
	int fd, i;
	char *f[3], buf[256];

	debug = 0;
	flagv = 0;
	flag6 = 0;
	flagt = 5000;
	nio = 10;

	ARGBEGIN{
	case 'd':
		debug = 1;
		break;
	case 'v':
		flagv = 1;
		break;
	case '6':
		flag6 = 1;
		break;
	case 't':
		if((flagt = atoi(EARGF(usage()))) < 0)
			usage();
		break;
	case 'n':
		if((nio = atoi(EARGF(usage()))) < 1)
			usage();
		break;
	case 'x':
		netmtpt = EARGF(usage());
		break;
	default:
		fprint(2, "unknown flag -%c\n", ARGC());
		usage();
	}ARGEND

	if(argc < 1)
		usage();

	if(argc == 1){
		/* default port list */
		thenports = nelem(defports);
		theports = mallocz(thenports * sizeof(char*), 1);
		for(i = 0; i < nelem(defports); i++)
			theports[i] = smprint("%d", defports[i]);
	} else {
		thenports = argc-1;
		theports = mallocz(thenports * sizeof(char*), 1);
		for(i = 0; i < argc-1; i++)
			theports[i] = strdup(argv[i+1]);
	}

	if(thenports < nio)
		nio = thenports;

	/* resolve host */
	snprint(buf, sizeof(buf), "%s/cs", netmtpt);
	if((fd = open(buf, ORDWR)) < 0)
		sysfatal("open: %r");

	snprint(buf, sizeof(buf), "tcp!%s!0", argv[0]);
	if(write(fd, buf, strlen(buf)) < 0)
		sysfatal("write: %r");

	seek(fd, 0, 0);
	if((i = read(fd, buf, sizeof(buf)-1)) < 0)
		sysfatal("read: %r");

	buf[i] = 0;
	if(getfields(buf, f, 3, 1, " !") < 2)
		sysfatal("bad cs fields");

	theclone = smprint("%s/%s/clone", netmtpt, "tcp");
	thehost = strdup(f[1]);

	if(flagv)
		fprint(2, "dialing %s through %s\n", thehost, theclone);

	initscan();
	doscan();

	while(nio > 0)
		yield();

	threadexitsall(nil);
}
