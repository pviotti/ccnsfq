#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "utils.h"
#include "tc_util.h"

struct tc_ccnsfq_qopt
{
	unsigned	quantum;	/* Bytes per round allocated to flow */
	int		perturb_period;	/* Period of hash perturbation */
	__u32		limit;		/* Maximal packets in queue */
	unsigned	divisor;	/* Hash divisor  */
	unsigned	flows;		/* Maximal number of flows  */
};

struct tc_ccnsfq_xstats
{
	__s32		allot;
};


static void explain(void)
{
	fprintf(stderr, "Usage: ... ccnsfq [ limit NUMBER ] [ perturb SECS ] [ quantum BYTES ]\n");
}

#define usage() return(-1)

static int ccnsfq_parse_opt(struct qdisc_util *qu, int argc, char **argv, struct nlmsghdr *n)
{
	int ok=0;
	struct tc_ccnsfq_qopt opt;

	memset(&opt, 0, sizeof(opt));

	while (argc > 0) {
		if (strcmp(*argv, "quantum") == 0) {
			NEXT_ARG();
			if (get_size(&opt.quantum, *argv)) {
				fprintf(stderr, "Illegal \"limit\"\n");
				return -1;
			}
			ok++;
		} else if (strcmp(*argv, "perturb") == 0) {
			NEXT_ARG();
			if (get_integer(&opt.perturb_period, *argv, 0)) {
				fprintf(stderr, "Illegal \"perturb\"\n");
				return -1;
			}
			ok++;
		} else if (strcmp(*argv, "limit") == 0) {
			NEXT_ARG();
			if (get_u32(&opt.limit, *argv, 0)) {
				fprintf(stderr, "Illegal \"limit\"\n");
				return -1;
			}
			if (opt.limit < 2) {
				fprintf(stderr, "Illegal \"limit\", must be > 1\n");
				return -1;
			}
			ok++;
		} else if (strcmp(*argv, "help") == 0) {
			explain();
			return -1;
		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			explain();
			return -1;
		}
		argc--; argv++;
	}

	if (ok)
		addattr_l(n, 1024, TCA_OPTIONS, &opt, sizeof(opt));
	return 0;
}

static int ccnsfq_print_opt(struct qdisc_util *qu, FILE *f, struct rtattr *opt)
{
	struct tc_ccnsfq_qopt *qopt;
	SPRINT_BUF(b1);

	if (opt == NULL)
		return 0;

	if (RTA_PAYLOAD(opt)  < sizeof(*qopt))
		return -1;
	qopt = RTA_DATA(opt);
	fprintf(f, "limit %up ", qopt->limit);
	fprintf(f, "quantum %s ", sprint_size(qopt->quantum, b1));
	if (show_details) {
		fprintf(f, "flows %u/%u ", qopt->flows, qopt->divisor);
	}
	if (qopt->perturb_period)
		fprintf(f, "perturb %dsec ", qopt->perturb_period);
	return 0;
}

static int ccnsfq_print_xstats(struct qdisc_util *qu, FILE *f, struct rtattr *xstats)
{
	return 0;
}

struct qdisc_util ccnsfq_qdisc_util = {
	.id		= "ccnsfq",
	.parse_qopt	= ccnsfq_parse_opt,
	.print_qopt	= ccnsfq_print_opt,
};
