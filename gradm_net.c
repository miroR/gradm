#include "gradm.h"

void
add_role_allowed_ip(struct role_acl *role, __u32 addr, __u32 netmask)
{
	struct role_allowed_ip **roleipp;
	struct role_allowed_ip *roleip;

	roleip =
	    (struct role_allowed_ip *) calloc(1,
					      sizeof (struct role_allowed_ip));
	if (!roleip)
		failure("calloc");

	roleipp = &(role->allowed_ips);

	if (*roleipp)
		(*roleipp)->next = roleip;

	roleip->prev = *roleipp;

	roleip->addr = addr;
	roleip->netmask = netmask;

	*roleipp = roleip;

	return;
}

void
add_ip_acl(struct proc_acl *subject, __u8 mode, struct ip_acl *acl_tmp)
{
	struct ip_acl **ipp;
	struct ip_acl *p;
	int i;

	if (!subject) {
		fprintf(stderr, "Error on line %lu of %s.\n  Definition "
			"of an IP ACL without a subject definition.\n"
			"The ACL system will not be allowed to be "
			"enabled until this problem is fixed.\n",
			lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	ipp = &(subject->ip_object);

	p = (struct ip_acl *) calloc(1, sizeof (struct ip_acl));
	if (!p)
		failure("calloc");

	if (*ipp)
		(*ipp)->next = p;

	p->prev = *ipp;

	p->mode = mode;
	p->addr = acl_tmp->addr;
	p->netmask = acl_tmp->netmask;
	p->low = acl_tmp->low;
	p->high = acl_tmp->high;
	memcpy(p->proto, acl_tmp->proto, sizeof (acl_tmp->proto));
	p->type = acl_tmp->type;

	for (i = 0; i < 8; i++)
		subject->ip_proto[i] |= p->proto[i];
	subject->ip_type |= p->type;

	*ipp = p;

	return;
}

__u32
get_ip(char *ip)
{
	struct in_addr address;

	if (!inet_aton(ip, &address)) {
		fprintf(stderr, "Invalid IP on line %lu of %s.\n", lineno,
			current_acl_file);
		exit(EXIT_FAILURE);
	}

	return address.s_addr;
}

void
conv_name_to_type(struct ip_acl *ip, char *name)
{
	struct protoent *proto;
	unsigned short i;

	if (!strcmp(name, "raw_proto"))
		ip->proto[IPPROTO_RAW / 32] |= (1 << (IPPROTO_RAW % 32));
	else if (!strcmp(name, "raw_sock"))
		ip->type |= (1 << SOCK_RAW);
	else if (!strcmp(name, "any_sock")) {
		ip->type = ~0;
		ip->type &= ~(1 << 0);	// there is no sock type 0
	} else if (!strcmp(name, "any_proto")) {
		for (i = 0; i < 8; i++)
			ip->proto[i] = ~0;
	} else if (!strcmp(name, "stream"))
		ip->type |= (1 << SOCK_STREAM);
	else if (!strcmp(name, "dgram"))
		ip->type |= (1 << SOCK_DGRAM);
	else if (!strcmp(name, "rdm"))
		ip->type |= (1 << SOCK_RDM);
	else if (!strcmp(name, "tcp")) {	// silly protocol 0
		ip->proto[IPPROTO_IP / 32] |= (1 << (IPPROTO_IP % 32));
		ip->proto[IPPROTO_TCP / 32] |= (1 << (IPPROTO_TCP % 32));
	} else if (!strcmp(name, "udp")) {	// silly protocol 0
		ip->proto[IPPROTO_IP / 32] |= (1 << (IPPROTO_IP % 32));
		ip->proto[IPPROTO_UDP / 32] |= (1 << (IPPROTO_UDP % 32));
	} else if ((proto = getprotobyname(name)))
		ip->proto[proto->p_proto / 32] |= (1 << (proto->p_proto % 32));
	else {
		fprintf(stderr, "Invalid type/protocol: %s\n", name);
		exit(EXIT_FAILURE);
	}
	return;
}
