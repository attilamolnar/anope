/* inspircd 1.2 functions
 *
 * (C) 2003-2010 Anope Team
 * Contact us at team@anope.org
 *
 * Please read COPYING and README for further details.
 *
 * Based on the original code of Epona by Lara.
 * Based on the original code of Services by Andy Church.
 *
 *
 */

/*************************************************************************/

#include "services.h"
#include "pseudo.h"
#include "hashcomp.h"

#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#ifdef _WIN32
#include <winsock.h>
int inet_aton(const char *name, struct in_addr *addr)
{
	uint32 a = inet_addr(name);
	addr->s_addr = a;
	return a != (uint32) - 1;
}
#endif

IRCDVar myIrcd[] = {
	{"InspIRCd 2.0",			/* ircd name */
	 "+I",					  /* Modes used by pseudoclients */
	 5,						 /* Chan Max Symbols	 */
	 "+ao",					 /* Channel Umode used by Botserv bots */
	 1,						 /* SVSNICK */
	 1,						 /* Vhost  */
	 0,						 /* Supports SGlines	 */
	 1,						 /* Supports SQlines	 */
	 1,						 /* Supports SZlines	 */
	 4,						 /* Number of server args */
	 0,						 /* Join 2 Set		   */
	 0,						 /* Join 2 Message	   */
	 1,						 /* TS Topic Forward	 */
	 0,						 /* TS Topci Backward	*/
	 0,						 /* Chan SQlines		 */
	 0,						 /* Quit on Kill		 */
	 0,						 /* SVSMODE unban		*/
	 1,						 /* Reverse			  */
	 1,						 /* vidents			  */
	 1,						 /* svshold			  */
	 0,						 /* time stamp on mode   */
	 0,						 /* NICKIP			   */
	 0,						 /* O:LINE			   */
	 1,						 /* UMODE			   */
	 1,						 /* VHOST ON NICK		*/
	 0,						 /* Change RealName	  */
	 1,						 /* No Knock requires +i */
	 0,						 /* We support inspircd TOKENS */
	 0,						 /* TIME STAMPS are BASE64 */
	 0,						 /* Can remove User Channel Modes with SVSMODE */
	 0,						 /* Sglines are not enforced until user reconnects */
	 1,						 /* ts6 */
	 0,						 /* p10 */
	 1,						 /* CIDR channelbans */
	 "$",					   /* TLD Prefix for Global */
	 20,					/* Max number of modes we can send per line */
	 }
	,
	{NULL}
};

static int has_servicesmod = 0;
static int has_svsholdmod = 0;
static int has_chghostmod = 0;
static int has_chgidentmod = 0;

/* Previously introduced user during burst */
static User *prev_u_intro = NULL;

/* CHGHOST */
void inspircd_cmd_chghost(const char *nick, const char *vhost)
{
	if (has_chghostmod != 1)
	{
		ircdproto->SendGlobops(findbot(Config.s_OperServ), "CHGHOST not loaded!");
		return;
	}

	BotInfo *bi = findbot(Config.s_OperServ);
	send_cmd(bi->uid, "CHGHOST %s %s", nick, vhost);
}

int anope_event_idle(const char *source, int ac, const char **av)
{
	BotInfo *bi = findbot(av[0]);
	if (!bi)
		return MOD_CONT;

	send_cmd(bi->uid, "IDLE %s %ld %ld", source, static_cast<long>(start_time), static_cast<long>(time(NULL) - bi->lastmsg));
	return MOD_CONT;
}

static char currentpass[1024];

/* PASS */
void inspircd_cmd_pass(const char *pass)
{
	strlcpy(currentpass, pass, sizeof(currentpass));
}


class InspIRCdProto : public IRCDProto
{
	void SendAkillDel(Akill *ak)
	{
		BotInfo *bi = findbot(Config.s_OperServ);
		send_cmd(bi->uid, "GLINE %s@%s", ak->user, ak->host);
	}

	void SendTopic(BotInfo *whosets, Channel *c, const char *whosetit, const char *topic)
	{
		send_cmd(whosets->uid, "FTOPIC %s %lu %s :%s", c->name.c_str(), static_cast<unsigned long>(c->topic_time), whosetit, topic);
	}

	void SendVhostDel(User *u)
	{
		if (u->HasMode(UMODE_CLOAK))
			inspircd_cmd_chghost(u->nick.c_str(), u->chost.c_str());
		else
			inspircd_cmd_chghost(u->nick.c_str(), u->host);

		if (has_chgidentmod && u->GetIdent() != u->GetVIdent())
		{
			inspircd_cmd_chgident(u->nick.c_str(), u->GetIdent().c_str());
		}
	}

	void SendAkill(Akill *ak)
	{
		// Calculate the time left before this would expire, capping it at 2 days
		time_t timeleft = ak->expires - time(NULL);
		if (timeleft > 172800 || !ak->expires)
			timeleft = 172800;
		BotInfo *bi = findbot(Config.s_OperServ);
		send_cmd(bi->uid, "ADDLINE G %s@%s %s %ld %ld :%s", ak->user, ak->host, ak->by, static_cast<long>(time(NULL)), static_cast<long>(timeleft), ak->reason);
	}

	void SendSVSKillInternal(BotInfo *source, User *user, const char *buf)
	{
		send_cmd(source ? source->uid : TS6SID, "KILL %s :%s", user->GetUID().c_str(), buf);
	}

	void SendSVSMode(User *u, int ac, const char **av)
	{
		this->SendModeInternal(NULL, u, merge_args(ac, av));
	}

	void SendNumericInternal(const char *source, int numeric, const char *dest, const char *buf)
	{
		send_cmd(TS6SID, "PUSH %s ::%s %03d %s %s", dest, source, numeric, dest, buf);
	}

	void SendGuestNick(const char *nick, const char *user, const char *host, const char *real, const char *modes)
	{
		send_cmd(TS6SID, "UID %ld %s %s %s %s +%s 0.0.0.0 :%s", static_cast<long>(time(NULL)), nick, host, host, user, modes, real);
	}

	void SendModeInternal(BotInfo *source, Channel *dest, const char *buf)
	{
		send_cmd(source ? source->uid : TS6SID, "FMODE %s %u %s", dest->name.c_str(), static_cast<unsigned>(dest->creation_time), buf);
	}

	void SendModeInternal(BotInfo *bi, User *u, const char *buf)
	{
		if (!buf) return;
		send_cmd(bi ? bi->uid : TS6SID, "MODE %s %s", u->GetUID().c_str(), buf);
	}

	void SendClientIntroduction(const std::string &nick, const std::string &user, const std::string &host, const std::string &real, const char *modes, const std::string &uid)
	{
		send_cmd(TS6SID, "UID %s %ld %s %s %s %s 0.0.0.0 %ld %s :%s", uid.c_str(), static_cast<long>(time(NULL)), nick.c_str(), host.c_str(), host.c_str(), user.c_str(), static_cast<long>(time(NULL)), modes, real.c_str());
	}

	void SendKickInternal(BotInfo *source, Channel *chan, User *user, const char *buf)
	{
		if (buf)
			send_cmd(source->uid, "KICK %s %s :%s", chan->name.c_str(), user->GetUID().c_str(), buf);
		else
			send_cmd(source->uid, "KICK %s %s :%s", chan->name.c_str(), user->GetUID().c_str(), user->nick.c_str());
	}

	void SendNoticeChanopsInternal(BotInfo *source, Channel *dest, const char *buf)
	{
		send_cmd(TS6SID, "NOTICE @%s :%s", dest->name.c_str(), buf);
	}

	/* SERVER services-dev.chatspike.net password 0 :Description here */
	void SendServer(Server *server)
	{
		send_cmd(NULL, "SERVER %s %s %d %s :%s", server->name, currentpass, server->hops, server->suid, server->desc);
	}

	/* JOIN */
	void SendJoin(BotInfo *user, const char *channel, time_t chantime)
	{
		send_cmd(TS6SID, "FJOIN %s %ld + :,%s", channel, static_cast<long>(chantime), user->uid.c_str());
	}

	/* UNSQLINE */
	void SendSQLineDel(const std::string &user)
	{
		if (user.empty())
			return;
		send_cmd(TS6SID, "DELLINE Q %s", user.c_str());
	}

	/* SQLINE */
	void SendSQLine(const std::string &mask, const std::string &reason)
	{
		if (mask.empty() || reason.empty())
			return;
		send_cmd(TS6SID, "ADDLINE Q %s %s %ld 0 :%s", mask.c_str(), Config.s_OperServ, static_cast<long>(time(NULL)), reason.c_str());
	}

	/* SQUIT */
	void SendSquit(const char *servname, const char *message)
	{
		send_cmd(TS6SID, "SQUIT %s :%s", servname, message);
	}

	/* Functions that use serval cmd functions */

	void SendVhost(User *u, const std::string &vIdent, const std::string &vhost)
	{
		if (!vIdent.empty())
			inspircd_cmd_chgident(u->nick.c_str(), vIdent.c_str());
		if (!vhost.empty())
			inspircd_cmd_chghost(u->nick.c_str(), vhost.c_str());
	}

	void SendConnect()
	{
		send_cmd(NULL, "CAPAB START 1202");
		send_cmd(NULL, "CAPAB CAPABILITIES :PROTOCOL=1202");
		send_cmd(NULL, "CAPAB END");
		inspircd_cmd_pass(uplink_server->password);
		me_server = new_server(NULL, Config.ServerName, Config.ServerDesc, SERVER_ISME, TS6SID);
		SendServer(me_server);
		send_cmd(TS6SID, "BURST");
		send_cmd(TS6SID, "VERSION :Anope-%s %s :%s - %s (%s) -- %s", version_number, Config.ServerName, ircd->name, version_flags, Config.EncModuleList.begin()->c_str(), version_build);
	}

	/* CHGIDENT */
	void inspircd_cmd_chgident(const char *nick, const char *vIdent)
	{
		if (has_chgidentmod == 0)
		{
			ircdproto->SendGlobops(findbot(Config.s_OperServ), "CHGIDENT not loaded!");
		}
		else
		{
			BotInfo *bi = findbot(Config.s_OperServ);
			send_cmd(bi->uid, "CHGIDENT %s %s", nick, vIdent);
		}
	}

	/* SVSHOLD - set */
	void SendSVSHold(const char *nick)
	{
		BotInfo *bi = findbot(Config.s_OperServ);
		send_cmd(bi->uid, "SVSHOLD %s %u :%s", nick, static_cast<unsigned>(Config.NSReleaseTimeout), "Being held for registered user");
	}

	/* SVSHOLD - release */
	void SendSVSHoldDel(const char *nick)
	{
		BotInfo *bi = findbot(Config.s_OperServ);
		send_cmd(bi->uid, "SVSHOLD %s", nick);
	}

	/* UNSZLINE */
	void SendSZLineDel(SXLine *sx)
	{
		send_cmd(TS6SID, "DELLINE Z %s", sx->mask);
	}

	/* SZLINE */
	void SendSZLine(SXLine *sx)
	{
		send_cmd(TS6SID, "ADDLINE Z %s %s %ld 0 :%s", sx->mask, sx->by, static_cast<long>(time(NULL)), sx->reason);
	}

	/* SVSMODE -r */
	void SendUnregisteredNick(User *u)
	{
		u->RemoveMode(findbot(Config.s_NickServ), UMODE_REGISTERED);
	}

	void SendSVSJoin(const char *source, const char *nick, const char *chan, const char *param)
	{
		User *u = finduser(nick);
		BotInfo *bi = findbot(source);
		send_cmd(bi->uid, "SVSJOIN %s %s", u->GetUID().c_str(), chan);
	}

	void SendSVSPart(const char *source, const char *nick, const char *chan)
	{
		User *u = finduser(nick);
		BotInfo *bi = findbot(source);
		send_cmd(bi->uid, "SVSPART %s %s", u->GetUID().c_str(), chan);
	}

	void SendSWhois(const char *source, const char *who, const char *mask)
	{
		User *u = finduser(who);

		send_cmd(TS6SID, "METADATA %s swhois :%s", u->GetUID().c_str(), mask);
	}

	void SendEOB()
	{
		send_cmd(TS6SID, "ENDBURST");
	}

	void SendGlobopsInternal(BotInfo *source, const char *buf)
	{
		send_cmd(source ? source->uid : TS6SID, "SNONOTICE g :%s", buf);
	}

	void SendAccountLogin(User *u, NickCore *account)
	{
		send_cmd(TS6SID, "METADATA %s accountname :%s", u->GetUID().c_str(), account->display);
	}

	void SendAccountLogout(User *u, NickCore *account)
	{
		send_cmd(TS6SID, "METADATA %s accountname :", u->GetUID().c_str());
	}

	int IsNickValid(const char *nick)
	{
		/* InspIRCd, like TS6, uses UIDs on collision, so... */
		if (isdigit(*nick))
			return 0;
		return 1;
	}

	void SetAutoIdentificationToken(User *u)
	{
		if (!u->Account())
			return;

		u->SetMode(findbot(Config.s_NickServ), UMODE_REGISTERED);
	}

} ircd_proto;






int anope_event_ftopic(const char *source, int ac, const char **av)
{
	/* :source FTOPIC channel ts setby :topic */
	const char *temp;
	if (ac < 4)
		return MOD_CONT;
	temp = av[1];			   /* temp now holds ts */
	av[1] = av[2];			  /* av[1] now holds set by */
	av[2] = temp;			   /* av[2] now holds ts */
	do_topic(source, ac, av);
	return MOD_CONT;
}

int anope_event_mode(const char *source, int ac, const char **av)
{
	if (*av[0] == '#' || *av[0] == '&')
	{
		do_cmode(source, ac, av);
	}
	else
	{
		/* InspIRCd lets opers change another
		   users modes, we have to kludge this
		   as it slightly breaks RFC1459
		 */
		User *u = find_byuid(source);
		User *u2 = find_byuid(av[0]);

		// This can happen with server-origin modes.
		if (u == NULL)
			u = u2;

		// if it's still null, drop it like fire.
		// most likely situation was that server introduced a nick which we subsequently akilled
		if (u == NULL)
			return MOD_CONT;

		av[0] = u2->nick.c_str();
		do_umode(u->nick.c_str(), ac, av);
	}
	return MOD_CONT;
}

int anope_event_opertype(const char *source, int ac, const char **av)
{
	/* opertype is equivalent to mode +o because servers
	   dont do this directly */
	User *u;
	u = finduser(source);
	if (u && !is_oper(u)) {
		const char *newav[2];
		newav[0] = source;
		newav[1] = "+o";
		return anope_event_mode(source, 2, newav);
	} else
		return MOD_CONT;
}

int anope_event_fmode(const char *source, int ac, const char **av)
{
	const char *newav[128];
	int n, o;
	Channel *c;

	/* :source FMODE #test 12345678 +nto foo */
	if (ac < 3)
		return MOD_CONT;

	/* Checking the TS for validity to avoid desyncs */
	if ((c = findchan(av[0]))) {
		if (c->creation_time > strtol(av[1], NULL, 10)) {
			/* Our TS is bigger, we should lower it */
			c->creation_time = strtol(av[1], NULL, 10);
		} else if (c->creation_time < strtol(av[1], NULL, 10)) {
			/* The TS we got is bigger, we should ignore this message. */
			return MOD_CONT;
		}
	} else {
		/* Got FMODE for a non-existing channel */
		return MOD_CONT;
	}

	/* TS's are equal now, so we can proceed with parsing */
	n = o = 0;
	while (n < ac) {
		if (n != 1) {
			newav[o] = av[n];
			o++;
			Alog(LOG_DEBUG) << "Param: " << newav[o - 1];
		}
		n++;
	}

	return anope_event_mode(source, ac - 1, newav);
}

/*
 * [Nov 03 22:31:57.695076 2009] debug: Received: :964 FJOIN #test 1223763723 +BPSnt :,964AAAAAB ,964AAAAAC ,966AAAAAA
 *
 * 0: name
 * 1: channel ts (when it was created, see protocol docs for more info)
 * 2: channel modes + params (NOTE: this may definitely be more than one param!)
 * last: users
 */
int anope_event_fjoin(const char *source, int ac, const char **av)
{
	Channel *c = findchan(av[0]);
	time_t ts = atol(av[1]);
	bool was_created = false;
	bool keep_their_modes = true;

	if (!c)
	{
		c = new Channel(av[0], ts);
		was_created = true;
	}
	/* Our creation time is newer than what the server gave us */
	else if (c->creation_time > ts)
	{
		c->creation_time = ts;

		/* Remove status from all of our users */
		for (CUserList::iterator it = c->users.begin(); it != c->users.end(); ++it)
		{
			UserContainer *uc = *it;

			c->RemoveMode(NULL, CMODE_OWNER, uc->user->nick);
			c->RemoveMode(NULL, CMODE_PROTECT, uc->user->nick);
			c->RemoveMode(NULL, CMODE_OP, uc->user->nick);
			c->RemoveMode(NULL, CMODE_HALFOP, uc->user->nick);
			c->RemoveMode(NULL, CMODE_VOICE, uc->user->nick);
		}
		if (c->ci)
		{
			/* Rejoin the bot to fix the TS */
			if (c->ci->bi)
			{
				ircdproto->SendPart(c->ci->bi, c, "TS reop");
				bot_join(c->ci);
			}
			/* Reset mlock */
			check_modes(c);
		}
	}
	/* Their TS is newer than ours, our modes > theirs, unset their modes if need be */
	else
		keep_their_modes = false;
	
	/* Mark the channel as syncing */
	if (was_created)
		c->SetFlag(CH_SYNCING);
	
	/* If we need to keep their modes, and this FJOIN string contains modes */
	if (keep_their_modes && ac >= 4)
	{
		/* Set the modes internally */
		ChanSetInternalModes(c, ac - 3, av + 2);
	}

	spacesepstream sep(av[ac - 1]);
	std::string buf;
	while (sep.GetToken(buf))
	{
		std::list<ChannelMode *> Status;
		Status.clear();

		/* Loop through prefixes and find modes for them */
		while (buf[0] != ',')
		{
			ChannelMode *cm = ModeManager::FindChannelModeByChar(buf[0]);
			if (!cm)
			{
				Alog() << "Recieved unknown mode prefix " << buf[0] << " in FJOIN string";
				buf.erase(buf.begin());
				continue;
			}

			buf.erase(buf.begin());
			Status.push_back(cm);
		}
		buf.erase(buf.begin());

		User *u = find_byuid(buf);
		if (!u)
		{
			Alog(LOG_DEBUG) << "FJOIN for nonexistant user " << buf << " on " << c->name;
			continue;
		}

		EventReturn MOD_RESULT;
		FOREACH_RESULT(I_OnPreJoinChannel, OnPreJoinChannel(u, c));

		/* Add the user to the channel */
		c->JoinUser(u);

		/* Update their status internally on the channel
		 * This will enforce secureops etc on the user
		 */
		for (std::list<ChannelMode *>::iterator it = Status.begin(); it != Status.end(); ++it)
		{
			c->SetModeInternal(*it, buf);
		}

		/* Now set whatever modes this user is allowed to have on the channel */
		chan_set_correct_modes(u, c, 1);

		/* Check to see if modules want the user to join, if they do
		 * check to see if they are allowed to join (CheckKick will kick/ban them)
		 * Don't trigger OnJoinChannel event then as the user will be destroyed
		 */
		if (MOD_RESULT != EVENT_STOP && c->ci && c->ci->CheckKick(u))
			continue;

		FOREACH_MOD(I_OnJoinChannel, OnJoinChannel(u, c));
	}

	/* Channel is done syncing */
	if (was_created)
	{
		/* Unset the syncing flag */
		c->UnsetFlag(CH_SYNCING);

		/* If there are users in the channel they are allowed to be, set topic mlock etc */
		if (!c->users.empty())
			c->Sync();
		/* If there are no users in the channel, there is a ChanServ timer set to part the service bot
		 * and destroy the channel soon
		 */
	}
	
	return MOD_CONT;
}

/* Events */
int anope_event_ping(const char *source, int ac, const char **av)
{
	if (ac == 1)
		ircdproto->SendPong(NULL, av[0]);

	if (ac == 2)
		ircdproto->SendPong(av[1], av[0]);

	return MOD_CONT;
}

int anope_event_time(const char *source, int ac, const char **av)
{
	if (ac !=2)
		return MOD_CONT;

	send_cmd(TS6SID, "TIME %s %s %ld", source, av[1], static_cast<long>(time(NULL)));

	/* We handled it, don't pass it on to the core..
	 * The core doesn't understand our syntax anyways.. ~ Viper */
	return MOD_STOP;
}

int anope_event_436(const char *source, int ac, const char **av)
{
	m_nickcoll(av[0]);
	return MOD_CONT;
}

int anope_event_away(const char *source, int ac, const char **av)
{
	m_away(source, (ac ? av[0] : NULL));
	return MOD_CONT;
}

/* Taken from hybrid.c, topic syntax is identical */
int anope_event_topic(const char *source, int ac, const char **av)
{
	Channel *c = findchan(av[0]);
	time_t topic_time = time(NULL);
	User *u = find_byuid(source);

	if (!c)
	{
		Alog(LOG_DEBUG) << "debug: TOPIC " << merge_args(ac - 1, av + 1) << " for nonexistent channel " << av[0];
		return MOD_CONT;
	}

	if (check_topiclock(c, topic_time))
		return MOD_CONT;

	if (c->topic) {
		delete [] c->topic;
		c->topic = NULL;
	}
	if (ac > 1 && *av[1])
		c->topic = sstrdup(av[1]);

	c->topic_setter = u ? u->nick : source;
	c->topic_time = topic_time;

	record_topic(av[0]);

	if (ac > 1 && *av[1]) {
		FOREACH_MOD(I_OnTopicUpdated, OnTopicUpdated(c, av[0]));
	}
	else {
		FOREACH_MOD(I_OnTopicUpdated, OnTopicUpdated(c, ""));
	}

	return MOD_CONT;
}

int anope_event_squit(const char *source, int ac, const char **av)
{
	do_squit(source, ac, av);
	return MOD_CONT;
}

int anope_event_rsquit(const char *source, int ac, const char **av)
{
	/* On InspIRCd we must send a SQUIT when we recieve RSQUIT for a server we have juped */
	Server *s = findserver(servlist, av[0]);
	if (!s)
		s = findserver_uid(servlist, av[0]);
	if (s && s->HasFlag(SERVER_JUPED))
	{
		send_cmd(TS6SID, "SQUIT %s :%s", s->suid, ac > 1 ? av[1] : "");
	}

	do_squit(source, ac, av);

	return MOD_CONT;
}

int anope_event_quit(const char *source, int ac, const char **av)
{
	do_quit(source, ac, av);
	return MOD_CONT;
}


int anope_event_kill(const char *source, int ac, const char **av)
{
	User *u = find_byuid(av[0]);
	BotInfo *bi = findbot(av[0]);
	m_kill(u ? u->nick.c_str() : (bi ? bi->nick : av[0]), av[1]);
	return MOD_CONT;
}

int anope_event_kick(const char *source, int ac, const char **av)
{
	do_kick(source, ac, av);
	return MOD_CONT;
}


int anope_event_join(const char *source, int ac, const char **av)
{
	do_join(source, ac, av);
	return MOD_CONT;
}

int anope_event_motd(const char *source, int ac, const char **av)
{
	m_motd(source);
	return MOD_CONT;
}

int anope_event_setname(const char *source, int ac, const char **av)
{
	User *u;

	u = finduser(source);
	if (!u)
	{
		Alog(LOG_DEBUG) << "SETNAME for nonexistent user " << source;
		return MOD_CONT;
	}

	u->SetRealname(av[0]);
	return MOD_CONT;
}

int anope_event_chgname(const char *source, int ac, const char **av)
{
	User *u;

	u = finduser(source);
	if (!u)
	{
		Alog(LOG_DEBUG) << "FNAME for nonexistent user " << source;
		return MOD_CONT;
	}

	u->SetRealname(av[0]);
	return MOD_CONT;
}

int anope_event_setident(const char *source, int ac, const char **av)
{
	User *u;

	u = finduser(source);
	if (!u)
	{
		Alog(LOG_DEBUG) << "SETIDENT for nonexistent user " << source;
		return MOD_CONT;
	}

	u->SetIdent(av[0]);
	return MOD_CONT;
}

int anope_event_chgident(const char *source, int ac, const char **av)
{
	User *u = finduser(source);

	if (!u)
	{
		Alog(LOG_DEBUG) << "FIDENT for nonexistent user " << source;
		return MOD_CONT;
	}

	u->SetIdent(av[0]);
	return MOD_CONT;
}

int anope_event_sethost(const char *source, int ac, const char **av)
{
	User *u;

	u = finduser(source);
	if (!u)
	{
		Alog(LOG_DEBUG) << "SETHOST for nonexistent user " << source;
		return MOD_CONT;
	}

	u->SetDisplayedHost(av[0]);
	return MOD_CONT;
}


int anope_event_nick(const char *source, int ac, const char **av)
{
	do_nick(source, av[0], NULL, NULL, NULL, NULL, 0, 0, NULL, NULL);
	return MOD_CONT;
}


/*
 * [Nov 03 22:09:58.176252 2009] debug: Received: :964 UID 964AAAAAC 1225746297 w00t2 localhost testnet.user w00t 127.0.0.1 1225746302 +iosw +ACGJKLNOQcdfgjklnoqtx :Robin Burchell <w00t@inspircd.org>
 * 0: uid
 * 1: ts
 * 2: nick
 * 3: host
 * 4: dhost
 * 5: ident
 * 6: ip
 * 7: signon
 * 8+: modes and params -- IMPORTANT, some modes (e.g. +s) may have parameters. So don't assume a fixed position of realname!
 * last: realname
*/

int anope_event_uid(const char *source, int ac, const char **av)
{
	User *user;
	NickAlias *na;
	struct in_addr addy;
	Server *s = findserver_uid(servlist, source);
	uint32 *ad = reinterpret_cast<uint32 *>(&addy);
	int ts = strtoul(av[1], NULL, 10);

	/* Check if the previously introduced user was Id'd for the nickgroup of the nick he s currently using.
	 * If not, validate the user.  ~ Viper*/
	user = prev_u_intro;
	prev_u_intro = NULL;
	if (user) na = findnick(user->nick);
	if (user && user->server->sync == SSYNC_IN_PROGRESS && (!na || na->nc != user->Account()))
	{
		validate_user(user);
		if (user->HasMode(UMODE_REGISTERED))
			user->RemoveMode(findbot(Config.s_NickServ), UMODE_REGISTERED);
	}
	user = NULL;

	inet_aton(av[6], &addy);
	user = do_nick("", av[2],   /* nick */
			av[5],   /* username */
			av[3],   /* realhost */
			s->name,  /* server */
			av[ac - 1],   /* realname */
			ts, htonl(*ad), av[4], av[0]);
	if (user)
	{
		UserSetInternalModes(user, 1, &av[8]);
		user->SetCloakedHost(av[4]);
		if (user->server->sync == SSYNC_IN_PROGRESS)
		{
			prev_u_intro = user;
		}
		else
		{
			validate_user(user);
		}
	}

	return MOD_CONT;
}

int anope_event_chghost(const char *source, int ac, const char **av)
{
	User *u;

	u = finduser(source);
	if (!u)
	{
		Alog(LOG_DEBUG) << "FHOST for nonexistent user " << source;
		return MOD_CONT;
	}

	u->SetDisplayedHost(av[0]);
	return MOD_CONT;
}

/*
 * [Nov 04 00:08:46.308435 2009] debug: Received: SERVER irc.inspircd.com pass 0 964 :Testnet Central!
 * 0: name
 * 1: pass
 * 2: hops
 * 3: numeric
 * 4: desc
 */
int anope_event_server(const char *source, int ac, const char **av)
{
	if (!stricmp(av[2], "0"))
	{
		uplink = sstrdup(av[0]);
	}
	do_server(source, av[0], av[2], av[4], av[3]);
	return MOD_CONT;
}


int anope_event_privmsg(const char *source, int ac, const char **av)
{
	User *u = find_byuid(source);
	BotInfo *bi = findbot(av[0]);

	if (!u)
		return MOD_CONT; // likely a message from a server, which can happen.

	m_privmsg(u->nick.c_str(), bi ? bi->nick: av[0], av[1]);
	return MOD_CONT;
}

int anope_event_part(const char *source, int ac, const char **av)
{
	do_part(source, ac, av);
	return MOD_CONT;
}

int anope_event_whois(const char *source, int ac, const char **av)
{
	m_whois(source, av[0]);
	return MOD_CONT;
}

int anope_event_metadata(const char *source, int ac, const char **av)
{
	User *u;

	if (ac < 3)
		return MOD_CONT;
	else if (!strcmp(av[1], "accountname"))
	{
		if ((u = find_byuid(av[0])))
		{
			/* Identify the user for this account - Adam */
			u->AutoID(av[2]);
		}
	}

	return MOD_CONT;
}

int anope_event_capab(const char *source, int ac, const char **av)
{
	if (strcasecmp(av[0], "START") == 0)
	{
		if (ac < 2 || atoi(av[1]) < 1202)
		{
			send_cmd(NULL, "ERROR :Protocol mismatch, no or invalid protocol version given in CAPAB START");
			quitmsg = "Protocol mismatch, no or invalid protocol version given in CAPAB START";
			quitting = 1;
			return MOD_STOP;
		}

		/* reset CAPAB */
		has_servicesmod = 0;
		has_svsholdmod = 0;
		has_chghostmod = 0;
		has_chgidentmod = 0;
	}
	else if (strcasecmp(av[0], "CHANMODES") == 0)
	{
		spacesepstream ssep(av[1]);
		std::string capab;

		while (ssep.GetToken(capab))
		{
			std::string modename = capab.substr(0, capab.find('='));
			std::string modechar = capab.substr(capab.find('=') + 1);
			ChannelMode *cm = NULL;

			if (modename == "admin")
				cm = new ChannelModeStatus(CMODE_PROTECT, modechar[1], modechar[0]);
			else if (modename == "allowinvite")
				cm = new ChannelMode(CMODE_ALLINVITE, modechar[0]);
			else if (modename == "auditorium")
				cm = new ChannelMode(CMODE_AUDITORIUM, modechar[0]);
			else if (modename == "autoop")
				continue; // XXX Not currently tracked
			else if (modename == "ban")
				cm = new ChannelModeBan(modechar[0]);
			else if (modename == "banexception")
				cm = new ChannelModeExcept(modechar[0]);
			else if (modename == "blockcaps")
				cm = new ChannelMode(CMODE_BLOCKCAPS, modechar[0]);
			else if (modename == "blockcolor")
				cm = new ChannelMode(CMODE_BLOCKCOLOR, modechar[0]);
			else if (modename == "c_registered")
				cm = new ChannelModeRegistered(modechar[0]);
			else if (modename == "censor")
				cm = new ChannelMode(CMODE_FILTER, modechar[0]);
			else if (modename == "delayjoin")
				cm = new ChannelMode(CMODE_DELAYEDJOIN, modechar[0]);
			else if (modename == "delaymsg")
				continue;
			else if (modename == "exemptchanops")
				continue; // XXX
			else if (modename == "filter")
				continue; // XXX
			else if (modename == "flood")
				cm = new ChannelModeFlood(modechar[0], true);
			else if (modename == "founder")
				cm = new ChannelModeStatus(CMODE_OWNER, modechar[1], modechar[0]);
			else if (modename == "halfop")
				cm = new ChannelModeStatus(CMODE_HALFOP, modechar[1], modechar[0]);
			else if (modename == "halfvoice")
				continue; // XXX - halfvoice? wtf
			else if (modename == "history")
				continue; // XXX
			else if (modename == "invex")
				cm = new ChannelModeInvex(modechar[0]);
			else if (modename == "inviteonly")
				cm = new ChannelMode(CMODE_INVITE, modechar[0]);
			else if (modename == "joinflood")
				cm = new ChannelModeParam(CMODE_JOINFLOOD, modechar[0], true);
			else if (modename == "key")
				cm = new ChannelModeKey(modechar[0]);
			else if (modename == "kicknorejoin")
				cm = new ChannelModeParam(CMODE_NOREJOIN, modechar[0], true);
			else if (modename == "limit")
				cm = new ChannelModeParam(CMODE_LIMIT, modechar[0], true);
			else if (modename == "moderated")
				cm = new ChannelMode(CMODE_MODERATED, modechar[0]);
			else if (modename == "namebase")
				continue; // XXX
			else if (modename == "nickflood")
				cm = new ChannelModeParam(CMODE_NICKFLOOD, modechar[0], true);
			else if (modename == "noctcp")
				cm = new ChannelMode(CMODE_NOCTCP, modechar[0]);
			else if (modename == "noextmsg")
				cm = new ChannelMode(CMODE_NOEXTERNAL, modechar[0]);
			else if (modename == "nokick")
				cm = new ChannelMode(CMODE_NOKICK, modechar[0]);
			else if (modename == "noknock")
				cm = new ChannelMode(CMODE_NOKNOCK, modechar[0]);
			else if (modename == "nonick")
				cm = new ChannelMode(CMODE_NONICK, modechar[0]);
			else if (modename == "nonotice")
				cm = new ChannelMode(CMODE_NONOTICE, modechar[0]);
			else if (modename == "official-join")
				continue; // XXX
			else if (modename == "op")
				cm = new ChannelModeStatus(CMODE_OP, modechar[1], modechar[0]);
			else if (modename == "operonly")
				cm = new ChannelModeOper(modechar[0]);
			else if (modename == "operprefix")
				continue; // XXX
			else if (modename == "permanent")
				cm = new ChannelMode(CMODE_PERM, modechar[0]);
			else if (modename == "private")
				cm = new ChannelMode(CMODE_PRIVATE, modechar[0]);
			else if (modename == "redirect")
				cm = new ChannelModeParam(CMODE_REDIRECT, modechar[0], true);
			else if (modename == "reginvite")
				cm = new ChannelMode(CMODE_REGISTEREDONLY, modechar[0]);
			else if (modename == "regmoderated")
				cm = new ChannelMode(CMODE_REGMODERATED, modechar[0]);
			else if (modename == "secret")
				cm = new ChannelMode(CMODE_SECRET, modechar[0]);
			else if (modename == "sslonly")
				cm = new ChannelMode(CMODE_SSL, modechar[0]);
			else if (modename == "stripcolor")
				cm = new ChannelMode(CMODE_STRIPCOLOR, modechar[0]);
			else if (modename == "topiclock")
				cm = new ChannelMode(CMODE_TOPIC, modechar[0]);
			else if (modename == "voice")
				cm = new ChannelModeStatus(CMODE_VOICE, modechar[1], modechar[0]);
			
			if (cm)
				ModeManager::AddChannelMode(cm);
			else
				Alog() << "Unrecognized mode string in CAPAB CHANMODES: " << capab;
		}
	}
	else if (strcasecmp(av[0], "USERMODES") == 0)
	{
		spacesepstream ssep(av[1]);
		std::string capab;

		while (ssep.GetToken(capab))
		{
			std::string modename = capab.substr(0, capab.find('='));
			std::string modechar = capab.substr(capab.find('=') + 1);
			UserMode *um = NULL;

			if (modename == "bot")
				um = new UserMode(UMODE_BOT, modechar[0]);
			else if (modename == "callerid")
				um = new UserMode(UMODE_CALLERID, modechar[0]);
			else if (modename == "cloak")
				um = new UserMode(UMODE_CLOAK, modechar[0]);
			else if (modename == "deaf")
				um = new UserMode(UMODE_DEAF, modechar[0]);
			else if (modename == "deaf_commonchan")
				um = new UserMode(UMODE_COMMONCHANS, modechar[0]);
			else if (modename == "helpop")
				um = new UserMode(UMODE_HELPOP, modechar[0]);
			else if (modename == "hidechans")
				um = new UserMode(UMODE_PRIV, modechar[0]);
			else if (modename == "hideoper")
				um = new UserMode(UMODE_HIDEOPER, modechar[0]);
			else if (modename == "invisible")
				um = new UserMode(UMODE_INVIS, modechar[0]);
			else if (modename == "oper")
				um = new UserMode(UMODE_OPER, modechar[0]);
			else if (modename == "regdeaf")
				um = new UserMode(UMODE_REGPRIV, modechar[0]);
			else if (modename == "servprotect")
				um = new UserMode(UMODE_PROTECTED, modechar[0]);
			else if (modename == "showwhois")
				um = new UserMode(UMODE_WHOIS, modechar[0]);
			else if (modename == "snomask")
				continue; // XXX
			else if (modename == "u_censor")
				um = new UserMode(UMODE_FILTER, modechar[0]);
			else if (modename == "u_registered")
				um = new UserMode(UMODE_REGISTERED, modechar[0]);
			else if (modename == "u_stripcolor")
				um = new UserMode(UMODE_STRIPCOLOR, modechar[0]);
			else if (modename == "wallops")
				um = new UserMode(UMODE_WALLOPS, modechar[0]);

			if (um)
				ModeManager::AddUserMode(um);
			else
				Alog() << "Unrecognized mode string in CAPAB USERMODES: " << capab;
		}
	}
	else if (strcasecmp(av[0], "MODULES") == 0)
	{
		spacesepstream ssep(av[1]);
		std::string module;

		while (ssep.GetToken(module))
		{
			if (module == "m_svshold.so")
				has_svsholdmod = 1;
		}
	}
	else if (strcasecmp(av[0], "MODSUPPORT") == 0)
	{
		spacesepstream ssep(av[1]);
		std::string module;

		while (ssep.GetToken(module))
		{
			if (module == "m_services_account.so")
				has_servicesmod = 1;
			else if (module == "m_chghost.so")
				has_chghostmod = 1;
			else if (module == "m_chgident.so")
				has_chgidentmod = 1;
			else if (module == "m_servprotect.so")
				ircd->pseudoclient_mode = "+Ik";
		}
	}
	else if (strcasecmp(av[0], "CAPABILITIES") == 0)
	{
		spacesepstream ssep(av[1]);
		std::string capab;
		while (ssep.GetToken(capab))
		{
			if (capab.find("CHANMODES") != std::string::npos)
			{
				std::string modes(capab.begin() + 10, capab.end());
				commasepstream sep(modes);
				std::string modebuf;

				sep.GetToken(modebuf);
				for (size_t t = 0; t < modebuf.size(); ++t)
				{
					if (ModeManager::FindChannelModeByChar(modebuf[t]))
						continue;
					// XXX list modes needs a bit of a rewrite
					ModeManager::AddChannelMode(new ChannelModeList(CMODE_END, modebuf[t]));
				}

				sep.GetToken(modebuf);
				for (size_t t = 0; t < modebuf.size(); ++t)
				{
					if (ModeManager::FindChannelModeByChar(modebuf[t]))
						continue;
					ModeManager::AddChannelMode(new ChannelModeParam(CMODE_END, modebuf[t]));
				}

				sep.GetToken(modebuf);
				for (size_t t = 0; t < modebuf.size(); ++t)
				{
					if (ModeManager::FindChannelModeByChar(modebuf[t]))
						continue;
					ModeManager::AddChannelMode(new ChannelModeParam(CMODE_END, modebuf[t], true));
				}

				sep.GetToken(modebuf);
				for (size_t t = 0; t < modebuf.size(); ++t)
				{
					if (ModeManager::FindChannelModeByChar(modebuf[t]));
						continue;
					ModeManager::AddChannelMode(new ChannelMode(CMODE_END, modebuf[t]));
				}
			}
			else if (capab.find("USERMODES") != std::string::npos)
			{
				std::string modes(capab.begin() + 10, capab.end());
				commasepstream sep(modes);
				std::string modebuf;

				sep.GetToken(modebuf);
				sep.GetToken(modebuf);
				
				if (sep.GetToken(modebuf))
				{
					for (size_t t = 0; t < modebuf.size(); ++t)
					{
						ModeManager::AddUserMode(new UserModeParam(UMODE_END, modebuf[t]));
					}
				}

				if (sep.GetToken(modebuf))
				{
					for (size_t t = 0; t < modebuf.size(); ++t)
					{
						ModeManager::AddUserMode(new UserMode(UMODE_END, modebuf[t]));
					}
				}
			}
			else if (capab.find("MAXMODES=") != std::string::npos)
			{
				std::string maxmodes(capab.begin() + 9, capab.end());
				ircd->maxmodes = atoi(maxmodes.c_str());
			}
		}
	}
	else if (strcasecmp(av[0], "END") == 0)
	{
		if (!has_servicesmod)
		{
			send_cmd(NULL, "ERROR :m_services_account.so is not loaded. This is required by Anope");
			quitmsg = "ERROR: Remote server does not have the m_services_account module loaded, and this is required.";
			quitting = 1;
			return MOD_STOP;
		}
		if (!ModeManager::FindUserModeByName(UMODE_PRIV))
		{
			send_cmd(NULL, "ERROR :m_hidechans.so is not loaded. This is required by Anope");
			quitmsg = "ERROR: Remote server does not have the m_hidechans module loaded, and this is required.";
			quitting = 1;
			return MOD_STOP;
		}
		if (!has_svsholdmod) {
			ircdproto->SendGlobops(findbot(Config.s_OperServ), "SVSHOLD missing, Usage disabled until module is loaded.");
		}
		if (!has_chghostmod) {
			ircdproto->SendGlobops(findbot(Config.s_OperServ), "CHGHOST missing, Usage disabled until module is loaded.");
		}
		if (!has_chgidentmod) {
			ircdproto->SendGlobops(findbot(Config.s_OperServ), "CHGIDENT missing, Usage disabled until module is loaded.");
		}
		ircd->svshold = has_svsholdmod;
	}

	CapabParse(ac, av);

	return MOD_CONT;
}

int anope_event_endburst(const char *source, int ac, const char **av)
{
	NickAlias *na;
	User *u = prev_u_intro;
	Server *s = findserver_uid(servlist, source);
	if (!s)
	{
		throw new CoreException("Got ENDBURST without a source");
	}

	/* Check if the previously introduced user was Id'd for the nickgroup of the nick he s currently using.
	 * If not, validate the user. ~ Viper*/
	prev_u_intro = NULL;
	if (u) na = findnick(u->nick);
	if (u && u->server->sync == SSYNC_IN_PROGRESS && (!na || na->nc != u->Account()))
	{
		validate_user(u);
		if (u->HasMode(UMODE_REGISTERED))
			u->RemoveMode(findbot(Config.s_NickServ), UMODE_REGISTERED);
	}

	Alog() << "Processed ENDBURST for " << s->name;

	finish_sync(s, 1);
	return MOD_CONT;
}

void moduleAddIRCDMsgs() {
	Message *m;

	m = createMessage("ENDBURST",  anope_event_endburst); addCoreMessage(IRCD, m);
	m = createMessage("436",	   anope_event_436); addCoreMessage(IRCD,m);
	m = createMessage("AWAY",	  anope_event_away); addCoreMessage(IRCD,m);
	m = createMessage("JOIN",	  anope_event_join); addCoreMessage(IRCD,m);
	m = createMessage("KICK",	  anope_event_kick); addCoreMessage(IRCD,m);
	m = createMessage("KILL",	  anope_event_kill); addCoreMessage(IRCD,m);
	m = createMessage("MODE",	  anope_event_mode); addCoreMessage(IRCD,m);
	m = createMessage("MOTD",	  anope_event_motd); addCoreMessage(IRCD,m);
	m = createMessage("NICK",	  anope_event_nick); addCoreMessage(IRCD,m);
	m = createMessage("UID",	  anope_event_uid); addCoreMessage(IRCD,m);
	m = createMessage("CAPAB",	 anope_event_capab); addCoreMessage(IRCD,m);
	m = createMessage("PART",	  anope_event_part); addCoreMessage(IRCD,m);
	m = createMessage("PING",	  anope_event_ping); addCoreMessage(IRCD,m);
	m = createMessage("TIME",	  anope_event_time); addCoreMessage(IRCD,m);
	m = createMessage("PRIVMSG",   anope_event_privmsg); addCoreMessage(IRCD,m);
	m = createMessage("QUIT",	  anope_event_quit); addCoreMessage(IRCD,m);
	m = createMessage("SERVER",	anope_event_server); addCoreMessage(IRCD,m);
	m = createMessage("SQUIT",	 anope_event_squit); addCoreMessage(IRCD,m);
	m = createMessage("RSQUIT",	anope_event_rsquit); addCoreMessage(IRCD,m);
	m = createMessage("TOPIC",	 anope_event_topic); addCoreMessage(IRCD,m);
	m = createMessage("WHOIS",	 anope_event_whois); addCoreMessage(IRCD,m);
	m = createMessage("SVSMODE",   anope_event_mode) ;addCoreMessage(IRCD,m);
	m = createMessage("FHOST",	 anope_event_chghost); addCoreMessage(IRCD,m);
	m = createMessage("FIDENT",      anope_event_chgident); addCoreMessage(IRCD,m);
	m = createMessage("FNAME",	 anope_event_chgname); addCoreMessage(IRCD,m);
	m = createMessage("SETHOST",   anope_event_sethost); addCoreMessage(IRCD,m);
	m = createMessage("SETIDENT",  anope_event_setident); addCoreMessage(IRCD,m);
	m = createMessage("SETNAME",   anope_event_setname); addCoreMessage(IRCD,m);
	m = createMessage("FJOIN",	 anope_event_fjoin); addCoreMessage(IRCD,m);
	m = createMessage("FMODE",	 anope_event_fmode); addCoreMessage(IRCD,m);
	m = createMessage("FTOPIC",	anope_event_ftopic); addCoreMessage(IRCD,m);
	m = createMessage("OPERTYPE",  anope_event_opertype); addCoreMessage(IRCD,m);
	m = createMessage("IDLE",	  anope_event_idle); addCoreMessage(IRCD,m);
	m = createMessage("METADATA", anope_event_metadata); addCoreMessage(IRCD,m);
}

bool ChannelModeFlood::IsValid(const std::string &value)
{
	char *dp, *end;
	if (!value.empty() && value[0] != ':' && strtoul((value[0] == '*' ? value.c_str() + 1 : value.c_str()), &dp, 10) > 0 && *dp == ':' && *(++dp) && strtoul(dp, &end, 10) > 0 && !*end) return 1;
	else return 0;
}

class ProtoInspIRCd : public Module
{
 public:
	ProtoInspIRCd(const std::string &modname, const std::string &creator) : Module(modname, creator)
	{
		this->SetAuthor("Anope");
		this->SetVersion("$Id$");
		this->SetType(PROTOCOL);

		if (Config.Numeric)
			TS6SID = sstrdup(Config.Numeric);

		pmodule_ircd_version("InspIRCd 2.0");
		pmodule_ircd_var(myIrcd);
		pmodule_ircd_useTSMode(0);

		CapabType c[] = { CAPAB_NOQUIT, CAPAB_SSJ3, CAPAB_NICK2, CAPAB_VL, CAPAB_TLKEXT	};
		for (unsigned i = 0; i < 5; ++i)
			Capab.SetFlag(c[i]);

		pmodule_ircd_proto(&ircd_proto);
		moduleAddIRCDMsgs();

		ModuleManager::Attach(I_OnUserNickChange, this);
	}

	~ProtoInspIRCd()
	{
		delete [] TS6SID;
	}

	void OnUserNickChange(User *u, const std::string &)
	{
		/* InspIRCd 2.0 removes r on nick change and doesn't tell services, even though it tells the user */
		u->RemoveModeInternal(ModeManager::FindUserModeByName(UMODE_REGISTERED));
	}
};

MODULE_INIT(ProtoInspIRCd)