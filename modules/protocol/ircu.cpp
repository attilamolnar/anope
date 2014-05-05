/* ircu protocol module
 *
 * (C) 2014 Fabio Scotoni
 *
 * Please read COPYING and README for further details.
 *
 * Based on the original code of Epona by Lara.
 * Based on the original code of Services by Andy Church.
 */

#include "module.h"

class IRCuProto : public IRCDProto
{
protected:
	/** Number of bits encoded in one numnick character. */
	static const unsigned int NUMNICKLOG = 6;
	static const unsigned int convert2n[];

public:
	static Anope::string DecodeIP(const Anope::string &encoded)
	{
		const unsigned char *input = reinterpret_cast<const unsigned char *>(encoded.c_str());
		size_t insz = encoded.length();
		sockaddrs sa;

		if (encoded.length() == 6)
		{
			uint32_t i = convert2n[*input++];
			while (*input)
			{
				i <<= NUMNICKLOG;
				i += convert2n[*input++];
			}

			struct in_addr addr;
			addr.s_addr = htonl(i);

			sa.ntop(AF_INET, &addr);
		}
		else
		{
			unsigned int pos = 0;
			uint16_t in6_16[8];

			do
			{
				if (*input == '_')
				{
					unsigned int left;
					for (left = (25 - insz) / 3 - pos; left && pos < 8; left--)
						in6_16[pos++] = 0;

					input++;
					--insz;
				}
				else
				{
					unsigned short accum = convert2n[*input++];
					accum = (accum << NUMNICKLOG) | convert2n[*input++];
					accum = (accum << NUMNICKLOG) | convert2n[*input++];
					in6_16[pos++] = ntohs(accum);

					insz -= 3;
				}
			}
			while (pos < 8);

			struct in6_addr addr;
			memcpy(addr.s6_addr, in6_16, sizeof(addr.s6_addr));

			sa.ntop(AF_INET6, &addr);
		}

		return sa.addr();
	}

	bool use_oplevels;

	IRCuProto(Module *creator) : IRCDProto(creator, "IRCu 2.10.12+")
	{
		DefaultPseudoclientModes = "+oik";
		/* Nick SQLine handling is actually in the IRCd, but the list
		 * can only be manipulated via config directive Jupe {}.
		 */
		RequiresID = AmbiguousID = CanSQLine = CanSQLineChannel = true;
		MaxModes = 6;
		use_oplevels = true;
	}


	static inline char& nextID(char &c)
	{
		if (c == 'Z')
			c = 'a';
		else if (c == 'z')
			c = '0';
		else if (c == '9')
			c = '[';
		else if (c == ']')
			c = 'A' - 1;
		return ++c;
	}

	Anope::string UID_Retrieve() anope_override
	{
		static Anope::string current_uid = "AAA";

		do
		{
			int current_len = current_uid.length() - 1;
			while (current_len >= 0 && nextID(current_uid[current_len--]) == 'A')
				;
		}
		while (User::Find(Me->GetSID() + current_uid) != NULL);

		return Me->GetSID() + current_uid;
	}

	Anope::string SID_Retrieve() anope_override
	{
		static Anope::string current_sid = Config->GetBlock("serverinfo")->Get<const Anope::string>("id");
		if (current_sid.empty())
			current_sid = "AA";

		do
		{
			int current_len = current_sid.length() - 1;
			while (current_len >= 0 && nextID(current_sid[current_len--]) == 'A')
				;
		}
		while (Server::Find(current_sid) != NULL);

		return current_sid;
	}

	void Parse(const Anope::string &buffer, Anope::string &source, Anope::string &command, std::vector<Anope::string> &params) anope_override
	{
		/* If the uplink hasn't introduced itself to us yet we use the RFC1459 parser */
		if (!Me || Me->GetLinks().empty())
			return IRCDProto::Parse(buffer, source, command, params);

		spacesepstream sep(buffer);

		sep.GetToken(source);
		sep.GetToken(command);

		for (Anope::string token; sep.GetToken(token);)
		{
			if (token[0] == ':')
			{
				if (!sep.StreamEnd())
					params.push_back(token.substr(1) + " " + sep.GetRemaining());
				else
					params.push_back(token.substr(1));
				break;
			}
			else
				params.push_back(token);
		}
	}

	Anope::string Format(const Anope::string &source, const Anope::string &message) anope_override
	{
		if (!source.empty())
			return source + " " + message;
		else
			return message;
	}

	void SendServer(const Server *server) anope_override
	{
		if (server != Me)
		{
			/* This is a jupe.
			 *
			 * Anope doesn't have any of the mechanics required to
			 * deal properly with P10 jupes, which have expiration
			 * times and times of last modification, all of which
			 * would require tracking to speak proper P10.
			 *
			 * Thus, for the time being, we do the same as other
			 * services seem to do: Just send a jupe with an
			 * arbitrary expiration time of one day.
			 *
			 * This means unjuping is not possible, as opers being
			 * able to /JUPE requires a F:line (CONFIG_OPERCMDS)
			 * that defaults to FALSE currently and there's no /os
			 * unjupe and we can't currently track jupes internally.
			 */
			UplinkSocket::Message(Me) << "JU * +" << server->GetName() << " "
				<< 86400 /* 1 day */ << " " << Anope::CurTime
				<< " :" << server->GetDescription();
			return;
		}

		/* Since we can add/remove pseudoclients at any point of time,
		 * we'll pretend that we have space for 262143 (]]]) clients.
		 * This will inevitably cause memory waste of about
		 * 262137 * sizeof(struct Client *) on all IRCds.
		 */
		UplinkSocket::Message(MessageSource("")) << "SERVER " << server->GetName() << " " << server->GetHops() << " " << Anope::StartTime
			<< " " << Anope::CurTime << " J10 " << Me->GetSID() << "]]] +sh6 :" << server->GetDescription();

		/* From this point on, all messages sent MUST be tokens! */
	}

	void SendConnect() anope_override
	{
		UplinkSocket::Message(MessageSource("")) << "PASS :" << Config->Uplinks[Anope::CurrentUplink].password;
		SendServer(Me);
	}

	inline bool IsPureRealNameBan(const XLine *const x)
	{
		return (!x->GetReal().empty() && !x->IsRegex()
				&& x->GetNick().empty() && x->GetUser().empty()
				&& x->GetHost().empty());
	}

	void SendAkill(User *u, XLine *x) anope_override
	{
		/* First, list all VALID gline possibilities */

		/* Pure realname bans are possible, but no combinations */
		if (IsPureRealNameBan(x))
		{
			/* XXX: I'm not sure, but I think this breaks if there
			 * are spaces in the mask...
			 */

			/* GLINE_MAX_EXPIRE (7 days) does not expire to us as we
			 * send the GL as server, giving the gline automatically
			 * the GLINE_FORCE flag.
			 *
			 * We can't set permanent glines (expiry time 0 == instant
			 * expiry); set a reasonable limit of 4 weeks there.
			 */
			UplinkSocket::Message(Me) << "GL * +$R" << x->GetReal()
				<< " " << (!x->expires ? 2419200 : x->expires - Anope::CurTime)
				<< " " << Anope::CurTime
				<< " :" << x->GetReason();
		}
		/* user@host is the standard case*/
		else if (!x->IsRegex() && !x->HasNickOrReal())
		{
			UplinkSocket::Message(Me) << "GL * +" << x->GetUser() << "@" << x->GetHost()
				<< " " << (!x->expires ? 2419200 : x->expires - Anope::CurTime)
				<< " " << Anope::CurTime
				<< " :" << x->GetReason();
		}
		/* Stuff we can't work with */
		else
		{
			if (!u)
			{
				/*
				 * No user (this akill was just added), and contains nick and/or realname.
				 * Find users that match and ban them.
				 */
				for (user_map::const_iterator it = UserListByNick.begin(); it != UserListByNick.end(); ++it)
					if (x->manager->Check(it->second, x))
						this->SendAkill(it->second, x);

				return;
			}

			const XLine *old = x;

			if (old->manager->HasEntry("*@" + u->host))
				return;

			/* We can't akill x as it has a nick and/or realname included, so create a new akill for *@host */
			XLine *xline = new XLine("*@" + u->host, old->by, old->expires, old->reason, old->id);

			old->manager->AddXLine(xline);
			x = xline;

			Log(Config->GetClient("OperServ"), "akill") << "AKILL: Added an akill for " << x->mask << " because " << u->GetMask() << "#"
					<< u->realname << " matches " << old->mask;
		}
	}

	void SendAkillDel(const XLine *x) anope_override
	{
		if (x == NULL || x->IsRegex() || (x->HasNickOrReal() && !IsPureRealNameBan(x)))
			return;

		if (IsPureRealNameBan(x))
			UplinkSocket::Message(Me) << "GL * -$R" << x->GetReal()
				<< " " << Anope::CurTime;
		else
			UplinkSocket::Message(Me) << "GL * -" << x->GetUser() << "@" << x->GetHost()
				<< " " << Anope::CurTime;
	}

	void SendSQLine(User *u, const XLine *x) anope_override
	{
		/* We have to say CanSQLine to get the channel SQLines.
		 * However, Anope doesn't care and sends us nick SQLines anyway.
		 */
		if (x->mask[0] != '#' && x->mask[0] != '&')
			return;

		UplinkSocket::Message(Me) << "GL * +" << x->mask
			/* Hold perm SQLines for four weeks */
			<< " " << (!x->expires ? 2419200 : x->expires - Anope::CurTime)
			<< " " << Anope::CurTime
			<< " :" << x->reason;
	}

	void SendSQLineDel(const XLine *x) anope_override
	{
		if (x->mask[0] != '#' && x->mask[0] != '&')
			return;

		UplinkSocket::Message(Me) << "GL * -" << x->mask << " " << Anope::CurTime;
	}

	void SendClientIntroduction(User *u) anope_override
	{
		/* nick, hops, nickts, ident, host, umodes, _ (IP), numnick, gecos */
		UplinkSocket::Message(Me) << "N " << u->nick << " 1 " << u->timestamp << " "
			<< u->GetIdent() << " " << u->host << " +" << u->GetModes()
			<< " _ " << u->GetUID() << " :" << u->realname;
	}

	void SendEOB() anope_override
	{
		UplinkSocket::Message(Me) << "EB";
	}

	void SendGlobalNotice(BotInfo *bi, const Server *dest, const Anope::string &msg) anope_override
	{
		UplinkSocket::Message(bi) << "O $" << dest->GetName() << " :" << msg;
	}

	void SendGlobalPrivmsg(BotInfo *bi, const Server *dest, const Anope::string &msg) anope_override
	{
		UplinkSocket::Message(bi) << "P $" << dest->GetName() << " :" << msg;
	}

	void SendJoin(User *user, Channel *c, const ChannelStatus *status) anope_override
	{
		Anope::string statusstr = ":";

		/* Order must be kept or the parser on the other side might choke */
		if (status != NULL)
		{
			if (status->HasMode('v'))
				statusstr += 'v';
			if (status->HasMode('o'))
				/* ircu really loves their oplevels and uses them even
				 * if FEAT_OPLEVELS == FALSE; 'o' == 999, but services
				 * will want creator status.
				 */
				statusstr += use_oplevels ? '0' : 'o';
		}

		/* We need to do something like SJOIN with hybrid to "burst
		 * onto" the channel.
		 */
		UplinkSocket::Message(Me) << "B " << c->name << " " << c->creation_time <<
			" " << user->GetUID() << (statusstr == ":" ? "" : statusstr);

		if (status != NULL)
		{
			ChanUserContainer *uc = c->FindUser(user);

			if (uc != NULL)
				uc->status = *status;
		}
	}

	void SendLogin(User *u, NickAlias *na) anope_override
	{
		if (u->Account())
		{
			Log(LOG_DEBUG) << "SendLogin for " << u->GetUID() << " as " << na->nc->display << " while already logged in as " << u->Account()->display;
			return;
		}

		UplinkSocket::Message(Me) << "AC " << u->GetUID() << " " << na->nc->display;
	}

	void SendLogout(User *u) anope_override
	{
		/* ircu doesn't know logging out. You don't log out. */
		Log() << "ircu does not support logging out. Please disable "
			"/ns logout. Services are now desynced with network "
			"state. We should not have gotten here, this is a bug!";
	}

	/* We need to override all IRCDProto prototypes to send tokens. */

	void SendKill(const MessageSource &source, const Anope::string &target, const Anope::string &reason) anope_override
	{
		UplinkSocket::Message(source) << "D " << target << " :" << reason;
	}

	void SendSVSKillInternal(const MessageSource &source, User *user, const Anope::string &buf) anope_override
	{
		SendKill(source, user->GetUID(), buf);
	}

	void SendModeInternal(const MessageSource &source, const Channel *dest, const Anope::string &buf) anope_override
	{
		if (dest->ci && dest->ci->bi && dest->FindUser(dest->ci->bi))
			UplinkSocket::Message(*dest->ci->bi) << "M " << dest->name << " " << buf;
		else
			UplinkSocket::Message(Me) << "M " << dest->name << " " << buf;
	}

	void SendModeInternal(const MessageSource &source, User *user, const Anope::string &buf) anope_override
	{
		UplinkSocket::Message(Me) << "M " << user->GetUID() << " " << buf;
	}

	void SendKickInternal(const MessageSource &source, const Channel *c, User *u, const Anope::string &r) anope_override
	{
		if (c->ci && c->ci->bi && c->FindUser(c->ci->bi))
			UplinkSocket::Message(*c->ci->bi) << "K " << c->name << " " << u->GetUID() << " :"
				<< (r.empty() ? "" : r);
		else
			UplinkSocket::Message(Me) << "K " << c->name << " " << u->GetUID() << " :"
				<< (r.empty() ? "" : r);
	}

	void SendNoticeInternal(const MessageSource &source, const Anope::string &dest, const Anope::string &msg) anope_override
	{
		UplinkSocket::Message(source) << "O " << dest << " :" << msg;
	}

	void SendPrivmsgInternal(const MessageSource &source, const Anope::string &dest, const Anope::string &buf) anope_override
	{
		UplinkSocket::Message(source) << "P " << dest << " :" << buf;
	}

	void SendQuitInternal(User *u, const Anope::string &buf) anope_override
	{
		UplinkSocket::Message(u) << "Q :" << (buf.empty() ? "" : buf);
	}

	void SendPartInternal(User *u, const Channel *chan, const Anope::string &buf) anope_override
	{
		if (buf.empty())
			UplinkSocket::Message(u) << "L " << chan->name;
		else
			UplinkSocket::Message(u) << "L " << chan->name << " :" << buf;
	}

	void SendGlobopsInternal(const MessageSource &source, const Anope::string &buf) anope_override
	{
		UplinkSocket::Message(source) << "WA :" << buf;
	}

	void SendTopic(const MessageSource &source, Channel *c) anope_override
	{
		UplinkSocket::Message(source) << "T " << c->name << " " << c->creation_time << " "
			<< c->topic_ts << " :" << c->topic;
	}

	void SendPing(const Anope::string &servname, const Anope::string &who) anope_override
	{
		UplinkSocket::Message(Me) << "G " << who;
	}

	void SendPong(const Anope::string &servname, const Anope::string &who) anope_override
	{
		UplinkSocket::Message(Me) << "Z " << who;
	}

	void SendInvite(const MessageSource &source, const Channel *c, User *u) anope_override
	{
		/* ircu requires nick at this point for some reason. */
		UplinkSocket::Message(source) << "I " << u->nick << " :" << c->name;
	}

	void SendSquit(Server *s, const Anope::string &message) anope_override
	{
		/* We don't keep track of server link TSes and we can force
		 * SQ with TS 0, so we won't bother doing anything fancy.
		 */
		UplinkSocket::Message(Me) << "SQ " << s->GetName() << " 0 :" << message;
	}

	void SendNickChange(User *u, const Anope::string &newnick) anope_override
	{
		UplinkSocket::Message(u) << "N " << newnick << " " << Anope::CurTime;
	}
};

const unsigned int IRCuProto::convert2n[] = {
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0-15
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 16-31
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 32-47
  52,53,54,55,56,57,58,59,60,61, 0, 0, 0, 0, 0, 0, // 48-63
   0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14, // 64-79
  15,16,17,18,19,20,21,22,23,24,25,62, 0,63, 0, 0, // 80-95
   0,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40, // 96-111
  41,42,43,44,45,46,47,48,49,50,51, 0, 0, 0, 0, 0, // 112-127

   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

struct IRCDMessageServer : IRCDMessage
{
	/*      0             1 2       3      4       5     6    7            */
	/* AB S hydra.invalid 1 startts linkts P10/J10 AA]]] +hs6 :Description */
	IRCDMessageServer(Module *creator) : IRCDMessage(creator, "S", 8) { SetFlag(IRCDMESSAGE_REQUIRE_SERVER); }

	void Run(MessageSource &source, const std::vector<Anope::string> &params) anope_override
	{
		unsigned int hops = params[1].is_pos_number_only() ? convertTo<unsigned>(params[1]) : 0;
		new Server(source.GetServer() == NULL ? Me : source.GetServer(), params[0], hops, params[7], params[5].substr(0, 2));
	}
};

struct IRCDMessageNick : IRCDMessage
{
	IRCDMessageNick(Module *creator) : IRCDMessage(creator, "N", 2) { SetFlag(IRCDMESSAGE_SOFT_LIMIT); }

	/*         0     1 2          3      4             5      6      7     8        */
	/* AB    N culex 1 1397454483 ~culex hydra.invalid +oiwgx B]AAAB ABAAA :Unknown */
	/* ABAAA N cule_ 1397454490 */
	void Run(MessageSource &source, const std::vector<Anope::string> &params) anope_override
	{
		time_t ts;

		try
		{
			ts = convertTo<time_t>(params[1]);
		}
		catch (const ConvertException &)
		{
			ts = 0;
		}

		/* nick change, source must be user */
		if (params.size() == 2)
		{
			User *u = source.GetUser();
			if (u)
				u->ChangeNick(params[0], ts);
		}
		else if (params.size() >= 8 && source.GetServer() != NULL)
		{
			Anope::string umodes;
			Anope::string ip = params[params.size() - 3];
			NickCore *nc = NULL;

			/* umodes are optional! */
			if (params.size() >= 8)
			{
				umodes = params[5];

				if (umodes.find('r') != Anope::string::npos)
				{
					Anope::string accname = params[6];

					/* If it's a timestamped account, truncate. */
					size_t pos = umodes.find(':');
					if (pos != Anope::string::npos)
						accname = accname.substr(0, pos);

					nc = NickCore::Find(accname);
				}
			}

			if (ip == '_')
				ip.clear();
			else
				ip = IRCuProto::DecodeIP(ip);

			User::OnIntroduce(params[0], params[3], params[4], "", ip,
					source.GetServer(), params[params.size() - 1],
					ts, umodes, params[params.size() - 2], nc);
		}
	}
};

struct IRCDMessageBurst : IRCDMessage
{
	IRCDMessageBurst(Module *creator) : IRCDMessage(creator, "B", 2) { SetFlag(IRCDMESSAGE_SOFT_LIMIT); }

	unsigned HealCModes(Anope::string &modes, const std::vector<Anope::string> &params, unsigned param)
	{
		unsigned ret = 0;
		Anope::string healed_modes = params[param];

		for (Anope::string::const_iterator it = params[param].begin(), end = params[param].end(); it != end; ++it)
		{
			ChannelMode *cm = ModeManager::FindChannelModeByChar(*it);
			if (cm == NULL)
				continue;

			/* From the B message, the only kind of channel modes we can get
			 * in the cmode list are
			 * MODE_REGULAR and MODE_PARAM, not MODE_LIST/MODE_STATUS.
			 *
			 * Bans are propagated in B as well, but elsewhere.
			 */
			if (cm->type != MODE_PARAM)
				continue;

			ret++;
			healed_modes += " " + params[++param];
		}

		modes = healed_modes;
		return ret;
	}

	std::list<Message::Join::SJoinUser> ParseClientList(const Anope::string &nicklist)
	{
		std::list<Message::Join::SJoinUser> users;
		commasepstream sep(nicklist);

		for (Anope::string nick; sep.GetToken(nick);)
		{
			Message::Join::SJoinUser sju;
			ChannelStatus modes;

			size_t pos = nick.find(':');
			if (pos != Anope::string::npos)
			{
				/* New CUS */
				Anope::string cus = nick.substr(pos + 1);
				nick = nick.substr(0, pos);

				for (Anope::string::const_iterator it = cus.begin(), end = cus.end(); it != end; ++it)
				{
					if (*it == 'o' || isdigit(*it))
						modes.AddMode('o');
					else if (*it == 'v')
						modes.AddMode('v');
				}
			}

			sju.first = modes;
			sju.second = User::Find(nick);
			if (sju.second == NULL)
			{
				Log(LOG_DEBUG) << "non-existent user " << nick << " in B message!";
				continue;
			}

			users.push_back(sju);
		}

		return users;
	}

	/* AB B #root 1234567890 +ntk moo ABAAA:0 */
	void Run(MessageSource &source, const std::vector<Anope::string> &params) anope_override
	{
		bool created;
		time_t ts;
		Anope::string modes;
		Anope::string buf;
		std::list<Message::Join::SJoinUser> users;

		try
		{
			ts = convertTo<time_t>(params[1]);
		}
		catch (const ConvertException &)
		{
			ts = 0;
		}

		Channel *c = Channel::FindOrCreate(params[0], created, ts);

		/* Skip check if local members are split riding -- ours
		 * are privileged.
		 */

		for (unsigned param = 2; param < params.size(); ++param)
		{
			switch (params[param][0])
			{
				case '+':
				{
					param += HealCModes(modes, params, param);
					break;
				}
				case '%':
				{
					spacesepstream bans(params[param]);
					ChannelMode *mode = ModeManager::FindChannelModeByName("BAN");

					while (bans.GetToken(buf))
						c->SetModeInternal(source, mode, buf);
					break;
				}
				default:
				{
					users = ParseClientList(params[param]);
					break;
				}
			}
		}

		Message::Join::SJoin(source, c->name, ts, modes, users);
	}
};

struct IRCDMessageWhois : Message::Whois
{
	/* ircu limits at 50 WHOIS entries. */
	static const int MAX_WHOIS = 50;

	IRCDMessageWhois(Module *creator) : Message::Whois(creator, "W") { }

	/* ABAAA W AS :chanserv */
	void Run(MessageSource &source, const std::vector<Anope::string> &params) anope_override
	{
		/* We don't have to check whether we're the server that is being asked for.
		 * Just assume we are and adjust parameters.
		 */
		const Anope::string &nicklist = (params.size() > 2) ? params[2] : params[1];

		int total = 0;
		commasepstream sep(nicklist);
		Anope::string nick;

		/* While ircu cuts off at 50 *successful* whois entries and doesn't count the
		 * users that weren't found, we do consider them as well.
		 *
		 * This is just a minor incompatibility.
		 */
		while (sep.GetToken(nick) && total++ < MAX_WHOIS)
		{
			std::vector<Anope::string> p;

			User *u = User::Find(nick, true);
			if (!u || u->server != Me)
				p.push_back(nick);
			else
				p.push_back(u->GetUID());

			Message::Whois::Run(source, p);
		}
	}
};

struct IRCDMessageClearModes : IRCDMessage
{
	IRCDMessageClearModes(Module *creator) : IRCDMessage(creator, "CM", 2) { }

	/* ABAAA CM #channel :ntk moo */
	void Run(MessageSource &source, const std::vector<Anope::string> &params) anope_override
	{
		Channel *c = Channel::Find(params[0]);

		if (c == NULL)
			return;

		for (Anope::string::const_iterator it = params[1].begin(), end = params[1].end(); it != end; ++it)
		{
			ChannelMode *cm = ModeManager::FindChannelModeByChar(*it);
			if (cm == NULL)
				continue;

			switch (cm->type)
			{
				case MODE_REGULAR:
				case MODE_PARAM:
				{
					c->RemoveModeInternal(source, cm);
					break;
				}
				case MODE_LIST:
				{
					std::pair<Channel::ModeList::iterator, Channel::ModeList::iterator> its = c->GetModeList(cm->name);
					for(; its.first != its.second;)
					{
						const Anope::string &mask = its.first->second;
						++its.first;
						c->RemoveModeInternal(source, cm, mask);
					}
					break;
				}
				case MODE_STATUS:
				{
					for (Channel::ChanUserList::const_iterator iit = c->users.begin(), it_end = c->users.end(); iit != it_end; ++iit)
					{
						ChanUserContainer *uc = iit->second;
						c->RemoveModeInternal(source, cm, uc->user->GetUID());
					}
					break;
				}
			}
		}
	}
};

struct IRCDMessageCreate : IRCDMessage
{
	static const unsigned TS_LAG_TIME = 86400;
	/* Some magic constant used in m_create.c to make minor TS deltas be ignored */
	static const unsigned MINOR_TS_DELTA = 4;

	IRCDMessageCreate(Module *creator) : IRCDMessage(creator, "C", 2) { SetFlag(IRCDMESSAGE_REQUIRE_USER); }

	/* ABAAA C #channel 1234567890 */
	void Run(MessageSource &source, const std::vector<Anope::string> &params) anope_override
	{
		/* See m_create.c of ircu for details as to what some of this code does. */
		User *u = source.GetUser();
		time_t ts;
		commasepstream sep(params[0]);

		try
		{
			ts = convertTo<time_t>(params[1]);
		}
		catch (const ConvertException &)
		{
			ts = 0;
		}

		for (Anope::string cname; sep.GetToken(cname);)
		{
			bool badop = false;

			Channel *c = Channel::Find(cname);

			if (c)
			{
				if (Anope::CurTime - ts > TS_LAG_TIME ||
						(c->creation_time && ts > c->creation_time &&
						 !(c->users.size() == 0 && !c->HasMode("APASS"))))
				{
					if (u->server->IsSynced()
							|| ts > c->creation_time + MINOR_TS_DELTA)
						badop = true;
					c->Reset();
				}

				c->creation_time = ts;
			}

			ChannelStatus cus;
			if (!badop)
				cus.AddMode('o');

			std::list<Message::Join::SJoinUser> sjusers;
			sjusers.push_back(std::make_pair(cus, u));
			Message::Join::SJoin(source, cname, ts, "", sjusers);
		}
	}
};

struct IRCDMessageDestruct : IRCDMessage
{
	IRCDMessageDestruct(Module *creator) : IRCDMessage(creator, "DE", 2) { SetFlag(IRCDMESSAGE_REQUIRE_SERVER); }

	void Run(MessageSource &source, const std::vector<Anope::string> &params) anope_override
	{
		time_t ts = convertTo<time_t>(params[1]);
		Channel *c = Channel::Find(params[0]);
		Anope::string delmodestr;

		if (c == NULL)
			return;

		if (ts > c->creation_time)
			return;

		/* The DE desync can't happen as we're a leaf and have no local users. The
		 * uplink will sort it out for us instead.
		 *
		 * We do need to bounce it back, however.
		 */

		UplinkSocket::Message(Me) << "DE " << c->name << " " << c->creation_time;

		delete c;
	}
};

struct IRCDMessageEndOfBurst : IRCDMessage
{
	IRCDMessageEndOfBurst(Module *creator) : IRCDMessage(creator, "EB", 0) { SetFlag(IRCDMESSAGE_REQUIRE_SERVER); }

	void Run(MessageSource &source, const std::vector<Anope::string> &params) anope_override
	{
		source.GetServer()->Sync(true);
		UplinkSocket::Message(Me) << "EA";
	}
};

struct IRCDMessageKick : IRCDMessage
{
	IRCDMessageKick(Module *creator) : IRCDMessage(creator, "K", 2) { SetFlag(IRCDMESSAGE_SOFT_LIMIT); }

	void Run(MessageSource &source, const std::vector<Anope::string> &params) anope_override
	{
		Channel *chan = Channel::Find(params[0]);
		const Anope::string reason = params.size() > 2 ? params[2] : "";

		commasepstream sep(params[1]);
		for (Anope::string uid; sep.GetToken(uid); )
		{
			User *target = User::Find(uid);
			if (!target)
				continue;

			if (target->server == Me)
			{
				// If our client is getting kicked send back a part to remove the zombie
				UplinkSocket::Message(target) << "L " << params[0];
			}

			if (chan)
				chan->KickInternal(source, uid, reason);
		}
	}
};

class ProtoIRCu : public Module
{
	IRCuProto ircd_proto;

	/* Core message handlers */
	Message::Away message_away;
	Message::Error message_error;
	Message::Invite message_invite;
	Message::Join message_join;
	Message::Kill message_kill;
	Message::Mode message_mode;
	Message::MOTD message_motd;
	Message::Notice message_notice;
	Message::Part message_part;
	Message::Ping message_ping;
	Message::Privmsg message_privmsg;
	Message::Quit message_quit;
	Message::Stats message_stats;
	Message::Time message_time;
	Message::Topic message_topic;
	Message::Version message_version;

	/* Our message handlers */
	IRCDMessageServer message_server;
	IRCDMessageNick message_nick;
	IRCDMessageBurst message_burst;
	IRCDMessageWhois message_whois;
	IRCDMessageClearModes message_clearmodes;
	IRCDMessageCreate message_create;
	IRCDMessageDestruct message_destruct;
	IRCDMessageEndOfBurst message_end_of_burst;
	IRCDMessageKick message_kick;

	/* Non-token message handlers */
	ServiceAlias alias_server, alias_nick, alias_burst, alias_whois,
		     alias_clearmodes, alias_create, alias_destruct,
		     alias_end_of_burst, alias_opmode,

		     alias_a, alias_y, alias_i, alias_j, alias_d, alias_mo,
		     alias_o, alias_l, alias_g, alias_p, alias_q, alias_r,
		     alias_ti, alias_t, alias_v,

		     /* true aliases */
		     alias_om;

public:
	Anope::string cloak_suffix;
	bool use_zannels;

	ProtoIRCu(const Anope::string &modname, const Anope::string &creator) : Module(modname, creator, PROTOCOL | VENDOR),
		ircd_proto(this),

		message_away(this),
		message_error(this),
		message_invite(this),
		message_join(this),
		message_kill(this),
		message_mode(this, "M"),
		message_motd(this),
		message_notice(this),
		message_part(this),
		message_ping(this),
		message_privmsg(this),
		message_quit(this),
		message_stats(this),
		message_time(this),
		message_topic(this),
		message_version(this),

		message_server(this),
		message_nick(this),
		message_burst(this),
		message_whois(this),
		message_clearmodes(this),
		message_create(this),
		message_destruct(this),
		message_end_of_burst(this),
		message_kick(this),

#define ALIAS(name, token) alias_##name("IRCDMessage", "ircu/" #name, "ircu/" #token)
		ALIAS(server, s),
		ALIAS(nick, n),
		ALIAS(burst, b),
		ALIAS(whois, w),
		ALIAS(clearmodes, cm),
		ALIAS(create, c),
		ALIAS(destruct, de),
		ALIAS(end_of_burst, eb),
		ALIAS(opmode, m),

		ALIAS(a, away),
		ALIAS(y, error),
		ALIAS(i, invite),
		ALIAS(j, join),
		ALIAS(d, kill),
		ALIAS(mo, motd),
		ALIAS(o, notice),
		ALIAS(l, part),
		ALIAS(g, ping),
		ALIAS(p, privmsg),
		ALIAS(q, quit),
		ALIAS(r, stats),
		ALIAS(ti, time),
		ALIAS(t, topic),
		ALIAS(v, version),

		ALIAS(om, m)
#undef ALIAS
	{
		/* Add user modes */
		ModeManager::AddUserMode(new UserModeOperOnly("DEAF", 'd'));
		ModeManager::AddUserMode(new UserModeOperOnly("DEBUG", 'g'));
		ModeManager::AddUserMode(new UserMode("INVIS", 'i'));
		ModeManager::AddUserMode(new UserModeNoone("PROTECTED", 'k'));
		ModeManager::AddUserMode(new UserModeOperOnly("OPER", 'o'));
		ModeManager::AddUserMode(new UserModeNoone("REGISTERED", 'r'));
		ModeManager::AddUserMode(new UserModeOperOnly("SNOMASK", 's'));
		ModeManager::AddUserMode(new UserMode("WALLOP", 'w'));
		ModeManager::AddUserMode(new UserMode("CLOAK", 'x'));

		/* No +eI supported */
		ModeManager::AddChannelMode(new ChannelModeList("BAN", 'b'));

		/* CUS are only v/o */
		ModeManager::AddChannelMode(new ChannelModeStatus("VOICE", 'v', '+', 0));
		ModeManager::AddChannelMode(new ChannelModeStatus("OP", 'o', '@', 2));

		ModeManager::AddChannelMode(new ChannelModeParam("LIMIT", 'l', true));
		ModeManager::AddChannelMode(new ChannelModeKey('k'));

		ModeManager::AddChannelMode(new ChannelModeParam("APASS", 'A', true));
		ModeManager::AddChannelMode(new ChannelModeParam("UPASS", 'U', true));

		ModeManager::AddChannelMode(new ChannelMode("PRIVATE", 'p'));
		ModeManager::AddChannelMode(new ChannelMode("SECRET", 's'));
		ModeManager::AddChannelMode(new ChannelMode("MODERATED", 'm'));
		ModeManager::AddChannelMode(new ChannelMode("TOPIC", 't'));
		ModeManager::AddChannelMode(new ChannelMode("INVITE", 'i'));
		ModeManager::AddChannelMode(new ChannelMode("NOEXTERNAL", 'n'));
		ModeManager::AddChannelMode(new ChannelMode("REGISTEREDONLY", 'r'));
		/* these modes are quite new; we'll need to externalize that for "base" P10 */
		ModeManager::AddChannelMode(new ChannelMode("DELAYJOIN", 'D'));
		ModeManager::AddChannelMode(new ChannelModeNoone("REGISTERED", 'R'));
	}

	EventReturn OnPreCommand(CommandSource &source, Command *command, std::vector<Anope::string> &params) anope_override
	{
		NickCore *nc = source.GetAccount();

		if (command->name == "nickserv/identify" && nc)
		{
			source.Reply(_("You are already identified."));
			return EVENT_CONTINUE;
		}

		/* ircu doesn't support changing account name and will
		 * cry with protocol_violation() if we try. Immediately
		 * stop any attempt to re-auth.
		 * The same applies to logging out -- there is no
		 * concept of logging out.
		 */
		if (command->name == "nickserv/logout")
		{
			source.Reply(_("You cannot log out. Please reconnect and authenticate for a different nick."));
			return EVENT_STOP;
		}

		return EVENT_CONTINUE;
	}

	void OnPartChannel(User *u, Channel *c, const Anope::string &channel, const Anope::string &msg) anope_override
	{
		if (c->users.size() > 0)
			return;

		/* As per channels.c:sub1_from_channel, modes are cleared for zannels, unless
		 * they have an apass.
		 *
		 * Remove +il as well unless they're mlocked to allow re-entry.
		 */
		ChannelMode *l = ModeManager::FindChannelModeByName("LIMIT");
		ChannelMode *i = ModeManager::FindChannelModeByName("INVITE");
		MessageSource ms = MessageSource(Me);

		if (l != NULL)
			c->RemoveModeInternal(ms, l);
		if (i != NULL)
			c->RemoveModeInternal(ms, i);

		if (!c->HasMode("APASS"))
		{
			Channel::ModeList ml = c->GetModes();
			for (std::multimap<Anope::string, Anope::string>::const_iterator it = ml.begin(), end = ml.end();
					it != end;
					++it)
			{
				ChannelMode *cm = ModeManager::FindChannelModeByName(it->first);
				c->RemoveModeInternal(ms, cm);
			}
		}
	}

	EventReturn OnCheckDelete(Channel *c) anope_override
	{
		/* Background: ircu introduced zannels to keep the pseudo-registration that is
		 * APASS/UPASS. We'll get a DE message when we can delete a channel.
		 *
		 * However, since zannels are configured by a F:line on the IRCd, we need to
		 * reply on the configuration to tell us whether or not zannels are enabled
		 * (they are by default).
		 */
		return use_zannels ? EVENT_STOP : EVENT_CONTINUE;
	}

	void OnReload(Configuration::Conf *conf) anope_override
	{
		use_zannels = conf->GetModule(ModuleManager::FindFirstOf(PROTOCOL))->Get<bool>("use_zannels", "yes");
		ircd_proto.use_oplevels = conf->GetModule(ModuleManager::FindFirstOf(PROTOCOL))->Get<bool>("use_oplevels", "yes");
		cloak_suffix = conf->GetModule(ModuleManager::FindFirstOf(PROTOCOL))->Get<const Anope::string>("cloak_suffix");
		if (cloak_suffix.empty())
			throw ConfigException(this->name + " cloak_suffix must not be empty.");
	}

	void OnUserModeSet(const MessageSource &setter, User *u, const Anope::string &mname) anope_override
	{
		/* Users *can* set +x before being authed, meaning the cloak will only
		 * be set when AC is sent.
		 */
		if (mname != "CLOAK" || u->Account() == NULL)
			return;

		u->SetCloakedHost(u->Account()->display + "." + cloak_suffix);
	}

	void OnUserLogin(User *u) anope_override
	{
		/* User::User first processes user modes, which doesn't parse +r containing the
		 * account name, and only THEN logs in. This is necessary to keep track of the
		 * cloak on-burst.
		 */
		if (u->HasMode("CLOAK"))
			u->SetCloakedHost(u->Account()->display + "." + cloak_suffix);
	}
};

MODULE_INIT(ProtoIRCu)

