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
	/* The following parts were stolen from ircu. Never touch a running system. */
	/*
	 * IRC - Internet Relay Chat, ircd/channel.c
	 * Copyright (C) 1996 Carlo Wood (I wish this was C++ - this sucks :/)
	 *
	 * This program is free software; you can redistribute it and/or modify
	 * it under the terms of the GNU General Public License as published by
	 * the Free Software Foundation; either version 2, or (at your option)
	 * any later version.
	 *
	 * This program is distributed in the hope that it will be useful,
	 * but WITHOUT ANY WARRANTY; without even the implied warranty of
	 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	 * GNU General Public License for more details.
	 *
	 * You should have received a copy of the GNU General Public License
	 * along with this program; if not, write to the Free Software
	 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
	 */
	static const unsigned int NUMNICKLEN = 5;
	/** Number of bits encoded in one numnick character. */
	static const unsigned int NUMNICKLOG = 6;
	/** Bitmask to select value of next numnick character. */
	static const unsigned int NUMNICKMASK = 63;          /* (NUMNICKBASE-1) */
	/** Number of servers representable in a numnick. */
	static const unsigned int NN_MAX_SERVER = 4096;      /* (NUMNICKBASE * NUMNICKBASE) */
	/** Number of clients representable in a numnick. */
	static const unsigned int NN_MAX_CLIENT = 262144;    /* NUMNICKBASE ^ 3 */

	struct irc_in_addr {
		unsigned short in6_16[8]; /**< IPv6 encoded parts, little-endian. */
	};
	static const unsigned int convert2n[];

	/** Convert a string to its value as a numnick.
	 * @param[in] s Numnick string to decode.
	 * @return %Numeric nickname value.
	 */
	static unsigned int base64toint(const char* s)
	{
	  unsigned int i = convert2n[(unsigned char) *s++];
	  while (*s) {
	    i <<= NUMNICKLOG;
	    i += convert2n[(unsigned char) *s++];
	  }
	  return i;
	}

	/** Decode an IP address from base64.
	 * @param[in] input Input buffer to decode.
	 * @param[out] addr IP address structure to populate.
	 */
	static void base64toip(const char* input, struct irc_in_addr* addr)
	{
	  memset(addr, 0, sizeof(*addr));
	  if (strlen(input) == 6) {
	    unsigned int in = base64toint(input);
	    /* An all-zero address should stay that way. */
	    if (in) {
	      addr->in6_16[5] = htons(65535);
	      addr->in6_16[6] = htons(in >> 16);
	      addr->in6_16[7] = htons(in & 65535);
	    }
	  } else {
	    unsigned int pos = 0;
	    do {
	      if (*input == '_') {
		unsigned int left;
		for (left = (25 - strlen(input)) / 3 - pos; left; left--)
		  addr->in6_16[pos++] = 0;
		input++;
	      } else {
		unsigned short accum = convert2n[(unsigned char)*input++];
		accum = (accum << NUMNICKLOG) | convert2n[(unsigned char)*input++];
		accum = (accum << NUMNICKLOG) | convert2n[(unsigned char)*input++];
		addr->in6_16[pos++] = ntohs(accum);
	      }
	    } while (pos < 8);
	  }
	}

#define irc_in_addr_is_ipv4(ADDR) (!(ADDR)->in6_16[0] && !(ADDR)->in6_16[1] && !(ADDR)->in6_16[2] \
					   && !(ADDR)->in6_16[3] && !(ADDR)->in6_16[4] \
					   && ((!(ADDR)->in6_16[5] && (ADDR)->in6_16[6]) \
					       || (ADDR)->in6_16[5] == 65535))
	/*
	 * this new faster inet_ntoa was ripped from:
	 * From: Thomas Helvey <tomh@inxpress.net>
	 */
	/** Array of text strings for dotted quads. */
	static const char* IpQuadTab[];
	/** Convert an IP address to printable ASCII form.
	 * @param[in] in Address to format.
	 * @return the IP in printable form
	 */
	static Anope::string ircd_ntoa_r(const struct irc_in_addr* in)
	{
	    static char buf[40];
	    if (irc_in_addr_is_ipv4(in)) {
	      unsigned int pos, len;
	      unsigned char *pch;

	      pch = (unsigned char*)&in->in6_16[6];
	      len = strlen(IpQuadTab[*pch]);
	      memcpy(buf, IpQuadTab[*pch++], len);
	      pos = len;
	      buf[pos++] = '.';
	      len = strlen(IpQuadTab[*pch]);
	      memcpy(buf+pos, IpQuadTab[*pch++], len);
	      pos += len;
	      buf[pos++] = '.';
	      len = strlen(IpQuadTab[*pch]);
	      memcpy(buf+pos, IpQuadTab[*pch++], len);
	      pos += len;
	      buf[pos++] = '.';
	      len = strlen(IpQuadTab[*pch]);
	      memcpy(buf+pos, IpQuadTab[*pch++], len);
	      buf[pos + len] = '\0';
	      return buf;
	    } else {
	      static const char hexdigits[] = "0123456789abcdef";
	      unsigned int pos, part, max_start, max_zeros, curr_zeros, ii;

	      /* Find longest run of zeros. */
	      for (max_start = ii = 1, max_zeros = curr_zeros = 0; ii < 8; ++ii) {
		if (!in->in6_16[ii])
		  curr_zeros++;
		else if (curr_zeros > max_zeros) {
		  max_start = ii - curr_zeros;
		  max_zeros = curr_zeros;
		  curr_zeros = 0;
		}
	      }
	      if (curr_zeros > max_zeros) {
		max_start = ii - curr_zeros;
		max_zeros = curr_zeros;
	      }

	      /* Print out address. */
	/** Append \a CH to the output buffer. */
#define APPEND(CH) do { buf[pos++] = (CH); } while (0)
	      for (pos = ii = 0; (ii < 8); ++ii) {
		if ((max_zeros > 0) && (ii == max_start)) {
		  APPEND(':');
		  ii += max_zeros - 1;
		  continue;
		}
		part = ntohs(in->in6_16[ii]);
		if (part >= 0x1000)
		  APPEND(hexdigits[part >> 12]);
		if (part >= 0x100)
		  APPEND(hexdigits[(part >> 8) & 15]);
		if (part >= 0x10)
		  APPEND(hexdigits[(part >> 4) & 15]);
		APPEND(hexdigits[part & 15]);
		if (ii < 7)
		  APPEND(':');
	      }
#undef APPEND

	      /* Nul terminate and return number of characters used. */
	      buf[pos++] = '\0';
	      return buf;
	    }
	}

public:
	/** Decode an IP address from base64 to printable.
	 * @param[in] input Input buffer to decode.
	 * @param[out] buf buffer for output
	 */
	static Anope::string base64toprintableip(const char *input)
	{
	  struct irc_in_addr addr;

	  base64toip(input, &addr);

	  return ircd_ntoa_r(&addr);
	}

	/*** END OF IRCU CODE ***/

	bool use_oplevels;
	Anope::string cloak_suffix;

	IRCuProto(Module *creator) : IRCDProto(creator, "IRCu 2.10.12+")
	{
		DefaultPseudoclientModes = "+oik";
		CanSNLine = true; /* GLINE $R */
		/* Nick SQLine handling is actually in the IRCd, but the list
		 * can only be manipulated via config directive Jupe {}.
		 */
		CanSQLineChannel = true; /* GLINE #channel */
		RequiresID = true;
		MaxModes = 6;
		RFC1459Lines = false;
		use_oplevels = true;
	}


	static inline char nextID(char &c)
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

	Anope::string UID_Retrieve()
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

	Anope::string SID_Retrieve()
	{
		static Anope::string current_sid = Config->GetBlock("options")->Get<const Anope::string>("id");
		if (current_sid.empty())
			current_sid = "AB";

		do
		{
			int current_len = current_sid.length() - 1;
			while (current_len >= 0 && nextID(current_sid[current_len--]) == 'A')
				;
		}
		while (Server::Find(current_sid) != NULL);

		return current_sid;
	}

	void SendServer(const Server *server) anope_override
	{
		if (server != Me)
		{
			Log(LOG_DEBUG) << "Ignoring SendServer for server " << server->GetName() << " that is not me. Broken jupe code?";
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
			/* TODO */
		}
		/* user@host is the standard case*/
		else if (!x->IsRegex() && !x->HasNickOrReal())
		{
			/* TODO */
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
		if (x == NULL || !IsPureRealNameBan(x) || x->IsRegex() || x->HasNickOrReal())
			return;
		/* TODO */
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
		if (status != NULL && status->HasMode('v'))
			statusstr += 'v';
		else if (status != NULL && status->HasMode('o'))
			/* ircu really loves their oplevels and uses them even
			 * if FEAT_OPLEVELS == FALSE; 'o' == 999, but services
			 * will want creator status.
			 */
			statusstr += use_oplevels ? '0' : 'o';

		/* We need to do something like SJOIN with hybrid to "burst
		 * onto" the channel.
		 */
		UplinkSocket::Message(Me) << "B " << c->name << " " << c->creation_time << " "
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
		UplinkSocket::Message(Me) << "AC " << u->GetUID() << " " << na->nc->display;
		if (u->HasMode("CLOAK"))
		{
			Log() << "MOOOOOOOOOOOOOOOOOOOOOOOOO!";
			u->SetCloakedHost(na->nc->display + "." + cloak_suffix);
		}
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
		if (dest->ci && dest->ci->bi)
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
		if (c->ci && c->ci->bi)
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
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  52,53,54,55,56,57,58,59,60,61, 0, 0, 0, 0, 0, 0,
   0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
  15,16,17,18,19,20,21,22,23,24,25,62, 0,63, 0, 0,
   0,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
  41,42,43,44,45,46,47,48,49,50,51, 0, 0, 0, 0, 0,

   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
const char* IRCuProto::IpQuadTab[] = {
    "0",   "1",   "2",   "3",   "4",   "5",   "6",   "7",   "8",   "9",
   "10",  "11",  "12",  "13",  "14",  "15",  "16",  "17",  "18",  "19",
   "20",  "21",  "22",  "23",  "24",  "25",  "26",  "27",  "28",  "29",
   "30",  "31",  "32",  "33",  "34",  "35",  "36",  "37",  "38",  "39",
   "40",  "41",  "42",  "43",  "44",  "45",  "46",  "47",  "48",  "49",
   "50",  "51",  "52",  "53",  "54",  "55",  "56",  "57",  "58",  "59",
   "60",  "61",  "62",  "63",  "64",  "65",  "66",  "67",  "68",  "69",
   "70",  "71",  "72",  "73",  "74",  "75",  "76",  "77",  "78",  "79",
   "80",  "81",  "82",  "83",  "84",  "85",  "86",  "87",  "88",  "89",
   "90",  "91",  "92",  "93",  "94",  "95",  "96",  "97",  "98",  "99",
  "100", "101", "102", "103", "104", "105", "106", "107", "108", "109",
  "110", "111", "112", "113", "114", "115", "116", "117", "118", "119",
  "120", "121", "122", "123", "124", "125", "126", "127", "128", "129",
  "130", "131", "132", "133", "134", "135", "136", "137", "138", "139",
  "140", "141", "142", "143", "144", "145", "146", "147", "148", "149",
  "150", "151", "152", "153", "154", "155", "156", "157", "158", "159",
  "160", "161", "162", "163", "164", "165", "166", "167", "168", "169",
  "170", "171", "172", "173", "174", "175", "176", "177", "178", "179",
  "180", "181", "182", "183", "184", "185", "186", "187", "188", "189",
  "190", "191", "192", "193", "194", "195", "196", "197", "198", "199",
  "200", "201", "202", "203", "204", "205", "206", "207", "208", "209",
  "210", "211", "212", "213", "214", "215", "216", "217", "218", "219",
  "220", "221", "222", "223", "224", "225", "226", "227", "228", "229",
  "230", "231", "232", "233", "234", "235", "236", "237", "238", "239",
  "240", "241", "242", "243", "244", "245", "246", "247", "248", "249",
  "250", "251", "252", "253", "254", "255"
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
		time_t ts = convertTo<time_t>(params[1]);
		User *u;

		/* nick change, source must be user */
		if (params.size() == 2 && (u = source.GetUser()) != NULL)
			u->ChangeNick(params[0], ts);
		else if (params.size() >= 8 && source.GetServer() != NULL)
		{
			Anope::string umodes;
			Anope::string accname;
			Anope::string ip = params[params.size() - 3];
			NickCore *nc = NULL;
			/* offset for user mode arg */
			unsigned short offset = 0;
			int pos;

			/* umodes are optional! */
			if (params.size() >= 8)
				umodes = params[5];
			if (!umodes.empty() && umodes.find('r') != Anope::string::npos)
			{
				accname = params[6 + offset++];
				/* If it's a timestamped account, truncate. */
				if ((pos = umodes.find(':')) != Anope::string::npos)
					accname = accname.substr(0, pos - 1);

				nc = NickCore::Find(accname);
			}
			if (ip == '_')
				ip.clear();
			else
			{
				ip = IRCuProto::base64toprintableip(ip.c_str());
			}

			User::OnIntroduce(params[0], params[3], params[4], "", ip,
					source.GetServer(), params[params.size() - 1],
					ts, umodes, params[params.size() - 2], nc);
		}
	}
};

struct IRCDMessageBurst : IRCDMessage
{
	IRCDMessageBurst(Module *creator) : IRCDMessage(creator, "B", 3) { SetFlag(IRCDMESSAGE_SOFT_LIMIT); }

	int HealCModes(Anope::string &modes, const std::vector<Anope::string> &params, int param)
	{
		int ret = 0;
		Anope::string healed_modes = params[param];

		for (Anope::string::const_iterator it = params[param].begin(), end = params[param].end();
				it != end;
				++it)
		{
			const ChannelMode *const cm = ModeManager::FindChannelModeByChar(*it);
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

	std::list<Message::Join::SJoinUser> ParseClientList(Anope::string nicklist)
	{
		std::list<Message::Join::SJoinUser> users;
		commasepstream sep(nicklist);
		Anope::string nick, cus;
		size_t pos;
		ChannelStatus current_mode, base_mode;

		while (sep.GetToken(nick))
		{
			Message::Join::SJoinUser sju;

			if ((pos = nick.find(':')) != Anope::string::npos)
			{
				/* New CUS */
				cus = nick.substr(pos + 1);
				nick = nick.substr(0, pos);

				int current_mode_needs_reset = 1;
				for (Anope::string::const_iterator it = cus.begin(), end = cus.end();
						it != end;
						++it)
				{
					if (*it == 'o')
					{
						if (current_mode_needs_reset)
						{
							current_mode = base_mode;
							current_mode_needs_reset = 0;
						}
						current_mode.AddMode('o');
					}
					else if (*it == 'v')
					{
						if (current_mode_needs_reset)
						{
							current_mode = base_mode;
							current_mode_needs_reset = 0;
						}
						current_mode.AddMode('v');
					}
					else if (isdigit(*it))
					{
						if (current_mode_needs_reset)
						{
							current_mode = base_mode;
							current_mode_needs_reset = 0;
						}
						current_mode.AddMode('o');
					}
				}
			}

			sju.first = current_mode;
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
		time_t ts = convertTo<time_t>(params[1]);
		Channel *c = Channel::FindOrCreate(params[0], created, ts);
		Anope::string modes;
		Anope::string buf;
		std::list<Message::Join::SJoinUser> users;
		int param;

		/* Skip check if local members are split riding -- ours
		 * are privileged.
		 */

		param = 2;
		while (param < params.size())
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
			param++;
		}

		Message::Join::SJoin(source, c->name, ts, modes, users);
	}
};

struct IRCDMessageWhois : IRCDMessage
{
	/* ircu limits at 50 WHOIS entries. */
	static const int MAX_WHOIS = 50;

	IRCDMessageWhois(Module *creator) : IRCDMessage(creator, "W", 2) { SetFlag(IRCDMESSAGE_SOFT_LIMIT); }

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
			std::vector<Anope::string> waste;
			waste.push_back(nick);

			User *u = User::Find(nick, true);

			if (u && u->server == Me)
			{
				const BotInfo *bi = BotInfo::Find(u->nick);
				IRCD->SendNumeric(311, source.GetSource(), "%s %s %s * :%s", u->nick.c_str(), u->GetIdent().c_str(), u->host.c_str(), u->realname.c_str());
				if (bi)
					IRCD->SendNumeric(307, source.GetSource(), "%s :is a registered nick", bi->nick.c_str());
				IRCD->SendNumeric(312, source.GetSource(), "%s %s :%s", u->nick.c_str(), Me->GetName().c_str(), Config->GetBlock("serverinfo")->Get<const Anope::string>("description").c_str());
				if (bi)
					IRCD->SendNumeric(317, source.GetSource(), "%s %ld %ld :seconds idle, signon time", bi->nick.c_str(), static_cast<long>(Anope::CurTime - bi->lastmsg), static_cast<long>(bi->signon));
				IRCD->SendNumeric(318, source.GetSource(), "%s :End of /WHOIS list.", u->nick.c_str());
			}
			else
				IRCD->SendNumeric(401, source.GetSource(), "%s :No such user.", params[0].c_str());
		}
	}
};

struct IRCDMessageClearModes : IRCDMessage
{
	/* ircu limits at 50 WHOIS entries. */
	static const int MAX_WHOIS = 50;

	IRCDMessageClearModes(Module *creator) : IRCDMessage(creator, "CM", 2) { }

	/* ABAAA CM #channel :ntk moo */
	void Run(MessageSource &source, const std::vector<Anope::string> &params) anope_override
	{
		Channel *c;
		ChannelMode *cm;

		if ((c = Channel::Find(params[0])) == NULL)
			return;

		for (Anope::string::const_iterator it = params[1].begin(), end = params[1].end();
				it != end;
				++it)
		{
			cm = ModeManager::FindChannelModeByChar(*it);
			if (cm == NULL)
				continue;

			switch (cm->type)
			{
				case MODE_REGULAR:
				case MODE_PARAM:
				{
					c->RemoveModeInternal(source, cm, "", false);
					break;
				}
				case MODE_LIST:
				{
					std::pair<Channel::ModeList::iterator, Channel::ModeList::iterator> its = c->GetModeList(cm->name);
					for(; its.first != its.second;)
					{
						const Anope::string &mask = its.first->second;
						++its.first;
						c->RemoveModeInternal(source, cm, mask, false);
					}
					break;
				}
				case MODE_STATUS:
				{
					for (Channel::ChanUserList::const_iterator iit = c->users.begin(), it_end = c->users.end();
							iit != it_end;)
					{
						ChanUserContainer *uc = iit->second;
						++iit;
						if (uc->status.HasMode(*it))
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
	IRCDMessageCreate(Module *creator) : IRCDMessage(creator, "C", 2) { SetFlag(IRCDMESSAGE_REQUIRE_USER); }

	/* ABAAA C #channel 1234567890 */
	void Run(MessageSource &source, const std::vector<Anope::string> &params) anope_override
	{
		/* See m_create.c of ircu for details as to what some of this code does. */
		User *u = source.GetUser();
		Channel *c;
		time_t ts = convertTo<time_t>(params[1]);
		Anope::string cname;
		commasepstream sep(params[0]);
		bool created;
		bool badop;
		ChannelStatus cus;
		std::list<Message::Join::SJoinUser> sjusers;

		while (sep.GetToken(cname))
		{
			badop = false;
			cus.Clear();
			c = Channel::FindOrCreate(cname, created, ts);

			if (!created)
			{
				if (c->FindUser(u) != NULL)
					continue;

				if (Anope::CurTime - ts > 86400 ||
						(c->creation_time && ts > c->creation_time &&
						 !(c->users.size() == 0 && !c->HasMode("APASS"))))
				{
					if (u->server->IsSynced() || ts > c->creation_time + 4)
						badop = true;
				}
			}

			if (!badop)
				cus.AddMode('o');

			c->creation_time = ts;
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
		Channel *c;
		Anope::string delmodestr;

		if ((c = Channel::Find(params[0])) == NULL)
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

struct IRCDMessageMode : IRCDMessage
{
	IRCDMessageMode(Module *creator) : IRCDMessage(creator, "M", 2) { SetFlag(IRCDMESSAGE_SOFT_LIMIT); }

	void Run(MessageSource &source, const std::vector<Anope::string> &params) anope_override
	{
		if (IRCD->IsChannelValid(params[0]))
		{
			Channel *c;

			if ((c = Channel::Find(params[0])) == NULL)
				return;

			/* A timestamp could be sent as the last argument, but
			 * we don't really care; the uplink will have figured
			 * conflicts out for us already.
			 */
			Anope::string arg;
			for (size_t i = 1; i < params.size(); i++)
			{
				arg += params[i];
				if (i != params.size() - 1)
					arg += " ";
			}
			c->SetModesInternal(source, arg, 0);
		}
		else
		{
			User *u;

			if ((u = User::Find(params[0])) == NULL)
				return;

			u->SetModesInternal(source, "%s", params[1].c_str());
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
	IRCDMessageEndOfBurst message_end_of_burst;
	IRCDMessageMode message_mode;

	/* Non-token message handlers */
	ServiceAlias alias_server, alias_nick, alias_burst, alias_whois,
		     alias_clearmodes, alias_create, alias_end_of_burst,
		     alias_mode, alias_opmode,

		     alias_a, alias_y, alias_i, alias_j, alias_d, alias_mo,
		     alias_o, alias_l, alias_g, alias_p, alias_q, alias_r,
		     alias_ti, alias_t, alias_v,
		     
		     /* true aliases */
		     alias_om;

	void AddModes()
	{
		/* Add user modes */
#define UM_U(name, c) ModeManager::AddUserMode(new UserMode((name), (c)))
#define UM_O(name, c) ModeManager::AddUserMode(new UserModeOperOnly((name), (c)))
#define UM_X(name, c) ModeManager::AddUserMode(new UserModeNoone((name), (c)))
		UM_U("OPER", 'o');
		UM_U("INVIS", 'i');
		UM_U("WALLOP", 'w');
		UM_O("SNOMASK", 's');
		UM_O("DEAF", 'd');
		UM_X("PROTECTED", 'k');
		UM_O("DEBUG", 'g');
		UM_X("REGISTERED", 'r');
		UM_U("CLOAK", 'x');
#undef UM_U
#undef UM_O
#undef UM_X

		/* No +eI supported */
		ModeManager::AddChannelMode(new ChannelModeList("BAN", 'b'));

		/* CUS are only v/o */
		ModeManager::AddChannelMode(new ChannelModeStatus("VOICE", 'v', '+', 0));
		ModeManager::AddChannelMode(new ChannelModeStatus("OP", 'o', '@', 1));

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

public:
	bool use_zannels;

	ProtoIRCu(const Anope::string &modname, const Anope::string &creator) : Module(modname, creator, PROTOCOL | VENDOR),
		ircd_proto(this),

		message_away(this),
		message_error(this),
		message_invite(this),
		message_join(this),
		message_kill(this),
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
		message_end_of_burst(this),
		message_mode(this),

#define ALIAS(name, token) alias_##name("IRCDMessage", "ircu/" #name, "ircu/" #token)
		ALIAS(server, s),
		ALIAS(nick, n),
		ALIAS(burst, b),
		ALIAS(whois, w),
		ALIAS(clearmodes, cm),
		ALIAS(create, c),
		ALIAS(end_of_burst, eb),
		ALIAS(mode, m),
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
		if (Config->GetModule(this))
			this->AddModes();
	}

	EventReturn OnPreCommand(CommandSource &source, Command *command, std::vector<Anope::string> &params) anope_override
	{
		NickCore *nc = source.GetAccount();

		if ((command->name == "nickserv/identify" && !params.empty() && nc != NULL)
				|| command->name == "nickserv/logout")
		{
			/* ircu doesn't support changing account name and will
			 * cry with protocol_violation() if we try. Immediately
			 * stop any attempt to re-auth.
			 * The same applies to logging out -- there is no 
			 * concept of logging out.
			 */
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
		 */
		ChannelMode *l = ModeManager::FindChannelModeByName("LIMIT");
		ChannelMode *i = ModeManager::FindChannelModeByName("INVITE");
		MessageSource ms = MessageSource(Me);

		if (l != NULL)
			c->RemoveModeInternal(ms, l, "", false);
		if (i != NULL)
			c->RemoveModeInternal(ms, i, "", false);

		if (!c->HasMode("APASS"))
			c->Reset();
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
		use_zannels = conf->GetModule(this)->Get<bool>("use_zannels", "yes");
		ircd_proto.use_oplevels = conf->GetModule(this)->Get<bool>("use_oplevels", "yes");
		ircd_proto.cloak_suffix = conf->GetModule(this)->Get<const Anope::string>("cloak_suffix");
		if (ircd_proto.cloak_suffix.empty())
			throw ConfigException(this->name + " cloak_suffix must not be empty.");
	}

	void OnUserModeSet(const MessageSource &setter, User *u, const Anope::string &mname) anope_override
	{
		/* Users *can* set +x before being authed, meaning the cloak will only
		 * be set when AC is sent.
		 */
		if (mname != "CLOAK" || u->Account() == NULL)
			return;

		u->SetCloakedHost(u->Account()->display + "." + ircd_proto.cloak_suffix);
	}
};

MODULE_INIT(ProtoIRCu)

