/* NickServ core functions
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

#include "module.h"

class CommandNSHelp : public Command
{
 public:
	CommandNSHelp() : Command("HELP", 1, 1)
	{
		this->SetFlag(CFLAG_ALLOW_UNREGISTERED);
	}

	CommandReturn Execute(User *u, const std::vector<ci::string> &params)
	{
		ci::string cmd = params[0];

		if (cmd == "SET LANGUAGE")
		{
			int i;
			notice_help(Config.s_NickServ, u, NICK_HELP_SET_LANGUAGE);
			for (i = 0; i < NUM_LANGS && langlist[i] >= 0; ++i)
				u->SendMessage(Config.s_NickServ, "    %2d) %s", i + 1, langnames[langlist[i]]);
		}
		else
			mod_help_cmd(Config.s_NickServ, u, NICKSERV, cmd.c_str());

		return MOD_CONT;
	}

	void OnSyntaxError(User *u, const ci::string &subcommand)
	{
		notice_help(Config.s_NickServ, u, NICK_HELP);
		FOREACH_MOD(I_OnNickServHelp, OnNickServHelp(u));
		if (u->Account() && u->Account()->IsServicesOper())
			notice_help(Config.s_NickServ, u, NICK_SERVADMIN_HELP);
		if (Config.NSExpire >= 86400)
			notice_help(Config.s_NickServ, u, NICK_HELP_EXPIRES, Config.NSExpire / 86400);
		notice_help(Config.s_NickServ, u, NICK_HELP_FOOTER);
	}
};

class NSHelp : public Module
{
 public:
	NSHelp(const std::string &modname, const std::string &creator) : Module(modname, creator)
	{
		this->SetAuthor("Anope");
		this->SetVersion(VERSION_STRING);
		this->SetType(CORE);

		this->AddCommand(NICKSERV, new CommandNSHelp());
	}
};

MODULE_INIT(NSHelp)
