/* NickServ core functions
 *
 * (C) 2003-2010 Anope Team
 * Contact us at team@anope.org
 *
 * Please read COPYING and README for further details.
 *
 * Based on the original code of Epona by Lara.
 * Based on the original code of Services by Andy Church.
 */

/*************************************************************************/

#include "module.h"

class CommandNSSetPrivate : public Command
{
 public:
	CommandNSSetPrivate(const Anope::string &spermission = "") : Command("PRIVATE", 2, 2, spermission)
	{
	}

	CommandReturn Execute(User *u, const std::vector<Anope::string> &params)
	{
		NickAlias *na = findnick(params[0]);
		if (!na)
			throw CoreException("NULL na in CommandNSSetPrivate");
		NickCore *nc = na->nc;

		Anope::string param = params[1];

		if (param.equals_ci("ON"))
		{
			nc->SetFlag(NI_PRIVATE);
			u->SendMessage(NickServ, NICK_SASET_PRIVATE_ON, nc->display.c_str());
		}
		else if (param.equals_ci("OFF"))
		{
			nc->UnsetFlag(NI_PRIVATE);
			u->SendMessage(NickServ, NICK_SASET_PRIVATE_OFF, nc->display.c_str());
		}
		else
			this->OnSyntaxError(u, "PRIVATE");

		return MOD_CONT;
	}

	bool OnHelp(User *u, const Anope::string &)
	{
		u->SendMessage(NickServ, NICK_HELP_SET_PRIVATE);
		return true;
	}

	void OnSyntaxError(User *u, const Anope::string &)
	{
		SyntaxError(NickServ, u, "SET PRIVATE", NICK_SET_PRIVATE_SYNTAX);
	}

	void OnServHelp(User *u)
	{
		u->SendMessage(NickServ, NICK_HELP_CMD_SET_PRIVATE);
	}
};

class CommandNSSASetPrivate : public CommandNSSetPrivate
{
 public:
	CommandNSSASetPrivate() : CommandNSSetPrivate("nickserv/saset/private")
	{
	}

	bool OnHelp(User *u, const Anope::string &)
	{
		u->SendMessage(NickServ, NICK_HELP_SASET_PRIVATE);
		return true;
	}

	void OnSyntaxError(User *u, const Anope::string &)
	{
		SyntaxError(NickServ, u, "SASET PRIVATE", NICK_SASET_PRIVATE_SYNTAX);
	}

	void OnServHelp(User *u)
	{
		u->SendMessage(NickServ, NICK_HELP_CMD_SASET_PRIVATE);
	}
};

class NSSetPrivate : public Module
{
	CommandNSSetPrivate commandnssetprivate;
	CommandNSSASetPrivate commandnssasetprivate;

 public:
	NSSetPrivate(const Anope::string &modname, const Anope::string &creator) : Module(modname, creator)
	{
		this->SetAuthor("Anope");
		this->SetType(CORE);

		Command *c = FindCommand(NickServ, "SET");
		if (c)
			c->AddSubcommand(&commandnssetprivate);

		c = FindCommand(NickServ, "SASET");
		if (c)
			c->AddSubcommand(&commandnssasetprivate);
	}

	~NSSetPrivate()
	{
		Command *c = FindCommand(NickServ, "SET");
		if (c)
			c->DelSubcommand(&commandnssetprivate);

		c = FindCommand(NickServ, "SASET");
		if (c)
			c->DelSubcommand(&commandnssasetprivate);
	}
};

MODULE_INIT(NSSetPrivate)