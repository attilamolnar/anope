/* ChanServ core functions
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

class CommandCSDrop : public Command
{
 public:
	CommandCSDrop() : Command("DROP", 1, 1)
	{
		this->SetFlag(CFLAG_ALLOW_FORBIDDEN);
		this->SetFlag(CFLAG_ALLOW_SUSPENDED);
	}

	CommandReturn Execute(User *u, const std::vector<ci::string> &params)
	{
		const char *chan = params[0].c_str();
		ChannelInfo *ci;

		if (readonly)
		{
			notice_lang(Config.s_ChanServ, u, CHAN_DROP_DISABLED); // XXX: READ_ONLY_MODE?
			return MOD_CONT;
		}

		ci = cs_findchan(chan);

		if ((ci->HasFlag(CI_FORBIDDEN)) && !u->Account()->HasCommand("chanserv/drop"))
		{
			notice_lang(Config.s_ChanServ, u, CHAN_X_FORBIDDEN, chan);
			return MOD_CONT;
		}

		if ((ci->HasFlag(CI_SUSPENDED)) && !u->Account()->HasCommand("chanserv/drop"))
		{
			notice_lang(Config.s_ChanServ, u, CHAN_X_FORBIDDEN, chan);
			return MOD_CONT;
		}

		if ((ci->HasFlag(CI_SECUREFOUNDER) ? !IsRealFounder(u, ci) : !IsFounder(u, ci)) && !u->Account()->HasCommand("chanserv/drop"))
		{
			notice_lang(Config.s_ChanServ, u, ACCESS_DENIED);
			return MOD_CONT;
		}

		int level = get_access(u, ci);

		if (ci->c)
		{
			if (ModeManager::FindChannelModeByName(CMODE_REGISTERED))
			{
				ci->c->RemoveMode(NULL, CMODE_REGISTERED, "", false);
			}
		}

		if (ircd->chansqline && (ci->HasFlag(CI_FORBIDDEN)))
		{
			ircdproto->SendSQLineDel(ci->name.c_str());
		}

		Alog() << Config.s_ChanServ << ": Channel " << ci->name << " dropped by " << u->GetMask() << " (founder: "
			<< (ci->founder ? ci->founder->display : "(none)") << ")";

		delete ci;

		/* We must make sure that the Services admin has not normally the right to
		 * drop the channel before issuing the wallops.
		 */
		if (Config.WallDrop) {
			if ((level < ACCESS_FOUNDER) || (!IsRealFounder(u, ci) && ci->HasFlag(CI_SECUREFOUNDER)))
				ircdproto->SendGlobops(findbot(Config.s_ChanServ), "\2%s\2 used DROP on channel \2%s\2", u->nick.c_str(), chan);
		}

		notice_lang(Config.s_ChanServ, u, CHAN_DROPPED, chan);

		FOREACH_MOD(I_OnChanDrop, OnChanDrop(chan));

		return MOD_CONT;
	}

	bool OnHelp(User *u, const ci::string &subcommand)
	{
		if (u->Account() && u->Account()->IsServicesOper())
			notice_help(Config.s_ChanServ, u, CHAN_SERVADMIN_HELP_DROP);
		else
			notice_help(Config.s_ChanServ, u, CHAN_HELP_DROP);

		return true;
	}

	void OnSyntaxError(User *u, const ci::string &subcommand)
	{
		syntax_error(Config.s_ChanServ, u, "DROP", CHAN_DROP_SYNTAX);
	}
};

class CSDrop : public Module
{
 public:
	CSDrop(const std::string &modname, const std::string &creator) : Module(modname, creator)
	{
		this->SetAuthor("Anope");
		this->SetVersion(VERSION_STRING);
		this->SetType(CORE);
		this->AddCommand(CHANSERV, new CommandCSDrop());

		ModuleManager::Attach(I_OnChanServHelp, this);
	}
	void OnChanServHelp(User *u)
	{
		notice_lang(Config.s_ChanServ, u, CHAN_HELP_CMD_DROP);
	}
};

MODULE_INIT(CSDrop)
