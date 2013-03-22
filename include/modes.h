/* Mode support
 *
 * Copyright (C) 2008-2011 Adam <Adam@anope.org>
 * Copyright (C) 2008-2013 Anope Team <team@anope.org>
 *
 * Please read COPYING and README for further details.
 */

#ifndef MODES_H
#define MODES_H

#include "anope.h"
#include "base.h"

/** The different types of modes
*/
enum ModeType
{
	/* Regular mode */
	MODE_REGULAR,
	/* b/e/I */
	MODE_LIST,
	/* k/l etc */
	MODE_PARAM,
	/* v/h/o/a/q */
	MODE_STATUS
};

/* Classes of modes, Channel modes and User modes
 */
enum ModeClass
{
	MC_CHANNEL,
	MC_USER
};

/** This class is the basis of all modes in Anope
 */
class CoreExport Mode : public Base
{
 public:
 	/* Mode name */
 	Anope::string name;
	/* Class of mode this is (user/channel) */
	ModeClass mclass;
	/* Mode char for this, eg 'b' */
	char mchar;
	/* Type of mode this is, eg MODE_LIST */
	ModeType type;

	/** constructor
	 * @param mname The mode name
	 * @param mclass The type of mode this is
	 * @param mc The mode char
	 * @param type The mode type
	 */
	Mode(const Anope::string &mname, ModeClass mclass, char mc, ModeType type);

	/** Constructor without a mode letter
	 * @param mname The mode name
	 * @param mclass The type of mode this is
	 * @param type The mode type
	 */
	Mode(const Anope::string &mname, ModeClass mclass, ModeType type);

	virtual ~Mode();
};

/** This class is a user mode, all user modes use this/inherit from this
 */
class CoreExport UserMode : public Mode
{
 public:
	/** constructor
	 * @param name The mode name
	 * @param mc The mode char
	 */
	UserMode(const Anope::string &name, char mc);
	virtual ~UserMode();
};

class CoreExport UserModeParam : public UserMode
{
 public:
 	/** constructor
	 * @param name The mode name
	 * @param mc The mode char
	 */
	UserModeParam(const Anope::string &name, char mc);

	/** Check if the param is valid
	 * @param value The param
	 * @return true or false
	 */
	virtual bool IsValid(const Anope::string &value) const { return true; }
};

/** This class is a channel mode, all channel modes use this/inherit from this
 */
class CoreExport ChannelMode : public Mode
{
 public:
	/** constructor
	 * @param name The mode name
	 * @param mc The mode char
	 */
	ChannelMode(const Anope::string &name, char mc);

	/** Constructor without a mode letter
	 * @param name The mode name
	 */
	ChannelMode(const Anope::string &name);

	virtual ~ChannelMode();

	/** Can a user set this mode, used for mlock
	 * NOTE: User CAN be NULL, this is for checking if it can be locked with defcon
	 * @param u The user, or NULL
	 */
	virtual bool CanSet(User *u) const;

	/** doc
	 */
	virtual ChannelMode* GetRealMode(Anope::string &param)
	{
		return this;
	}
};


/** This is a mode for lists, eg b/e/I. These modes should inherit from this
 */
class CoreExport ChannelModeList : public ChannelMode
{
 public:
	/** constructor
	 * @param name The mode name
	 * @param mc The mode char
	 */
	ChannelModeList(const Anope::string &name, char mc);

	/** Constructor without a mode letter
	 * @param name The mode name
	 */
	ChannelModeList(const Anope::string &name);

	/** destructor
	 */
	virtual ~ChannelModeList();

	/** Is the mask valid
	 * @param mask The mask
	 * @return true for yes, false for no
	 */
	virtual bool IsValid(const Anope::string &mask) const { return true; }

	/** Checks if mask affects user
	 * Should only be used for extbans or other weird ircd-specific things.
	 * @param u The user
	 * @param e The entry to match against
	 * @return true on match
	 */
	virtual bool Matches(const User *u, const Entry *e) { return false; }

	/** Called when a mask is added to a channel
	 * @param chan The channel
	 * @param mask The mask
	 */
	virtual void OnAdd(Channel *chan, const Anope::string &mask) { }

	/** Called when a mask is removed from a channel
	 * @param chan The channel
	 * @param mask The mask
	 */
	virtual void OnDel(Channel *chan, const Anope::string &mask) { }
};

/** This is a mode with a paramater, eg +k/l. These modes should use/inherit from this
*/
class CoreExport ChannelModeParam : public ChannelMode
{
 public:
	/** constructor
	 * @param name The mode name
	 * @param mc The mode char
	 * @param minus_no_arg true if this mode sends no arg when unsetting
	 */
	ChannelModeParam(const Anope::string &name, char mc, bool minus_no_arg = false);

	/** Constructor without a mode letter
	 * @param name The mode name
	 * @param minus_no_arg true if this mode sends no arg when unsetting
	 */
	ChannelModeParam(const Anope::string &name, bool minus_no_arg = false);

	/** destructor
	 */
	virtual ~ChannelModeParam();

	/* Should we send an arg when unsetting this mode? */
	bool minus_no_arg;

	/** Is the param valid
	 * @param value The param
	 * @return true for yes, false for no
	 */
	virtual bool IsValid(const Anope::string &value) const { return true; }
};

/** This is a mode that is a channel status, eg +v/h/o/a/q.
*/
class CoreExport ChannelModeStatus : public ChannelMode
{
 public:
	/* The symbol, eg @ % + */
	char Symbol;
	/* The "level" of the mode, used to compare with other modes.
	 * Used so we know op > halfop > voice etc.
	 */
	short level;

	/** constructor
	 * @param name The mode name
	 * @param mc The mode char
	 * @param mSymbol The symbol for the mode, eg @ % 
	 * @param mlevel A level for the mode, which is usually determined by the PREFIX capab
	 */
	ChannelModeStatus(const Anope::string &name, char mc, char mSymbol, short mlevel = 0);

	/** destructor
	 */
	virtual ~ChannelModeStatus();
};

/* The status a user has on a channel (+v, +h, +o) etc */
class CoreExport ChannelStatus
{
 public:
	std::set<Anope::string> modes;
	Anope::string BuildCharPrefixList() const;
	Anope::string BuildModePrefixList() const;
};

/** Channel mode +k (key)
 */
class CoreExport ChannelModeKey : public ChannelModeParam
{
 public:
	ChannelModeKey(char mc) : ChannelModeParam("KEY", mc) { }

	bool IsValid(const Anope::string &value) const anope_override;
};

/** This class is used for channel mode +A (Admin only)
 * Only opers can mlock it
 */
class CoreExport ChannelModeAdmin : public ChannelMode
{
 public:
	ChannelModeAdmin(char mc) : ChannelMode("ADMINONLY", mc) { }

	/* Opers only */
	bool CanSet(User *u) const anope_override;
};

/** This class is used for channel mode +O (Opers only)
 * Only opers can mlock it
 */
class CoreExport ChannelModeOper : public ChannelMode
{
 public:
	ChannelModeOper(char mc) : ChannelMode("OPERONLY", mc) { }

	/* Opers only */
	bool CanSet(User *u) const anope_override;
};

/** This class is used for channel mode +r (registered channel)
 * No one may mlock r
 */
class CoreExport ChannelModeRegistered : public ChannelMode
{
 public:
	ChannelModeRegistered(char mc) : ChannelMode("REGISTERED", mc) { }

	/* No one mlocks +r */
	bool CanSet(User *u) const anope_override;
};

class StackerInfo
{
 public:
	/* Modes to be added */
	std::list<std::pair<Mode *, Anope::string> > AddModes;
	/* Modes to be deleted */
	std::list<std::pair<Mode *, Anope::string> > DelModes;
	/* Bot this is sent from */
	const BotInfo *bi;

	/** Add a mode to this object
	 * @param mode The mode
	 * @param set true if setting, false if unsetting
	 * @param param The param for the mode
	 */
	void AddMode(Mode *mode, bool set, const Anope::string &param);
};

/** This is the mode manager
 * It contains functions for adding modes to Anope so Anope can track them
 * and do things such as MLOCK.
 * This also contains a mode stacker that will combine multiple modes and set
 * them on a channel or user at once
 */
class CoreExport ModeManager
{
 protected:
	/* List of pairs of user/channels and their stacker info */
	static std::map<User *, StackerInfo *> UserStackerObjects;
	static std::map<Channel *, StackerInfo *> ChannelStackerObjects;

	/** Build a list of mode strings to send to the IRCd from the mode stacker
	 * @param info The stacker info for a channel or user
	 * @return a list of strings
	 */
	static std::list<Anope::string> BuildModeStrings(StackerInfo *info);

 public:
 	/* List of all modes Anope knows about */
	static std::vector<ChannelMode *> ChannelModes;
	static std::vector<UserMode *> UserModes;

	/* Number of generic channel and user modes we are tracking */
	static unsigned GenericChannelModes;
	static unsigned GenericUserModes;
	/* Default channel mode lock */
	static std::list<std::pair<Anope::string, Anope::string> > ModeLockOn;
	static std::list<Anope::string> ModeLockOff;
	/* Default modes bots have on channels */
	static ChannelStatus DefaultBotModes;

	/** Add a user mode to Anope
	 * @param um A UserMode or UserMode derived class
	 * @return true on success, false on error
	 */
	static bool AddUserMode(UserMode *um);

	/** Add a channel mode to Anope
	 * @param cm A ChannelMode or ChannelMode derived class
	 * @return true on success, false on error
	 */
	static bool AddChannelMode(ChannelMode *cm);

	/** Remove a user mode from Anope
	 * @param um A UserMode to remove
	 */
	static void RemoveUserMode(UserMode *um);

	/** Remove a channel mode from Anope
	 * @param um A ChanneMode to remove
	 */
	static void RemoveChannelMode(ChannelMode *cm);

	/** Find a channel mode
	 * @param mode The mode
	 * @return The mode class
	 */
	static ChannelMode *FindChannelModeByChar(char mode);

	/** Find a user mode
	 * @param mode The mode
	 * @return The mode class
	 */
	static UserMode *FindUserModeByChar(char mode);

	/** Find a channel mode
	 * @param name The modename
	 * @return The mode class
	 */
	static ChannelMode *FindChannelModeByName(const Anope::string &name);

	/** Find a user mode
	 * @param name The modename
	 * @return The mode class
	 */
	static UserMode *FindUserModeByName(const Anope::string &name);

	/** Gets the channel mode char for a symbol (eg + returns v)
	 * @param symbol The symbol
	 * @return The char
	 */
	static char GetStatusChar(char symbol);

	/** Add a mode to the stacker to be set on a channel
	 * @param bi The client to set the modes from
	 * @param c The channel
	 * @param cm The channel mode
	 * @param set true for setting, false for removing
	 * @param param The param, if there is one
	 */
	static void StackerAdd(const BotInfo *bi, Channel *c, ChannelMode *cm, bool set, const Anope::string &param = "");

	/** Add a mode to the stacker to be set on a user
	 * @param bi The client to set the modes from
	 * @param u The user
	 * @param um The user mode
	 * @param set true for setting, false for removing
	 * @param param The param, if there is one
	 */
	static void StackerAdd(const BotInfo *bi, User *u, UserMode *um, bool set, const Anope::string &param = "");

	/** Process all of the modes in the stacker and send them to the IRCd to be set on channels/users
	 */
	static void ProcessModes();

	/** Delete a user, channel, or mode from the stacker
	 */
	static void StackerDel(User *u);
	static void StackerDel(Channel *c);
	static void StackerDel(Mode *m);

	/** Updates the default mode locks and default bot modes
	 * @param config The configuration to read from. This is often called
	 * during a config reload.
	 */
	static void UpdateDefaultMLock(ServerConfig *config);
};

/** Represents a mask set on a channel (b/e/I)
 */
class CoreExport Entry
{
	Anope::string name;
	Anope::string mask;
 public:
	unsigned short cidr_len;
	Anope::string nick, user, host, real;

	/** Constructor
 	 * @param mode What mode this host is for, can be empty for unknown/no mode
	 * @param host A full or poartial nick!ident@host/cidr#real name mask
	 */
	Entry(const Anope::string &mode, const Anope::string &host);

	/** Get the banned mask for this entry
	 * @return The mask
	 */
	const Anope::string GetMask() const;

	/** Check if this entry matches a user
	 * @param u The user
	 * @param full True to match against a users real host and IP
	 * @return true on match
	 */
	bool Matches(const User *u, bool full = false) const;
};

#endif // MODES_H
